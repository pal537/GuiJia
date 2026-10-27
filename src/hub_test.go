package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func setupHubTest(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	oldServersFile, oldServers, oldPending := serversFile, hubServers, hubPending
	oldCodes, oldChals := codes, chals
	oldWaiters, oldResults := cmdWaiters, cmdResults
	oldSettings := settings
	serversFile = filepath.Join(dir, "servers.json")
	hubServers = []*hubServer{}
	hubPending = []*hubPendingEntry{}
	codes = map[string]*pairingCode{}
	chals = map[string]*nodeChallenge{}
	cmdWaiters = map[string]chan hubCommand{}
	cmdResults = map[string]chan hubCmdResult{}
	settings = defaultSettings()
	settings.RunMode = "standalone"
	settings.ServerID = "testhub1"
	return func() {
		serversFile, hubServers, hubPending = oldServersFile, oldServers, oldPending
		codes, chals = oldCodes, oldChals
		cmdWaiters, cmdResults = oldWaiters, oldResults
		settings = oldSettings
	}
}

func hubTestKey(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return priv, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(pub)
}

func hubCall(t *testing.T, h http.HandlerFunc, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func hubCallJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("响应不是 JSON: %v body=%s", err, rec.Body.String())
	}
	return out
}

func TestPairingCodeSingleUse(t *testing.T) {
	defer setupHubTest(t)()
	code, _ := newPairingCode()
	if !consumePairingCode(code) {
		t.Fatalf("首次核销应成功")
	}
	if consumePairingCode(code) {
		t.Fatalf("二次核销应失败")
	}
	if consumePairingCode("不存在的码") {
		t.Fatalf("不存在的码应失败")
	}
	code2, _ := newPairingCode()
	codes[code2].expiresAt = 1
	if consumePairingCode(code2) {
		t.Fatalf("过期码应失败")
	}
}

func TestHubHelloApproveAuthFlow(t *testing.T) {
	defer setupHubTest(t)()
	priv, fp, pubB64 := hubTestKey(t)
	code, _ := newPairingCode()

	// hello 进待添加
	rec := hubCall(t, handleNodeHello, "POST", "/api/nodes/hello",
		`{"fingerprint":"`+fp+`","pubKey":"`+pubB64+`","name":"测试节点","version":"0.1","code":"`+code+`"}`, nil)
	if rec.Code != 200 || hubCallJSON(t, rec)["status"] != "pending" {
		t.Fatalf("hello 应进 pending: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// 公钥与指纹不符应拒
	_, _, otherPub := hubTestKey(t)
	rec = hubCall(t, handleNodeHello, "POST", "/api/nodes/hello",
		`{"fingerprint":"`+fp+`","pubKey":"`+otherPub+`","name":"x","version":"0.1","code":"`+code+`"}`, nil)
	if rec.Code != 400 {
		t.Fatalf("公钥指纹不符应 400, 得到 %d", rec.Code)
	}
	// 审批
	rec = hubCall(t, handleNodeApprove, "POST", "/api/nodes/approve", `{"fingerprint":"`+fp+`"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("审批应成功: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// 挑战 + 签名换 token
	rec = hubCall(t, handleNodeChallenge, "POST", "/api/nodes/challenge", `{"fingerprint":"`+fp+`"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("挑战应成功: code=%d", rec.Code)
	}
	nonce := hubCallJSON(t, rec)["nonce"].(string)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(nonce)))
	rec = hubCall(t, handleNodeAuth, "POST", "/api/nodes/auth",
		`{"fingerprint":"`+fp+`","nonce":"`+nonce+`","signature":"`+sig+`"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("签名换 token 应成功: code=%d body=%s", rec.Code, rec.Body.String())
	}
	tok := hubCallJSON(t, rec)["token"].(string)
	if tok == "" {
		t.Fatalf("应返回 token")
	}
	// ping: 正确 token 过, 错误 token 拦
	hdr := map[string]string{"X-Node-Fingerprint": fp, "X-Node-Token": tok}
	rec = hubCall(t, handleNodePing, "POST", "/api/nodes/ping", `{"version":"0.1"}`, hdr)
	if rec.Code != 200 {
		t.Fatalf("正确 token ping 应 200, 得到 %d", rec.Code)
	}
	hdr["X-Node-Token"] = "错的token"
	rec = hubCall(t, handleNodePing, "POST", "/api/nodes/ping", `{}`, hdr)
	if rec.Code != 401 {
		t.Fatalf("错误 token ping 应 401, 得到 %d", rec.Code)
	}
	// 坏签名应拒
	rec = hubCall(t, handleNodeChallenge, "POST", "/api/nodes/challenge", `{"fingerprint":"`+fp+`"}`, nil)
	nonce2 := hubCallJSON(t, rec)["nonce"].(string)
	badSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("不是这个nonce")))
	rec = hubCall(t, handleNodeAuth, "POST", "/api/nodes/auth",
		`{"fingerprint":"`+fp+`","nonce":"`+nonce2+`","signature":"`+badSig+`"}`, nil)
	if rec.Code != 401 {
		t.Fatalf("坏签名应 401, 得到 %d", rec.Code)
	}
}

func TestHubRejectRemove(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	code, _ := newPairingCode()
	hubCall(t, handleNodeHello, "POST", "/api/nodes/hello",
		`{"fingerprint":"`+fp+`","pubKey":"`+pubB64+`","name":"n","version":"0.1","code":"`+code+`"}`, nil)
	rec := hubCall(t, handleNodeReject, "POST", "/api/nodes/reject", `{"fingerprint":"`+fp+`"}`, nil)
	if rec.Code != 200 || findHubPending(fp) != nil {
		t.Fatalf("拒绝后待添加应清空: code=%d", rec.Code)
	}
	code2, _ := newPairingCode()
	hubCall(t, handleNodeHello, "POST", "/api/nodes/hello",
		`{"fingerprint":"`+fp+`","pubKey":"`+pubB64+`","name":"n","version":"0.1","code":"`+code2+`"}`, nil)
	hubCall(t, handleNodeApprove, "POST", "/api/nodes/approve", `{"fingerprint":"`+fp+`"}`, nil)
	rec = hubCall(t, handleNodeRemove, "POST", "/api/nodes/remove", `{"fingerprint":"`+fp+`"}`, nil)
	if rec.Code != 200 || findHubServer(fp) != nil {
		t.Fatalf("移除后登记应清空: code=%d", rec.Code)
	}
}

func TestHubEndpointsBlockedWhenManaged(t *testing.T) {
	defer setupHubTest(t)()
	settings.RunMode = "managed"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := authMiddleware(next)
	for _, p := range []string{"/api/nodes/servers", "/api/nodes/hello", "/api/nodes/ping"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", p, nil))
		if rec.Code != 403 {
			t.Fatalf("被群控时 %s 应 403, 得到 %d", p, rec.Code)
		}
	}
}
