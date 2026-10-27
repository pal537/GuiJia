package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupLinkTest(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	oldSettings, oldNodeIdent, oldNodeFile, oldServersFile, oldSettingFile := settings, nodeIdent, nodeFile, serversFile, settingFile
	oldServers, oldPending := hubServers, hubPending
	oldCodes, oldChals := codes, chals
	oldWaiters, oldResults := cmdWaiters, cmdResults
	oldRootMux := rootMux
	oldLink, oldLast, oldErr := linkState, linkLastContact, linkLastError
	oldHold := linkPollHold
	settings = defaultSettings()
	settings.RunMode = "managed"
	settings.ServerName = "测试节点"
	settings.ServerID = "testnode1"
	nodeIdent = nil
	nodeFile = filepath.Join(dir, "node.json")
	serversFile = filepath.Join(dir, "servers.json")
	hubServers = []*hubServer{}
	hubPending = []*hubPendingEntry{}
	codes = map[string]*pairingCode{}
	chals = map[string]*nodeChallenge{}
	cmdWaiters = map[string]chan hubCommand{}
	cmdResults = map[string]chan hubCmdResult{}
	linkState, linkLastContact, linkLastError = "idle", 0, ""
	linkPollHold = 2 * time.Second
	return func() {
		settings, nodeIdent, nodeFile, serversFile, settingFile = oldSettings, oldNodeIdent, oldNodeFile, oldServersFile, oldSettingFile
		hubServers, hubPending = oldServers, oldPending
		codes, chals = oldCodes, oldChals
		cmdWaiters, cmdResults = oldWaiters, oldResults
		rootMux = oldRootMux
		linkState, linkLastContact, linkLastError = oldLink, oldLast, oldErr
		linkPollHold = oldHold
	}
}

func TestNodeCredentialsPersist(t *testing.T) {
	defer setupLinkTest(t)()
	loadNodeIdentity()
	if nodeFingerprint() == "" {
		t.Fatalf("节点身份应生成")
	}
	setNodePairingCode("CODE123")
	setNodeToken("tok-abc")
	b, _ := os.ReadFile(nodeFile)
	if !strings.Contains(string(b), "CODE123") || !strings.Contains(string(b), "tok-abc") {
		t.Fatalf("node.json 应含配对码与 token")
	}
	if st, _ := os.Stat(nodeFile); st.Mode().Perm() != 0600 {
		t.Fatalf("node.json 应为 0600")
	}
	clearNodePairingCode()
	b, _ = os.ReadFile(nodeFile)
	if strings.Contains(string(b), "CODE123") {
		t.Fatalf("清除后不应再有配对码")
	}
	if nodeToken() != "tok-abc" {
		t.Fatalf("清除配对码不应动 token")
	}
	// token 绝不进 settings.json(0644): 设置文件里不应出现它。
	settingsFile := filepath.Join(filepath.Dir(nodeFile), "settings.json")
	settingFile = settingsFile
	saveSettings()
	sb, _ := os.ReadFile(settingsFile)
	if strings.Contains(string(sb), "tok-abc") {
		t.Fatalf("settings.json 不应含 token")
	}
}

func TestExecuteNodeCommandAllowlist(t *testing.T) {
	defer setupLinkTest(t)()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"fromNode": true})
	})
	mux.HandleFunc("/api/bans", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	rootMux = mux
	if st, body := executeNodeCommand(hubCommand{ID: "1", Method: "GET", Path: "api/overview"}); st != 200 || !strings.Contains(string(body), "fromNode") {
		t.Fatalf("无斜杠路径应归一化执行: st=%d body=%s", st, body)
	}
	if st, _ := executeNodeCommand(hubCommand{ID: "2", Method: "GET", Path: "/api/auth/sessions"}); st != 403 {
		t.Fatalf("鉴权接口应 403, 得到 %d", st)
	}
	if st, _ := executeNodeCommand(hubCommand{ID: "3", Method: "GET", Path: "/api/nodes/servers"}); st != 403 {
		t.Fatalf("节点接口应 403, 得到 %d", st)
	}
	if st, _ := executeNodeCommand(hubCommand{ID: "4", Method: "PATCH", Path: "/api/overview"}); st != 400 {
		t.Fatalf("不支持的方法应 400, 得到 %d", st)
	}
	if st, _ := executeNodeCommand(hubCommand{ID: "5", Method: "POST", Path: "/api/bans"}); st != 200 {
		t.Fatalf("管理接口应放行, 得到 %d", st)
	}
}

func TestLinkLimit(t *testing.T) {
	defer setupLinkTest(t)()
	fail := func(w http.ResponseWriter, r *http.Request) { errJSON(w, 401, "bad") }
	h := linkLimit(fail)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/api/nodes/hello", nil)
		req.RemoteAddr = "198.51.100.7:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("前 20 次应 401, 第 %d 次得到 %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest("POST", "/api/nodes/hello", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 429 {
		t.Fatalf("第 21 次应 429, 得到 %d", rec.Code)
	}
}

// TestLinkFullFlowFakeHub: 假主服务器(真实 hub 处理器)+真实拨号器,
// 走完加入→待添加→审批→在线→代理总览→移除→吊销全流程。
func TestLinkFullFlowFakeHub(t *testing.T) {
	defer setupLinkTest(t)()
	hubMux := http.NewServeMux()
	hubMux.HandleFunc("/api/nodes/hello", handleNodeHello)
	hubMux.HandleFunc("/api/nodes/challenge", handleNodeChallenge)
	hubMux.HandleFunc("/api/nodes/auth", handleNodeAuth)
	hubMux.HandleFunc("/api/nodes/ping", handleNodePing)
	hubMux.HandleFunc("/api/nodes/poll", handleNodePoll)
	hubMux.HandleFunc("/api/nodes/result", handleNodeResult)
	hubSrv := httptest.NewServer(hubMux)
	defer hubSrv.Close()

	nodeIdent = nil
	loadNodeIdentity() // 生成节点身份(拨号器全程用 nodeIdent, 指纹/签名自然一致)
	fp := nodeFingerprint()

	settings.HubURL = hubSrv.URL
	code, _ := newPairingCode()
	setNodePairingCode(code)

	nodeMux := http.NewServeMux()
	nodeMux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"nodeOverview": true})
	})
	rootMux = nodeMux

	done := make(chan error, 1)
	go func() { done <- linkSession() }()

	// 等待待添加
	deadline := time.Now().Add(5 * time.Second)
	for findHubPending(fp) == nil && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if findHubPending(fp) == nil {
		t.Fatalf("拨号器 hello 后主服务器应有待添加")
	}
	// 配对码应在首次 hello 成功后清除
	if b, _ := os.ReadFile(nodeFile); strings.Contains(string(b), code) {
		t.Fatalf("首次 hello 成功后配对码应清除")
	}
	// 审批
	rec := hubCall(t, handleNodeApprove, "POST", "/api/nodes/approve", `{"fingerprint":"`+fp+`"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("审批应成功: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// 等待在线
	deadline = time.Now().Add(20 * time.Second)
	for {
		st, _, _ := linkSnapshot()
		if st == "connected" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("拨号器应在线, 当前状态 %q", st)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if nodeToken() == "" {
		t.Fatalf("在线后应持有 token")
	}
	// 代理总览: 主服务器经命令通道拿到节点数据
	time.Sleep(300 * time.Millisecond) // 等节点 poll 注册
	rec = hubCall(t, handleNodeProxy, "POST", "/api/nodes/proxy",
		`{"fingerprint":"`+fp+`","method":"GET","path":"api/overview"}`, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "nodeOverview") {
		t.Fatalf("代理总览应拿到节点数据: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// 移除节点: 下一次 poll/ping 应 401, 拨号器吊销并清 token
	hubCall(t, handleNodeRemove, "POST", "/api/nodes/remove", `{"fingerprint":"`+fp+`"}`, nil)
	select {
	case err := <-done:
		if !errors.Is(err, errLinkRevoked) {
			t.Fatalf("移除后拨号器应以吊销退出, 得到 %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("移除后拨号器应在 30 秒内退出")
	}
	if nodeToken() != "" {
		t.Fatalf("吊销后 token 应清除")
	}
}

func TestHubProxyFlow(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	hubServers = []*hubServer{{
		Fingerprint: fp, PubKey: pubB64, Name: "n", Status: "online",
		LastSeen: time.Now().Unix(), TokenHash: hashToken("tok123"),
	}}
	hdr := map[string]string{"X-Node-Fingerprint": fp, "X-Node-Token": "tok123"}

	// 节点 poll(另 goroutine 等命令)
	pollRec := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("POST", "/api/nodes/poll", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		handleNodePoll(rec, req)
		pollRec <- rec
	}()
	time.Sleep(200 * time.Millisecond)

	// 代理请求(另 goroutine 等结果)
	proxyRec := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := hubCall(t, handleNodeProxy, "POST", "/api/nodes/proxy",
			`{"fingerprint":"`+fp+`","method":"GET","path":"api/overview"}`, nil)
		proxyRec <- rec
	}()
	// poll 应收到命令, 回结果
	select {
	case rec := <-pollRec:
		if rec.Code != 200 {
			t.Fatalf("poll 应收到命令: code=%d body=%s", rec.Code, rec.Body.String())
		}
		var cmd hubCommand
		if json.Unmarshal(rec.Body.Bytes(), &cmd) != nil || cmd.ID == "" || cmd.Path != "api/overview" {
			t.Fatalf("命令内容异常: %s", rec.Body.String())
		}
		rec2 := hubCall(t, handleNodeResult, "POST", "/api/nodes/result",
			`{"id":"`+cmd.ID+`","status":200,"body":{"fromNode":true}}`, hdr)
		if rec2.Code != 200 {
			t.Fatalf("回结果应成功: code=%d", rec2.Code)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("poll 超时未收到命令")
	}
	select {
	case rec := <-proxyRec:
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "fromNode") {
			t.Fatalf("代理应回传节点数据: code=%d body=%s", rec.Code, rec.Body.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("代理超时未回结果")
	}

	// 离线节点代理应 502
	hubServers[0].LastSeen = time.Now().Unix() - 1000
	rec := hubCall(t, handleNodeProxy, "POST", "/api/nodes/proxy",
		`{"fingerprint":"`+fp+`","method":"GET","path":"api/overview"}`, nil)
	if rec.Code != 502 {
		t.Fatalf("离线节点代理应 502, 得到 %d", rec.Code)
	}
	// 被禁路径应 403
	hubServers[0].LastSeen = time.Now().Unix()
	rec = hubCall(t, handleNodeProxy, "POST", "/api/nodes/proxy",
		`{"fingerprint":"`+fp+`","method":"GET","path":"api/auth/sessions"}`, nil)
	if rec.Code != 403 {
		t.Fatalf("鉴权接口代理应 403, 得到 %d", rec.Code)
	}
}
