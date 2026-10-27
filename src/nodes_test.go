package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupNodeTest(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	oldSettings, oldAuth, oldIdent, oldNodeFile, oldSettingFile := settings, auth, nodeIdent, nodeFile, settingFile
	oldLink, oldLast, oldErr := linkState, linkLastContact, linkLastError
	settings = defaultSettings()
	auth = adminAuth{}
	nodeIdent = nil
	nodeFile = filepath.Join(dir, "node.json")
	settingFile = filepath.Join(dir, "settings.json")
	linkState, linkLastContact, linkLastError = "idle", 0, ""
	return func() {
		settings, auth, nodeIdent, nodeFile, settingFile = oldSettings, oldAuth, oldIdent, oldNodeFile, oldSettingFile
		linkState, linkLastContact, linkLastError = oldLink, oldLast, oldErr
	}
}

func TestRunModeMigration(t *testing.T) {
	defer setupNodeTest(t)()
	auth.PassHash = "x"
	migrateRunMode()
	if settings.RunMode != "standalone" {
		t.Fatalf("老机器应迁为独立, 得到 %q", settings.RunMode)
	}
	if effectiveRunMode() != "standalone" {
		t.Fatalf("effective 应为 standalone")
	}
}

func TestRunModeUndecided(t *testing.T) {
	defer setupNodeTest(t)()
	if effectiveRunMode() != "" {
		t.Fatalf("无密码无模式应为未定")
	}
}

func TestSetupModeStandalone(t *testing.T) {
	defer setupNodeTest(t)()
	req := httptest.NewRequest("POST", "/api/setup/mode", strings.NewReader(`{"mode":"standalone"}`))
	rec := httptest.NewRecorder()
	handleSetupMode(rec, req)
	if rec.Code != 200 || settings.RunMode != "standalone" {
		t.Fatalf("独立选择失败: code=%d body=%s mode=%q", rec.Code, rec.Body.String(), settings.RunMode)
	}
	req2 := httptest.NewRequest("POST", "/api/setup/mode", strings.NewReader(`{"mode":"managed","hubUrl":"https://hub.example.com","code":"x"}`))
	rec2 := httptest.NewRecorder()
	handleSetupMode(rec2, req2)
	if rec2.Code != 403 {
		t.Fatalf("二次选择应 403, 得到 %d", rec2.Code)
	}
}

func TestSetupModeManaged(t *testing.T) {
	defer setupNodeTest(t)()
	bad := []string{
		`{"mode":"managed","hubUrl":"ftp://hub.example.com","code":"abc"}`,
		`{"mode":"managed","hubUrl":"https://hub.example.com","code":""}`,
		`{"mode":"managed","hubUrl":"","code":"abc"}`,
		`{"mode":"managed","hubUrl":"not-a-url","code":"abc"}`,
	}
	for _, b := range bad {
		req := httptest.NewRequest("POST", "/api/setup/mode", strings.NewReader(b))
		rec := httptest.NewRecorder()
		handleSetupMode(rec, req)
		if rec.Code != 400 {
			t.Fatalf("非法加入应 400: %s 得到 %d", b, rec.Code)
		}
	}
	// 模拟主服务器 hello: 好码 -> pending, 其余 -> 403；无码 hello（拨号器跟进）也回 pending。
	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Code != "" && req.Code != "good-code" {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"error": "配对码无效或已过期"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}))
	defer hubSrv.Close()
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/setup/mode", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handleSetupMode(rec, req)
		return rec
	}
	get := func() map[string]any {
		req := httptest.NewRequest("GET", "/api/setup/mode", nil)
		rec := httptest.NewRecorder()
		handleSetupMode(rec, req)
		var v map[string]any
		json.Unmarshal(rec.Body.Bytes(), &v)
		return v
	}
	// 错码: 400 + 模式仍未定 + 码不落盘, 加入页可重输
	if rec := post(`{"mode":"managed","hubUrl":"` + hubSrv.URL + `","code":"bad-code"}`); rec.Code != 400 {
		t.Fatalf("错码应 400, 得到 %d: %s", rec.Code, rec.Body.String())
	} else if !strings.Contains(rec.Body.String(), "配对码无效") {
		t.Fatalf("错码应回配对码无效, 得到 %s", rec.Body.String())
	}
	if v := get(); v["decided"] != false || v["runMode"] != "" {
		t.Fatalf("错码后模式应仍未定, 得到 %+v", v)
	}
	if nodePairingCode() != "" {
		t.Fatalf("错码不应落盘, 得到 %q", nodePairingCode())
	}
	// 连不上主服务器: 400 + 模式仍未定
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closed.Close()
	if rec := post(`{"mode":"managed","hubUrl":"` + closed.URL + `","code":"good-code"}`); rec.Code != 400 {
		t.Fatalf("连不上应 400, 得到 %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), "无法连接主服务器") {
		t.Fatalf("连不上应回无法连接主服务器, 得到 %s", rec.Body.String())
	}
	if v := get(); v["decided"] != false {
		t.Fatalf("连不上后模式应仍未定, 得到 %+v", v)
	}
	// 好码: 200 + 模式 managed + 码不落盘（已被主服务器消耗）+ 链路 joining + 未配对 + 清掉上次回退标记
	settings.JoinError = "rejected"
	if rec := post(`{"mode":"managed","hubUrl":"` + hubSrv.URL + `","code":"good-code"}`); rec.Code != 200 {
		t.Fatalf("好码应 200, 得到 %d: %s", rec.Code, rec.Body.String())
	}
	if settings.RunMode != "managed" || settings.HubURL != hubSrv.URL {
		t.Fatalf("加入失败: mode=%q hub=%q", settings.RunMode, settings.HubURL)
	}
	if v := get(); v["linkState"] != "joining" && v["linkState"] != "pending" || v["paired"] != false {
		t.Fatalf("好码后应 joining/pending 且未配对, 得到 %+v", v)
	}
	if nodePairingCode() != "" {
		t.Fatalf("好码校验通过后码不应再留盘, 得到 %q", nodePairingCode())
	}
	if settings.JoinError != "" {
		t.Fatalf("好码提交应清掉上次回退标记, 得到 %q", settings.JoinError)
	}
	// 二次选择应 403
	if rec := post(`{"mode":"standalone"}`); rec.Code != 403 {
		t.Fatalf("二次选择应 403, 得到 %d", rec.Code)
	}
}

func TestNodeIdentityStable(t *testing.T) {
	defer setupNodeTest(t)()
	loadNodeIdentity()
	fp1 := nodeFingerprint()
	if fp1 == "" {
		t.Fatalf("指纹为空")
	}
	st, err := os.Stat(nodeFile)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("node.json 应为 0600: %v", err)
	}
	nodeIdent = nil
	loadNodeIdentity()
	if nodeFingerprint() != fp1 {
		t.Fatalf("指纹应稳定, %q vs %q", nodeFingerprint(), fp1)
	}
}

func TestManagedMiddleware(t *testing.T) {
	defer setupNodeTest(t)()
	settings.RunMode = "managed"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := authMiddleware(next)
	for _, p := range []string{"/api/overview", "/api/auth/login", "/api/auth/setup"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 403 {
			t.Fatalf("被群控时 %s 应 403, 得到 %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/api/node/status"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 200 {
			t.Fatalf("被群控时 %s 应放行, 得到 %d", p, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/setup/mode", nil))
	if rec.Code != 403 {
		t.Fatalf("被群控时 POST 模式应 403, 得到 %d", rec.Code)
	}
}

func TestAuthSetupModeGate(t *testing.T) {
	defer setupNodeTest(t)()
	rec := httptest.NewRecorder()
	handleAuthSetup(rec, httptest.NewRequest("POST", "/api/auth/setup", nil))
	if rec.Code != 400 {
		t.Fatalf("未定模式设密应 400, 得到 %d", rec.Code)
	}
	settings.RunMode = "managed"
	rec2 := httptest.NewRecorder()
	handleAuthSetup(rec2, httptest.NewRequest("POST", "/api/auth/setup", nil))
	if rec2.Code != 403 {
		t.Fatalf("被群控设密应 403, 得到 %d", rec2.Code)
	}
}
