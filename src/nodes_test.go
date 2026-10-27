package main

import (
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
	req := httptest.NewRequest("POST", "/api/setup/mode", strings.NewReader(`{"mode":"managed","hubUrl":"https://hub.example.com/","code":"abc123"}`))
	rec := httptest.NewRecorder()
	handleSetupMode(rec, req)
	if rec.Code != 200 || settings.RunMode != "managed" || settings.HubURL != "https://hub.example.com" {
		t.Fatalf("加入失败: code=%d body=%s mode=%q hub=%q", rec.Code, rec.Body.String(), settings.RunMode, settings.HubURL)
	}
	if st, _, _ := linkSnapshot(); st != "joining" {
		t.Fatalf("加入后链路应为 joining, 得到 %q", st)
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
