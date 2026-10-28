package main

// 设置页群控模块单测：已独立的面板可经“接入主服务器”弹窗转为被控节点。
// 锁住：standalone→managed 成功且防护数据不动、接入同时立即取消本地登录凭证
// （密码与 2FA 清掉、现存 session 作废、信任设备清空；错码时凭证不动）、
// 脱离回落后无密码须重新设置密码、已有子服务器时接入被拒、被控后管理接口只读、
// 生成配对码接口与原来一致、设置页新模块结构（两按钮弹窗、旧卡内生成区消失）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeJoinHub: 模拟主服务器 hello 端点。GOOD 码回 pending，其余回 403。
func fakeJoinHub(t *testing.T, hits *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/nodes/hello" {
			w.WriteHeader(404)
			return
		}
		if hits != nil {
			*hits++
		}
		var in struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Code == "BAD" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":"配对码无效或已过期"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
}

// stopLinkLoop: 成功用例起的拨号器在 pending 循环里每 5 秒查一次模式；
// 把模式翻回独立并等它退出，避免残留 goroutine 干扰后续测试。
func stopLinkLoop(t *testing.T) {
	t.Helper()
	settings.RunMode = "standalone"
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		linkRunMu.Lock()
		running := linkRunning
		linkRunMu.Unlock()
		if !running {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("拨号器在模式翻回后 8 秒内未退出")
}

func TestSetupJoinHubSuccess(t *testing.T) {
	defer setupNodeTest(t)()
	hubSrv := fakeJoinHub(t, nil)
	defer hubSrv.Close()
	loadNodeIdentity()
	settings.RunMode = "standalone"
	settings.ServerName = "B机"
	settings.ManualLocation = "江苏"
	req := httptest.NewRequest("POST", "/api/setup/join-hub",
		strings.NewReader(`{"hubUrl":"`+hubSrv.URL+`","code":"GOOD"}`))
	rec := httptest.NewRecorder()
	handleSetupJoinHub(rec, req)
	if rec.Code != 200 {
		t.Fatalf("接入应成功: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if settings.RunMode != "managed" || settings.HubURL != hubSrv.URL {
		t.Fatalf("接入后模式应为 managed 且 HubURL 落盘, 得到 mode=%q hub=%q", settings.RunMode, settings.HubURL)
	}
	// 本地数据不动：服务器名与手动归属地原样保留。
	if settings.ServerName != "B机" || settings.ManualLocation != "江苏" {
		t.Fatalf("接入不应改动本地数据, 得到 name=%q loc=%q", settings.ServerName, settings.ManualLocation)
	}
	if settings.JoinError != "" {
		t.Fatalf("成功接入不应留 JoinError, 得到 %q", settings.JoinError)
	}
	stopLinkLoop(t)
}

func TestSetupJoinHubBadCode(t *testing.T) {
	defer setupNodeTest(t)()
	hubSrv := fakeJoinHub(t, nil)
	defer hubSrv.Close()
	loadNodeIdentity()
	settings.RunMode = "standalone"
	req := httptest.NewRequest("POST", "/api/setup/join-hub",
		strings.NewReader(`{"hubUrl":"`+hubSrv.URL+`","code":"BAD"}`))
	rec := httptest.NewRecorder()
	handleSetupJoinHub(rec, req)
	if rec.Code != 400 {
		t.Fatalf("错码应 400: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if settings.RunMode != "standalone" {
		t.Fatalf("错码时模式必须不动, 得到 %q", settings.RunMode)
	}
	if settings.HubURL != "" {
		t.Fatalf("错码时 HubURL 不应落盘, 得到 %q", settings.HubURL)
	}
}

func TestSetupJoinHubBlockedByServers(t *testing.T) {
	defer setupNodeTest(t)()
	oldServers := hubServers
	defer func() { hubServers = oldServers }()
	hubServers = []*hubServer{{Fingerprint: strings.Repeat("a", 64), Name: "子服务器"}}
	hits := 0
	hubSrv := fakeJoinHub(t, &hits)
	defer hubSrv.Close()
	loadNodeIdentity()
	settings.RunMode = "standalone"
	req := httptest.NewRequest("POST", "/api/setup/join-hub",
		strings.NewReader(`{"hubUrl":"`+hubSrv.URL+`","code":"GOOD"}`))
	rec := httptest.NewRecorder()
	handleSetupJoinHub(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "请先移除/处理全部子服务器") {
		t.Fatalf("已有子服务器时应 400 且提示先移除: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if settings.RunMode != "standalone" {
		t.Fatalf("被拒时模式必须不动, 得到 %q", settings.RunMode)
	}
	if hits != 0 {
		t.Fatalf("被拒时不应向主服务器校验配对码, 命中 %d 次", hits)
	}
}

func TestSetupJoinHubManagedRejected(t *testing.T) {
	defer setupNodeTest(t)()
	settings.RunMode = "managed"
	req := httptest.NewRequest("POST", "/api/setup/join-hub",
		strings.NewReader(`{"hubUrl":"https://hub.example.com","code":"GOOD"}`))
	rec := httptest.NewRecorder()
	handleSetupJoinHub(rec, req)
	if rec.Code != 403 {
		t.Fatalf("被控节点再接入应 403: code=%d", rec.Code)
	}
}

func TestManagedReadOnlyMiddleware(t *testing.T) {
	defer setupNodeTest(t)()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	// 被控后管理接口一律 403（中间件先于鉴权拦截）。
	settings.RunMode = "managed"
	rec := httptest.NewRecorder()
	authMiddleware(next).ServeHTTP(rec, httptest.NewRequest("GET", "/api/settings", nil))
	if rec.Code != 403 {
		t.Fatalf("被控后 /api/settings 应 403, 得到 %d", rec.Code)
	}
	// 独立面板无 session 时管理接口 401：接入接口必须登录才能调。
	settings.RunMode = "standalone"
	rec2 := httptest.NewRecorder()
	authMiddleware(next).ServeHTTP(rec2, httptest.NewRequest("POST", "/api/setup/join-hub", nil))
	if rec2.Code != 401 {
		t.Fatalf("未登录调接入接口应 401, 得到 %d", rec2.Code)
	}
}

func TestPairingCodeAPIUnchanged(t *testing.T) {
	defer setupNodeTest(t)()
	req := httptest.NewRequest("POST", "/api/nodes/pairing-code", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handlePairingCode(rec, req)
	if rec.Code != 200 {
		t.Fatalf("生成配对码接口应 200, 得到 %d", rec.Code)
	}
	var v struct {
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &v) != nil || v.Code == "" || v.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("生成配对码应回 code 与未来 expiresAt, 得到 %+v", v)
	}
}

func TestJoinHubUI(t *testing.T) {
	html := string(indexHTML)
	for _, s := range []string{
		`id="btnJoinHub"`, `id="btnPairGen2"`,
		`接入主服务器（被控）`, `生成配对码（控制子服务器）`,
		`function openJoinHubModal`, `function openPairGenModal`,
		`api/setup/join-hub`, `api/nodes/pairing-code`,
		`只读状态页`, `guijia leave`, `请先移除/处理全部子服务器`,
		`id="pairPending"`, `id="btnPairRefresh"`,
	} {
		if !strings.Contains(html, s) {
			t.Errorf("设置页群控模块缺 %q", s)
		}
	}
	for _, s := range []string{
		`id="pairCodeTx"`, `id="pairCodeBox"`, `id="btnPairGen"`, `id="btnPairCopy"`,
		`id="pairCodeExp"`,
	} {
		if strings.Contains(html, s) {
			t.Errorf("旧卡内生成区应已搬进弹窗, 不应再有 %q", s)
		}
	}
}

func TestSetupJoinHubClearsCredentials(t *testing.T) {
	defer setupNodeTest(t)()
	dir := t.TempDir()
	oldDataDir, oldAuthFile := dataDir, authFile
	dataDir, authFile = dir, filepath.Join(dir, "auth.json")
	defer func() { dataDir, authFile = oldDataDir, oldAuthFile }()
	oldTrusts, oldLoaded := deviceTrusts, deviceTrustLoaded
	defer func() { deviceTrusts, deviceTrustLoaded = oldTrusts, oldLoaded }()
	deviceTrusts = []*deviceTrust{{Hash: "h", IP: "1.2.3.4", Expires: time.Now().Add(time.Hour).Unix()}}
	deviceTrustLoaded = true
	oldSessions := sessions
	sessions = map[string]*session{"tok": {token: "tok", gen: 0, expires: time.Now().Add(time.Hour)}}
	defer func() { sessions = oldSessions }()
	auth.PassHash = "pbkdf2-sha256$1$abc$def"
	auth.TOTPSecret = "SECRET"
	auth.TOTPEnabled = true
	auth.RecoveryCodes = []string{"aa", "bb"}
	auth.SessionGen = 0
	hubSrv := fakeJoinHub(t, nil)
	defer hubSrv.Close()
	loadNodeIdentity()
	settings.RunMode = "standalone"
	settings.ServerName = "B机"
	req := httptest.NewRequest("POST", "/api/setup/join-hub",
		strings.NewReader(`{"hubUrl":"`+hubSrv.URL+`","code":"GOOD"}`))
	rec := httptest.NewRecorder()
	handleSetupJoinHub(rec, req)
	if rec.Code != 200 {
		t.Fatalf("接入应成功: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if settings.RunMode != "managed" {
		t.Fatalf("接入后模式应为 managed, 得到 %q", settings.RunMode)
	}
	// 本地登录凭证立即取消：密码、2FA、恢复码全清，代次 +1 废掉旧 session。
	if auth.PassHash != "" || auth.TOTPSecret != "" || auth.TOTPEnabled || len(auth.RecoveryCodes) != 0 {
		t.Fatalf("接入应清掉密码与 2FA, 得到 passHash=%q totp=%q enabled=%v recovery=%d",
			auth.PassHash, auth.TOTPSecret, auth.TOTPEnabled, len(auth.RecoveryCodes))
	}
	if auth.SessionGen != 1 {
		t.Fatalf("接入应抬代次废掉现存 session, 得到 gen=%d", auth.SessionGen)
	}
	if _, ok := sessions["tok"]; ok {
		// 旧 session 代次已不符：sessionOf 视角下它已失效（map 里残留无妨，gen 对不上）。
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "tok"})
		if sessionOf(r) != nil {
			t.Fatalf("旧 session 在代次抬升后应失效")
		}
	}
	if len(deviceTrusts) != 0 {
		t.Fatalf("接入应清空信任设备, 剩余 %d 条", len(deviceTrusts))
	}
	// 防护数据不动：服务器名原样保留。
	if settings.ServerName != "B机" {
		t.Fatalf("接入不应改动防护数据, 得到 name=%q", settings.ServerName)
	}
	stopLinkLoop(t)
}

func TestSetupJoinHubBadCodeKeepsCredentials(t *testing.T) {
	defer setupNodeTest(t)()
	auth.PassHash = "pbkdf2-sha256$1$abc$def"
	auth.TOTPEnabled = true
	auth.TOTPSecret = "SECRET"
	hubSrv := fakeJoinHub(t, nil)
	defer hubSrv.Close()
	loadNodeIdentity()
	settings.RunMode = "standalone"
	req := httptest.NewRequest("POST", "/api/setup/join-hub",
		strings.NewReader(`{"hubUrl":"`+hubSrv.URL+`","code":"BAD"}`))
	rec := httptest.NewRecorder()
	handleSetupJoinHub(rec, req)
	if rec.Code != 400 {
		t.Fatalf("错码应 400: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if auth.PassHash == "" || !auth.TOTPEnabled || auth.TOTPSecret == "" {
		t.Fatalf("错码时凭证必须不动, 得到 passHash=%q totp=%v secret=%q", auth.PassHash, auth.TOTPEnabled, auth.TOTPSecret)
	}
}

// TestJoinHubDetachRequiresPassword: 走完整链路——加入时凭证已清，
// 随后被主服务器移除，回落为未定模式且无密码——选独立使用必须重新设置密码。
func TestJoinHubDetachRequiresPassword(t *testing.T) {
	defer setupNodeTest(t)()
	auth.PassHash = "pbkdf2-sha256$1$abc$def"
	auth.TOTPEnabled = true
	auth.TOTPSecret = "SECRET"
	hubSrv := fakeJoinHub(t, nil)
	defer hubSrv.Close()
	loadNodeIdentity()
	settings.RunMode = "standalone"
	req := httptest.NewRequest("POST", "/api/setup/join-hub",
		strings.NewReader(`{"hubUrl":"`+hubSrv.URL+`","code":"GOOD"}`))
	rec := httptest.NewRecorder()
	handleSetupJoinHub(rec, req)
	if rec.Code != 200 {
		t.Fatalf("接入应成功: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if hasPassword() || auth.TOTPEnabled {
		t.Fatalf("加入后凭证应已清, 得到 passHash=%q totp=%v", auth.PassHash, auth.TOTPEnabled)
	}
	// 主服务器移除 → 节点自动脱离（不翻模式：回落断言就看这次翻转）。
	rollbackJoin("revoked")
	if effectiveRunMode() != "" {
		t.Fatalf("脱离后无密码应回未定模式, 得到 %q", effectiveRunMode())
	}
	if hasPassword() {
		t.Fatalf("脱离后应无密码")
	}
	if !(!hasPassword() && effectiveRunMode() != "managed") {
		t.Fatalf("脱离后应满足 setupRequired（须重新设置密码）")
	}
	// 等拨号器自行退出（模式已不是 managed，不用 stopLinkLoop 翻模式）。
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		linkRunMu.Lock()
		running := linkRunning
		linkRunMu.Unlock()
		if !running {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("拨号器在脱离后 8 秒内未退出")
}
