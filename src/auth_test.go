package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// authTestSetup 重置鉴权相关全局量, 指向临时数据目录, nft 干跑。
func authTestSetup(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldAuthFile, oldBansFile, oldEventsDir, oldDry := authFile, bansFile, eventsDir, dryBan
	authFile = filepath.Join(dir, "auth.json")
	bansFile = filepath.Join(dir, "bans.json")
	eventsDir = filepath.Join(dir, "events")
	eventsSrcDir = filepath.Join(dir, "events-src")
	os.MkdirAll(eventsDir, 0755)
	os.MkdirAll(eventsSrcDir, 0755)
	dryBan = true
	authMu.Lock()
	auth = adminAuth{}
	authMu.Unlock()
	sessMu.Lock()
	sessions = map[string]*session{}
	sessMu.Unlock()
	panelFailMu.Lock()
	panelFails = map[string][]int64{}
	panelFailMu.Unlock()
	// 2FA 全局量也重置: 否则 -count 多轮同进程跑时上一轮残留会污染下一轮。
	totpPendingMu.Lock()
	totpPendingSecret = ""
	totpPendingMu.Unlock()
	pendingMu.Lock()
	pending = map[string]*pending2FA{}
	pendingMu.Unlock()
	banMu.Lock()
	bans = []*Ban{}
	banMu.Unlock()
	mu.Lock()
	settings = defaultSettings()
	settings.RunMode = "standalone" // 测试默认独立机(已选模式), 否则设密会被模式门拦
	mu.Unlock()
	t.Cleanup(func() {
		authFile, bansFile, eventsDir, dryBan = oldAuthFile, oldBansFile, oldEventsDir, oldDry
	})
}

func doJSON(t *testing.T, h http.HandlerFunc, method, path, body, remote string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestCheckStrongPassword(t *testing.T) {
	cases := []struct {
		pw   string
		want string // "" 表示通过
	}{
		{"short1A!", "密码至少 12 位"},
		{"alllowercase1!", "密码须含大写、小写、数字、符号"},
		{"ALLUPPERCASE1!", "密码须含大写、小写、数字、符号"},
		{"MixedCaseNoDigit!", "密码须含大写、小写、数字、符号"},
		{"MixedCase123456", "密码须含大写、小写、数字、符号"},
		{"MixedCase1!234", ""},
		{"Ab1!Ab1!Ab1!Ab", ""},
	}
	for _, c := range cases {
		if got := checkStrongPassword(c.pw); got != c.want {
			t.Errorf("checkStrongPassword(%q) = %q, want %q", c.pw, got, c.want)
		}
	}
}

func setupTestPassword(t *testing.T) {
	t.Helper()
	rec := doJSON(t, handleAuthSetup, "POST", "/api/auth/setup",
		`{"password":"StrongPass1!xx","confirm":"StrongPass1!xx"}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("setup 应成功, 得到 %d %s", rec.Code, rec.Body.String())
	}
}

func loginTestPassword(t *testing.T, remote string, remember bool) *httptest.ResponseRecorder {
	t.Helper()
	rem := "false"
	if remember {
		rem = "true"
	}
	return doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
		`{"password":"StrongPass1!xx","remember":`+rem+`}`, remote)
}

func TestAuthSetupLoginLogout(t *testing.T) {
	authTestSetup(t)
	if !(!hasPassword()) {
		t.Fatal("初始应无密码")
	}
	// 弱密码拒绝
	rec := doJSON(t, handleAuthSetup, "POST", "/api/auth/setup",
		`{"password":"weak","confirm":"weak"}`, "203.0.113.9:1234")
	if rec.Code != 400 {
		t.Fatalf("弱密码应 400, 得到 %d", rec.Code)
	}
	// 两次不一致拒绝
	rec = doJSON(t, handleAuthSetup, "POST", "/api/auth/setup",
		`{"password":"StrongPass1!xx","confirm":"StrongPass1!yy"}`, "203.0.113.9:1234")
	if rec.Code != 400 {
		t.Fatalf("不一致应 400, 得到 %d", rec.Code)
	}
	setupTestPassword(t)
	// 重复设置拒绝
	rec = doJSON(t, handleAuthSetup, "POST", "/api/auth/setup",
		`{"password":"StrongPass1!xx","confirm":"StrongPass1!xx"}`, "203.0.113.9:1234")
	if rec.Code != 403 {
		t.Fatalf("重复设置应 403, 得到 %d", rec.Code)
	}
	// 错密码 401
	rec = doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
		`{"password":"WrongPass1!xx","remember":false}`, "203.0.113.9:1234")
	if rec.Code != 401 {
		t.Fatalf("错密码应 401, 得到 %d %s", rec.Code, rec.Body.String())
	}
	// 正确登录发 cookie
	rec = loginTestPassword(t, "203.0.113.9:1234", false)
	if rec.Code != 200 {
		t.Fatalf("登录应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			ck = c
		}
	}
	if ck == nil || ck.Value == "" {
		t.Fatal("登录应发 session cookie")
	}
	if ck.HttpOnly != true {
		t.Error("session cookie 应为 HttpOnly")
	}
	// cookie 有效
	req := httptest.NewRequest("GET", "/api/overview", nil)
	req.AddCookie(ck)
	if !validSession(req) {
		t.Error("登录后 session 应有效")
	}
	// 退出后失效
	req2 := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req2.AddCookie(ck)
	rec2 := httptest.NewRecorder()
	handleAuthLogout(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("退出应 200, 得到 %d", rec2.Code)
	}
	req3 := httptest.NewRequest("GET", "/api/overview", nil)
	req3.AddCookie(ck)
	if validSession(req3) {
		t.Error("退出后 session 应失效")
	}
}

func TestPanelBanThreshold(t *testing.T) {
	authTestSetup(t)
	setupTestPassword(t)
	ip := "203.0.113.7:1234"
	// 前 4 次只 401, 第 5 次触发封禁 403
	for i := 1; i <= 4; i++ {
		rec := doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
			`{"password":"WrongPass1!xx","remember":false}`, ip)
		if rec.Code != 401 {
			t.Fatalf("第 %d 次错密码应 401, 得到 %d", i, rec.Code)
		}
	}
	rec := doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
		`{"password":"WrongPass1!xx","remember":false}`, ip)
	if rec.Code != 403 {
		t.Fatalf("第 5 次应触发封禁 403, 得到 %d %s", rec.Code, rec.Body.String())
	}
	// 封禁记录: 统一黑名单, 7 天, 来源 panel, 记录保留
	found := false
	for _, b := range allBans() {
		if b.IP == "203.0.113.7" && b.Status == BanActive && b.Source == "panel" {
			found = true
			days := float64(b.Until-time.Now().Unix()) / 86400
			if days < 6.9 || days > 7.1 {
				t.Errorf("面板封禁应为 7 天, 得到 %.2f 天", days)
			}
		}
	}
	if !found {
		t.Error("应有一条生效中的 panel 封禁记录")
	}
	// 已封禁 IP 即使用正确密码也进不去
	rec = loginTestPassword(t, ip, false)
	if rec.Code != 403 {
		t.Fatalf("已封禁 IP 登录应 403, 得到 %d", rec.Code)
	}
}

func TestPanelBanSuccessResets(t *testing.T) {
	authTestSetup(t)
	setupTestPassword(t)
	ip := "203.0.113.8:1234"
	for i := 0; i < 4; i++ {
		doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
			`{"password":"WrongPass1!xx","remember":false}`, ip)
	}
	// 成功一次清零
	if rec := loginTestPassword(t, ip, false); rec.Code != 200 {
		t.Fatalf("正确登录应 200, 得到 %d", rec.Code)
	}
	// 再错 4 次仍不封, 第 5 次才封
	for i := 1; i <= 4; i++ {
		rec := doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
			`{"password":"WrongPass1!xx","remember":false}`, ip)
		if rec.Code != 401 {
			t.Fatalf("清零后第 %d 次应 401, 得到 %d", i, rec.Code)
		}
	}
	rec := doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
		`{"password":"WrongPass1!xx","remember":false}`, ip)
	if rec.Code != 403 {
		t.Fatalf("清零后第 5 次应封禁 403, 得到 %d", rec.Code)
	}
}

func TestPanelBanExemptsPrivate(t *testing.T) {
	authTestSetup(t)
	setupTestPassword(t)
	for i := 0; i < 6; i++ {
		rec := doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
			`{"password":"WrongPass1!xx","remember":false}`, "127.0.0.1:1234")
		if rec.Code != 401 {
			t.Fatalf("内网 IP 错密码应始终 401(豁免不封), 第 %d 次得到 %d", i+1, rec.Code)
		}
	}
	if isGloballyBanned("127.0.0.1") {
		t.Error("内网 IP 不应被面板防爆破封禁")
	}
}

func TestAuthPasswordChangeInvalidatesOthers(t *testing.T) {
	authTestSetup(t)
	setupTestPassword(t)
	recA := loginTestPassword(t, "203.0.113.9:1234", false)
	recB := loginTestPassword(t, "203.0.113.10:1234", false)
	var ckA, ckB *http.Cookie
	for _, c := range recA.Result().Cookies() {
		if c.Name == sessionCookieName {
			ckA = c
		}
	}
	for _, c := range recB.Result().Cookies() {
		if c.Name == sessionCookieName {
			ckB = c
		}
	}
	// A 改密(带 A 的 cookie)
	req := httptest.NewRequest("POST", "/api/auth/password",
		strings.NewReader(`{"current":"StrongPass1!xx","password":"NewStrong2@yy","confirm":"NewStrong2@yy"}`))
	req.AddCookie(ckA)
	rec := httptest.NewRecorder()
	handleAuthPassword(rec, req)
	if rec.Code != 200 {
		t.Fatalf("改密应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	// A 的 session 续用有效, B 的失效
	reqA := httptest.NewRequest("GET", "/api/overview", nil)
	reqA.AddCookie(ckA)
	if !validSession(reqA) {
		t.Error("改密者自己的 session 应续用有效")
	}
	reqB := httptest.NewRequest("GET", "/api/overview", nil)
	reqB.AddCookie(ckB)
	if validSession(reqB) {
		t.Error("改密后其他 session 应失效")
	}
	// 旧密码失效, 新密码可用
	rec = doJSON(t, handleAuthLogin, "POST", "/api/auth/login",
		`{"password":"StrongPass1!xx","remember":false}`, "203.0.113.9:1234")
	if rec.Code != 401 {
		t.Fatalf("旧密码应 401, 得到 %d", rec.Code)
	}
}

func TestAuthMiddleware(t *testing.T) {
	authTestSetup(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	h := authMiddleware(inner)
	// 未登录拦 /api/overview
	req := httptest.NewRequest("GET", "/api/overview", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("未登录访问 API 应 401, 得到 %d", rec.Code)
	}
	// /api/auth/status 例外
	req = httptest.NewRequest("GET", "/api/auth/status", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status 应例外放行, 得到 %d", rec.Code)
	}
	// 非 API 路径(面板 HTML)放行
	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("面板 HTML 应放行, 得到 %d", rec.Code)
	}
	// 登录后放行
	setupTestPassword(t)
	lr := loginTestPassword(t, "203.0.113.9:1234", false)
	var ck *http.Cookie
	for _, c := range lr.Result().Cookies() {
		if c.Name == sessionCookieName {
			ck = c
		}
	}
	req = httptest.NewRequest("GET", "/api/overview", nil)
	req.AddCookie(ck)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("登录后访问 API 应 200, 得到 %d", rec.Code)
	}
}
