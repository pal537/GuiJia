package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// RFC 6238 SHA1 测试向量: 密钥 ASCII "12345678901234567890"。
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPCodeRFCVectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := totpCodeAt(rfcSecret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("totpCodeAt(%d) error: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("totpCodeAt(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestTOTPVerifyWindow(t *testing.T) {
	now := time.Unix(1234567890, 0).UTC()
	code, _ := totpCodeAt(rfcSecret, now)
	if !verifyTOTP(rfcSecret, code, now) {
		t.Error("同一时刻的动态码应通过")
	}
	if !verifyTOTP(rfcSecret, code, now.Add(30*time.Second)) {
		t.Error("±1 步内的动态码应通过")
	}
	if verifyTOTP(rfcSecret, code, now.Add(60*time.Second)) {
		t.Error("±2 步外的动态码不应通过")
	}
	if verifyTOTP(rfcSecret, "000000", now) {
		t.Error("错误动态码不应通过")
	}
	if verifyTOTP(rfcSecret, "12345", now) {
		t.Error("非 6 位输入不应通过")
	}
}

func TestTOTPFullFlow(t *testing.T) {
	authTestSetup(t)
	setupTestPassword(t)
	// 登录一次拿 session(2FA 未开, 直接登录)
	lr := loginTestPassword(t, "203.0.113.9:1234", false)
	var ck *http.Cookie
	for _, c := range lr.Result().Cookies() {
		if c.Name == sessionCookieName {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("应拿到 session cookie")
	}
	callAuthed := func(h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(ck)
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	// 开通前启用应失败(未获取密钥)
	rec := callAuthed(handleAuthTOTPEnable, "POST", "/api/auth/totp/enable", `{"code":"123456"}`)
	if rec.Code != 400 {
		t.Fatalf("未获取密钥就启用应 400, 得到 %d", rec.Code)
	}
	// 获取密钥
	rec = callAuthed(handleAuthTOTPSetup, "POST", "/api/auth/totp/setup", `{}`)
	if rec.Code != 200 {
		t.Fatalf("获取密钥应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	var setupResp struct {
		Secret     string `json:"secret"`
		OTPAUTHURL string `json:"otpauth_url"`
	}
	json.NewDecoder(rec.Body).Decode(&setupResp)
	if setupResp.Secret == "" || !strings.Contains(setupResp.OTPAUTHURL, setupResp.Secret) {
		t.Fatalf("密钥/otpauth URL 异常: %+v", setupResp)
	}
	// 错码启用失败
	rec = callAuthed(handleAuthTOTPEnable, "POST", "/api/auth/totp/enable", `{"code":"000000"}`)
	if rec.Code != 401 {
		t.Fatalf("错码启用应 401, 得到 %d", rec.Code)
	}
	// 对码启用成功, 返回 10 个恢复码
	code, err := totpCodeAt(setupResp.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = callAuthed(handleAuthTOTPEnable, "POST", "/api/auth/totp/enable", `{"code":"`+code+`"}`)
	if rec.Code != 200 {
		t.Fatalf("对码启用应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	var enableResp struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	json.NewDecoder(rec.Body).Decode(&enableResp)
	if len(enableResp.RecoveryCodes) != 10 {
		t.Fatalf("应返回 10 个恢复码, 得到 %d", len(enableResp.RecoveryCodes))
	}
	// 登录现需 2FA
	lr2 := loginTestPassword(t, "203.0.113.9:1234", false)
	var step1 struct {
		Need2FA bool   `json:"need2fa"`
		Pending string `json:"pending"`
	}
	json.NewDecoder(lr2.Body).Decode(&step1)
	if !step1.Need2FA || step1.Pending == "" {
		t.Fatalf("2FA 开通后登录应返回 need2fa + pending, 得到 %s", lr2.Body.String())
	}
	// 错码验证失败
	rec = doJSON(t, handleAuthTOTPVerify, "POST", "/api/auth/totp/verify",
		`{"pending":"`+step1.Pending+`","code":"000000"}`, "203.0.113.9:1234")
	if rec.Code != 401 {
		t.Fatalf("错码验证应 401, 得到 %d", rec.Code)
	}
	// 临时凭证一次性: 上次失败已消费 pending, 需重新登录
	lr3 := loginTestPassword(t, "203.0.113.9:1234", false)
	json.NewDecoder(lr3.Body).Decode(&step1)
	code2, _ := totpCodeAt(setupResp.Secret, time.Now())
	rec = doJSON(t, handleAuthTOTPVerify, "POST", "/api/auth/totp/verify",
		`{"pending":"`+step1.Pending+`","code":"`+code2+`"}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("对码验证应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	gotCookie := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Error("2FA 验证通过后应发 session cookie")
	}
	// 恢复码登录一次, 再用同一码应失败
	lr4 := loginTestPassword(t, "203.0.113.9:1234", false)
	json.NewDecoder(lr4.Body).Decode(&step1)
	rc := enableResp.RecoveryCodes[0]
	rec = doJSON(t, handleAuthTOTPVerify, "POST", "/api/auth/totp/verify",
		`{"pending":"`+step1.Pending+`","code":"`+rc+`"}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("恢复码验证应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	lr5 := loginTestPassword(t, "203.0.113.9:1234", false)
	json.NewDecoder(lr5.Body).Decode(&step1)
	rec = doJSON(t, handleAuthTOTPVerify, "POST", "/api/auth/totp/verify",
		`{"pending":"`+step1.Pending+`","code":"`+rc+`"}`, "203.0.113.9:1234")
	if rec.Code != 401 {
		t.Fatalf("用过的恢复码应 401, 得到 %d", rec.Code)
	}
	// 关闭 2FA: 错密码拒绝, 对密码成功, 此后登录不再要 2FA
	rec = callAuthed(handleAuthTOTPDisable, "POST", "/api/auth/totp/disable", `{"password":"WrongPass1!xx"}`)
	if rec.Code != 401 {
		t.Fatalf("关闭 2FA 错密码应 401, 得到 %d", rec.Code)
	}
	rec = callAuthed(handleAuthTOTPDisable, "POST", "/api/auth/totp/disable", `{"password":"StrongPass1!xx"}`)
	if rec.Code != 200 {
		t.Fatalf("关闭 2FA 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	lr6 := loginTestPassword(t, "203.0.113.9:1234", false)
	var step6 struct {
		Need2FA bool `json:"need2fa"`
	}
	json.NewDecoder(lr6.Body).Decode(&step6)
	if step6.Need2FA {
		t.Error("关闭 2FA 后登录不应再要二次验证")
	}
}

func TestTOTPMiddlewareRequiresSession(t *testing.T) {
	authTestSetup(t)
	setupTestPassword(t)
	h := authMiddleware(http.HandlerFunc(handleAuthTOTPSetup))
	// 未登录拦
	req := httptest.NewRequest("POST", "/api/auth/totp/setup", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("未登录调 totp/setup 应 401, 得到 %d", rec.Code)
	}
	// 登录后放行
	lr := loginTestPassword(t, "203.0.113.9:1234", false)
	var ck *http.Cookie
	for _, c := range lr.Result().Cookies() {
		if c.Name == sessionCookieName {
			ck = c
		}
	}
	req = httptest.NewRequest("POST", "/api/auth/totp/setup", strings.NewReader(`{}`))
	req.AddCookie(ck)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("登录后调 totp/setup 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
}
