package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func resetDeviceTrusts(t *testing.T) {
	t.Helper()
	dataDir = t.TempDir()
	deviceTrustLoaded = false
	deviceTrusts = nil
}

func reqWithIP(ip string) *http.Request {
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	if ip != "" && ip != "127.0.0.1" {
		r.Header.Set("X-Real-IP", ip)
	}
	return r
}

func TestRealIP(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		xri    string
		xff    string
		want   string
	}{
		{"回环+X-Real-IP", "127.0.0.1:1", "1.2.3.4", "", "1.2.3.4"},
		{"回环+XFF 首个", "127.0.0.1:1", "", "5.6.7.8, 9.9.9.9", "5.6.7.8"},
		{"回环无头", "127.0.0.1:1", "", "", "127.0.0.1"},
		{"非回环忽略 XFF(防伪造)", "8.8.8.8:1", "", "1.2.3.4", "8.8.8.8"},
		{"非回环忽略 XRI(防伪造)", "8.8.8.8:1", "1.2.3.4", "", "8.8.8.8"},
		{"回环非法 XRI 回落 XFF", "127.0.0.1:1", "not-an-ip", "5.6.7.8", "5.6.7.8"},
		{"回环非法头全回落", "127.0.0.1:1", "nope", "nope", "127.0.0.1"},
		{"v6 回环+XRI", "[::1]:1", "2001:db8::1", "", "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = c.remote
		if c.xri != "" {
			r.Header.Set("X-Real-IP", c.xri)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := realIP(r); got != c.want {
			t.Errorf("%s: realIP = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClientIP(t *testing.T) {
	// clientIP 必须与 realIP 一致: 反代后登录鉴权才能看到真实 IP。
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	if got := clientIP(r); got != "1.2.3.4" {
		t.Errorf("clientIP behind proxy = %q, want 1.2.3.4", got)
	}
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.RemoteAddr = "8.8.8.8:1"
	r2.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r2); got != "8.8.8.8" {
		t.Errorf("clientIP direct = %q, want 8.8.8.8 (spoofed header must be ignored)", got)
	}
}

func TestDeviceTrustRoundtrip(t *testing.T) {
	resetDeviceTrusts(t)
	// 首次验证通过: 发设备 cookie, 绑定 IP。
	rec := httptest.NewRecorder()
	recordDeviceTrust(rec, reqWithIP("1.2.3.4"), "1.2.3.4")
	cookies := rec.Result().Cookies()
	var dev *http.Cookie
	for _, ck := range cookies {
		if ck.Name == deviceCookieName {
			dev = ck
		}
	}
	if dev == nil || dev.Value == "" {
		t.Fatalf("no device cookie issued")
	}
	// 同 IP 同设备 -> 信任。
	r := reqWithIP("1.2.3.4")
	r.AddCookie(dev)
	if !trustedDevice(r) {
		t.Fatalf("same IP+device should be trusted")
	}
	// 换 IP -> 不信任。
	r2 := reqWithIP("5.6.7.8")
	r2.AddCookie(dev)
	if trustedDevice(r2) {
		t.Fatalf("changed IP must not be trusted")
	}
	// 无 cookie -> 不信任。
	if trustedDevice(reqWithIP("1.2.3.4")) {
		t.Fatalf("no device cookie must not be trusted")
	}
	// 换 IP 后重新验证: 复用同一设备记录, 绑定新 IP。
	rec2 := httptest.NewRecorder()
	r3 := reqWithIP("5.6.7.8")
	r3.AddCookie(dev)
	recordDeviceTrust(rec2, r3, "5.6.7.8")
	r4 := reqWithIP("5.6.7.8")
	r4.AddCookie(dev)
	if !trustedDevice(r4) {
		t.Fatalf("device re-verified from new IP should be trusted there")
	}
	// 过期 -> 不信任。
	deviceTrustMu.Lock()
	deviceTrusts[0].Expires = time.Now().Add(-time.Hour).Unix()
	deviceTrustMu.Unlock()
	r5 := reqWithIP("5.6.7.8")
	r5.AddCookie(dev)
	if trustedDevice(r5) {
		t.Fatalf("expired device trust must not be trusted")
	}
	// 清空 -> 不信任。
	clearDeviceTrusts()
	r6 := reqWithIP("5.6.7.8")
	r6.AddCookie(dev)
	if trustedDevice(r6) {
		t.Fatalf("cleared device trust must not be trusted")
	}
}
