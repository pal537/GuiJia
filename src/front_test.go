package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// frontTestCfg: 临时反代配置, 测试后恢复。
func frontTestCfg(t *testing.T, rules []*ProxyRule) {
	t.Helper()
	proxyMu.Lock()
	old := proxyCfg
	proxyCfg = ProxyConfig{Rules: rules}
	proxyMu.Unlock()
	t.Cleanup(func() {
		proxyMu.Lock()
		proxyCfg = old
		proxyMu.Unlock()
	})
}

func TestApplyProxyRuleDefaults(t *testing.T) {
	r := &ProxyRule{Domain: "a.example.com", Backend: "127.0.0.1:8080"}
	applyProxyRuleDefaults(r)
	if len(r.Listens) != 1 || r.Listens[0].Port != 443 || r.Listens[0].Protocol != "https" {
		t.Errorf("监听为空应默认 443 HTTPS, 得到 %+v", r.Listens)
	}
	if r.Cert != "auto" {
		t.Errorf("HTTPS 规则证书为空应默认 auto, 得到 %q", r.Cert)
	}
	// 纯 HTTP 规则不补证书
	r2 := &ProxyRule{Domain: "b.example.com", Backend: "127.0.0.1:8080",
		Listens: []ProxyListen{{Port: 8080, Protocol: "http"}}}
	applyProxyRuleDefaults(r2)
	if r2.Cert != "" {
		t.Errorf("纯 HTTP 规则不应补证书, 得到 %q", r2.Cert)
	}
	// 已有监听与证书不动
	r3 := &ProxyRule{Domain: "c.example.com", Backend: "127.0.0.1:8080",
		Listens: []ProxyListen{{Port: 8443, Protocol: "https"}}, Cert: "upload:x"}
	applyProxyRuleDefaults(r3)
	if r3.Listens[0].Port != 8443 || r3.Cert != "upload:x" {
		t.Errorf("已有值不应被默认值覆盖: %+v", r3)
	}
}

func TestValidateProxyPanelDomainConflict(t *testing.T) {
	panelTestSetup(t)
	mu.Lock()
	settings.PanelSSLMode = "domain"
	settings.PanelDomain = "panel.example.com"
	mu.Unlock()
	cfg := ProxyConfig{Rules: []*ProxyRule{
		{Domain: "panel.example.com", Listens: []ProxyListen{{Port: 443, Protocol: "https"}}, Backend: "127.0.0.1:8080", Cert: "auto", Enabled: true},
	}}
	if err := validateProxyConfig(cfg, nil); err == nil || !strings.Contains(err.Error(), "面板") {
		t.Errorf("反代规则抢面板域名应报错, 得到 %v", err)
	}
	mu.Lock()
	settings.PanelSSLMode = "off"
	mu.Unlock()
	if err := validateProxyConfig(cfg, nil); err == nil || !strings.Contains(err.Error(), "证书") {
		t.Errorf("面板域名模式关闭后应不再报面板冲突(此时应报证书问题), 得到 %v", err)
	}
}

func TestRedirectPortForDomain(t *testing.T) {
	frontTestCfg(t, []*ProxyRule{
		{Domain: "one.example.com", Listens: []ProxyListen{{Port: 8443, Protocol: "https"}}, Backend: "127.0.0.1:8080", Enabled: true},
		{Domain: "two.example.com", Listens: []ProxyListen{{Port: 8443, Protocol: "https"}, {Port: 9443, Protocol: "https"}}, Backend: "127.0.0.1:8080", Enabled: true},
		{Domain: "off.example.com", Listens: []ProxyListen{{Port: 8443, Protocol: "https"}}, Backend: "127.0.0.1:8080", Enabled: false},
	})
	if p := redirectPortForDomain("one.example.com"); p != 8443 {
		t.Errorf("唯一 HTTPS 端口应返回该端口, 得到 %d", p)
	}
	if p := redirectPortForDomain("two.example.com"); p != 443 {
		t.Errorf("多 HTTPS 端口应回落 443, 得到 %d", p)
	}
	if p := redirectPortForDomain("off.example.com"); p != 443 {
		t.Errorf("停用规则不应参与, 得到 %d", p)
	}
	if p := redirectPortForDomain("none.example.com"); p != 443 {
		t.Errorf("无规则域名应回落 443, 得到 %d", p)
	}
}

func TestFront80Dispatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "http://")
	frontTestCfg(t, []*ProxyRule{
		{Domain: "proxy80.example.com", Listens: []ProxyListen{{Port: 80, Protocol: "http"}}, Backend: backendHost, Enabled: true},
		{Domain: "app.example.com", Listens: []ProxyListen{{Port: 8443, Protocol: "https"}}, Backend: backendHost, Enabled: true},
	})
	h := http.HandlerFunc(front80Handler)
	// 匹配的 80 规则 -> 代理到后端
	req := httptest.NewRequest("GET", "http://proxy80.example.com/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != 200 || string(body) != "backend-ok" {
		t.Errorf("匹配的 80 规则应代理到后端, 得到 %d %q", rec.Code, string(body))
	}
	// 未匹配 80、域名有唯一 HTTPS 端口 -> 跳该端口
	req = httptest.NewRequest("GET", "http://app.example.com/foo?q=1", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 301 {
		t.Fatalf("未匹配应 301 跳转, 得到 %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "https://app.example.com:8443/foo?q=1" {
		t.Errorf("跳转目标应带唯一 HTTPS 端口, 得到 %q", loc)
	}
	// 无规则域名 -> 跳 443
	req = httptest.NewRequest("GET", "http://none.example.com/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Location") != "https://none.example.com/" {
		t.Errorf("无规则域名应跳 443 默认, 得到 %q", rec.Header().Get("Location"))
	}
	// ACME 验证路径优先于跳转
	frontRegisterChallenge("tok-z", "tok-z.thumb")
	defer frontClearChallenge("tok-z")
	req = httptest.NewRequest("GET", "http://none.example.com/.well-known/acme-challenge/tok-z", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ = io.ReadAll(rec.Result().Body)
	if rec.Code != 200 || string(body) != "tok-z.thumb" {
		t.Errorf("ACME 验证路径应优先应答, 得到 %d %q", rec.Code, string(body))
	}
}

func TestFront443Handler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("app-ok"))
	}))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "http://")
	frontTestCfg(t, []*ProxyRule{
		{Domain: "app.example.com", Listens: []ProxyListen{{Port: 443, Protocol: "https"}}, Backend: backendHost, Enabled: true},
	})
	oldMux := rootMux
	oldSettings := func() Settings { mu.Lock(); defer mu.Unlock(); return settings }()
	rootMux = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("panel-ok")) })
	mu.Lock()
	settings.PanelSSLMode = "domain"
	settings.PanelDomain = "panel.example.com"
	mu.Unlock()
	t.Cleanup(func() {
		rootMux = oldMux
		mu.Lock()
		settings = oldSettings
		mu.Unlock()
	})
	h := http.HandlerFunc(front443Handler)
	// 面板域名 -> 面板(走鉴权中间件, 未登录应 401, 而非后端内容)
	req := httptest.NewRequest("GET", "http://panel.example.com/api/overview", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("面板域名应走面板鉴权, 得到 %d", rec.Code)
	}
	// 反代域名 -> 后端
	req = httptest.NewRequest("GET", "http://app.example.com/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != 200 || string(body) != "app-ok" {
		t.Errorf("反代域名应代理到后端, 得到 %d %q", rec.Code, string(body))
	}
	// 无规则域名 -> 421
	req = httptest.NewRequest("GET", "http://none.example.com/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 421 {
		t.Errorf("无规则域名应 421, 得到 %d", rec.Code)
	}
}

func TestFront443GetCertificatePanel(t *testing.T) {
	panelTestSetup(t) // 数据目录里有 example.com 自签证书
	mu.Lock()
	settings.PanelSSLMode = "domain"
	settings.PanelDomain = "example.com"
	settings.PanelSSLCert = ""
	mu.Unlock()
	cert, err := front443GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil || cert == nil {
		t.Fatalf("面板域名自动匹配应返回证书, 得到 err=%v", err)
	}
	// 显式证书
	mu.Lock()
	settings.PanelSSLCert = "upload:example"
	mu.Unlock()
	cert, err = front443GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil || cert == nil {
		t.Fatalf("面板域名显式证书应返回, 得到 err=%v", err)
	}
	// 显式证书不存在 -> 报错
	mu.Lock()
	settings.PanelSSLCert = "upload:missing"
	mu.Unlock()
	if _, err := front443GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Error("面板证书不存在应报错")
	}
	// 非面板域名且无规则 -> 报错
	if _, err := front443GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err == nil {
		t.Error("无匹配规则的 SNI 应报错")
	}
}

func TestFrontApplyOn(t *testing.T) {
	frontTestCfg(t, []*ProxyRule{
		{Domain: "app.example.com", Listens: []ProxyListen{{Port: 443, Protocol: "https"}}, Backend: "127.0.0.1:8080", Enabled: true},
	})
	// 有 443 规则 -> 起监听(测试用随机端口)
	frontApplyOn("127.0.0.1:0")
	on, _ := front443Status()
	if !on {
		t.Fatal("有 443 规则时前置应起监听")
	}
	first := front443Srv
	frontApplyOn("127.0.0.1:0")
	if front443Srv != first {
		t.Error("已在跑时重复 frontApply 不应重建监听")
	}
	// 撤掉规则 -> 停监听
	frontTestCfg(t, []*ProxyRule{})
	frontApplyOn("127.0.0.1:0")
	on, _ = front443Status()
	if on || front443Srv != nil {
		t.Error("无 443 需求时前置应停监听")
	}
}
