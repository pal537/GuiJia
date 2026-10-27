package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 生成自签证书(测试内自签, 不依赖任何外部文件)。
func genTestCert(t *testing.T, dns []string, ips []net.IP, notAfter time.Time) (crtPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crtPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return crtPEM, keyPEM
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
		bad      bool
	}{
		{"EXAMPLE.com ", "example.com", false},
		{"example.com.", "example.com", false},
		{"example.com:8443", "example.com", false},
		{"  A.B-C.example.com ", "a.b-c.example.com", false},
		{"*.example.com", "*.example.com", false},
		{"*.EXAMPLE.COM.", "*.example.com", false},
		{"", "", true},
		{"   ", "", true},
		{"exa mple.com", "", true},
		{"-bad.com", "", true},
		{"bad-.com", "", true},
		{"bad..com", "", true},
		{"*.*.com", "", true},
		{"a.*.com", "", true},
		{"*example.com", "", true},
		{"192.168.1.1", "", true},
		{"example.com:abc", "", true},
		{"[::1]", "", true},
	}
	for _, c := range cases {
		got, err := normalizeDomain(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("normalizeDomain(%q) 应报错, 得到 %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeDomain(%q) 报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeDomain(%q) = %q,  want %q", c.in, got, c.want)
		}
	}
}

func TestDomainMatchesRule(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"a.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},     // 通配符不匹配 apex
		{"a.b.example.com", "*.example.com", false}, // 通配符只单层
		{"b.example.com", "*.example.com", true},
		{"other.com", "*.example.com", false},
		{"a.example.com", "example.com", false},
	}
	for _, c := range cases {
		if got := domainMatchesRule(c.host, c.pattern); got != c.want {
			t.Errorf("domainMatchesRule(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestFindProxyRuleByPortAndProtocol(t *testing.T) {
	rules := []*ProxyRule{
		{ID: "w", Domain: "*.example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "http"}}, Enabled: true},
		{ID: "e", Domain: "example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "http"}}, Enabled: true},
		{ID: "a", Domain: "a.example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "http"}}, Enabled: true},
		{ID: "a90", Domain: "a.example.com", Listens: []ProxyListen{{Port: 19090, Protocol: "http"}}, Enabled: true},
		{ID: "a443", Domain: "a.example.com", Listens: []ProxyListen{{Port: 18443, Protocol: "https"}}, Enabled: true},
		{ID: "d", Domain: "b.example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "http"}}, Enabled: false}, // 停用不参与
	}
	find := func(host string, port int, proto string) string {
		if r := findProxyRule(host, port, proto, rules); r != nil {
			return r.ID
		}
		return ""
	}
	if got := find("example.com", 18080, "http"); got != "e" {
		t.Errorf("example.com:18080 应命中精确规则 e, 得到 %q", got)
	}
	if got := find("a.example.com", 18080, "http"); got != "a" {
		t.Errorf("a.example.com:18080 应命中精确规则 a(优先于通配符), 得到 %q", got)
	}
	if got := find("a.example.com", 19090, "http"); got != "a90" {
		t.Errorf("同域名不同端口应命中 a90, 得到 %q", got)
	}
	if got := find("a.example.com", 18443, "https"); got != "a443" {
		t.Errorf("同域名 https 端口应命中 a443, 得到 %q", got)
	}
	if got := find("a.example.com", 18443, "http"); got != "" {
		t.Errorf("协议不匹配不应命中, 得到 %q", got)
	}
	if got := find("c.example.com", 18080, "http"); got != "w" {
		t.Errorf("c.example.com 应命中通配符 w, 得到 %q", got)
	}
	if got := find("b.example.com", 18080, "http"); got != "w" {
		t.Errorf("b.example.com 停用精确规则后应回落通配符 w, 得到 %q", got)
	}
	if got := find("x.y.example.com", 18080, "http"); got != "" {
		t.Errorf("x.y.example.com 不应匹配, 得到 %q", got)
	}
	if got := find("other.com", 18080, "http"); got != "" {
		t.Errorf("other.com 不应匹配, 得到 %q", got)
	}
	if got := find("a.example.com", 18081, "http"); got != "" {
		t.Errorf("无此端口的规则不应匹配, 得到 %q", got)
	}
}

func TestParseBackend(t *testing.T) {
	cases := []struct {
		in, want string
		bad      bool
	}{
		{"127.0.0.1:8080", "127.0.0.1:8080", false},
		{"http://Host:8080", "host:8080", false},
		{"http://192.168.1.5:9000", "192.168.1.5:9000", false},
		{"https://x:443", "", true},
		{"host", "", true},
		{"host:99999", "", true},
		{"host:0", "", true},
		{"host:80/path", "", true},
		{"http://host:80/", "", true},
		{"", "", true},
		{"[::1]:8080", "[::1]:8080", false},
	}
	for _, c := range cases {
		got, err := parseBackend(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("parseBackend(%q) 应报错, 得到 %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseBackend(%q) 报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseBackend(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateProxyConfig(t *testing.T) {
	cert := ProxyCertMeta{ID: "c1", DNSNames: []string{"example.com", "*.example.com"}}
	expired := ProxyCertMeta{ID: "c2", DNSNames: []string{"example.com"}, Expired: true}
	other := ProxyCertMeta{ID: "c3", DNSNames: []string{"other.com"}}
	base := func() ProxyConfig {
		return ProxyConfig{Rules: []*ProxyRule{
			{ID: "1", Domain: "example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "https"}}, Backend: "127.0.0.1:8080", Cert: "c1", Enabled: true},
		}}
	}
	if err := validateProxyConfig(base(), []ProxyCertMeta{cert}); err != nil {
		t.Errorf("合法配置应通过: %v", err)
	}
	// 入站端口必填
	c := base()
	c.Rules[0].Listens = nil
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "入站端口") {
		t.Errorf("入站端口缺失应报错, 得到 %v", err)
	}
	// 入站端口越界
	c = base()
	c.Rules[0].Listens = []ProxyListen{{Port: 65536, Protocol: "https"}}
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "入站端口") {
		t.Errorf("入站端口越界应报错, 得到 %v", err)
	}
	// 协议非法
	c = base()
	c.Rules[0].Listens[0].Protocol = "ftp"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "协议") {
		t.Errorf("非法协议应报错, 得到 %v", err)
	}
	// 域名+端口重复(归一化后)
	c = base()
	c.Rules = append(c.Rules, &ProxyRule{ID: "2", Domain: "EXAMPLE.COM.", Listens: []ProxyListen{{Port: 18080, Protocol: "https"}}, Backend: "127.0.0.1:8081", Cert: "c1", Enabled: true})
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Errorf("域名+端口重复应报错, 得到 %v", err)
	}
	// 同域名不同端口可以共存
	c = base()
	c.Rules = append(c.Rules, &ProxyRule{ID: "2", Domain: "example.com", Listens: []ProxyListen{{Port: 19090, Protocol: "http"}}, Backend: "127.0.0.1:8081", Enabled: true})
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err != nil {
		t.Errorf("同域名不同端口应通过: %v", err)
	}
	// 同端口不同域名可以共存
	c = base()
	c.Rules = append(c.Rules, &ProxyRule{ID: "2", Domain: "other.example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "https"}}, Backend: "127.0.0.1:8081", Cert: "c1", Enabled: true})
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err != nil {
		t.Errorf("同端口不同域名应通过: %v", err)
	}
	// 同端口协议混用
	c = base()
	c.Rules = append(c.Rules, &ProxyRule{ID: "2", Domain: "other.com", Listens: []ProxyListen{{Port: 18080, Protocol: "http"}}, Backend: "127.0.0.1:8081", Enabled: true})
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "协议不一致") {
		t.Errorf("同端口协议混用应报错, 得到 %v", err)
	}
	// 回环 + 任一入站端口 = 自环
	c = base()
	c.Rules[0].Backend = "127.0.0.1:18080"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "自环") {
		t.Errorf("回环自环应报错, 得到 %v", err)
	}
	// localhost + 入站端口 = 自环
	c = base()
	c.Rules[0].Backend = "localhost:18080"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "自环") {
		t.Errorf("localhost 自环应报错, 得到 %v", err)
	}
	// 回环 + 非入站端口不算自环
	c = base()
	c.Rules[0].Backend = "127.0.0.1:8080"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err != nil {
		t.Errorf("回环+非入站端口应通过: %v", err)
	}
	// 后端主机名等于规则域名 = 自环
	c = base()
	c.Rules[0].Backend = "example.com:8080"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "自环") {
		t.Errorf("后端等于规则域名应报错, 得到 %v", err)
	}
	// HTTPS 规则证书必填(空证书)
	c = base()
	c.Rules[0].Cert = ""
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "必须选择证书") {
		t.Errorf("HTTPS 空证书应报必填, 得到 %v", err)
	}
	// HTTPS 规则无覆盖证书(auto 模式下证书列表为空)
	c = base()
	c.Rules[0].Cert = "auto"
	if err := validateProxyConfig(c, nil); err == nil || !strings.Contains(err.Error(), "没有 SAN") {
		t.Errorf("无覆盖证书应报错, 得到 %v", err)
	}
	// 指定证书 SAN 不匹配也可保存(用户自选任意证书, 如双线两张证书混用)
	c = base()
	c.Rules[0].Cert = "c3"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert, other}); err != nil {
		t.Errorf("SAN 不匹配的指定证书应通过: %v", err)
	}
	// 指定证书已过期
	c = base()
	c.Rules[0].Cert = "c2"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert, expired}); err == nil || !strings.Contains(err.Error(), "过期") {
		t.Errorf("过期证书应报错, 得到 %v", err)
	}
	// 指定证书不存在
	c = base()
	c.Rules[0].Cert = "nope"
	if err := validateProxyConfig(c, []ProxyCertMeta{cert}); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Errorf("不存在的证书应报错, 得到 %v", err)
	}
	// 停用规则的证书问题不卡保存
	c = base()
	c.Rules[0].Enabled = false
	c.Rules[0].Cert = ""
	if err := validateProxyConfig(c, nil); err != nil {
		t.Errorf("停用规则不应卡证书校验: %v", err)
	}
	// HTTP 规则不需要证书
	c = base()
	c.Rules[0].Listens[0].Protocol = "http"
	c.Rules[0].Cert = ""
	if err := validateProxyConfig(c, nil); err != nil {
		t.Errorf("HTTP 规则不应卡证书: %v", err)
	}
	// 后端必填(1.8.3 起重定向已取消, 后端一律必填, 纯 HTTP 规则也不例外)
	c = base()
	c.Rules[0].Listens[0].Protocol = "http"
	c.Rules[0].Cert = ""
	c.Rules[0].Backend = ""
	if err := validateProxyConfig(c, nil); err == nil || !strings.Contains(err.Error(), "后端") {
		t.Errorf("后端为空应报错, 得到 %v", err)
	}
}

// 入站端口硬约束: 只校验 1-65535 本身合法, 不限高低、不给默认、不因 80/443 报错。
func TestProxyPortNoRestriction(t *testing.T) {
	for _, port := range []int{1, 80, 443, 8080, 8443, 65535} {
		c := ProxyConfig{Rules: []*ProxyRule{
			{ID: "1", Domain: "example.com", Listens: []ProxyListen{{Port: port, Protocol: "http"}}, Backend: "backend.local:8080", Enabled: true},
		}}
		if err := validateProxyConfig(c, nil); err != nil {
			t.Errorf("入站端口 %d 应通过(不限高低), 得到 %v", port, err)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		c := ProxyConfig{Rules: []*ProxyRule{
			{ID: "1", Domain: "example.com", Listens: []ProxyListen{{Port: port, Protocol: "http"}}, Backend: "backend.local:8080", Enabled: true},
		}}
		if err := validateProxyConfig(c, nil); err == nil {
			t.Errorf("入站端口 %d 应报错(超出 1-65535), 却通过了", port)
		}
	}
}

func TestCertCoversDomain(t *testing.T) {
	m := ProxyCertMeta{DNSNames: []string{"example.com", "*.example.com"}, IPs: []string{"10.0.0.9"}}
	for host, want := range map[string]bool{
		"example.com": true, "a.example.com": true, "a.b.example.com": false,
		"other.com": false, "10.0.0.9": true, "10.0.0.10": false,
	} {
		if got := certCoversDomain(m, host); got != want {
			t.Errorf("certCoversDomain(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestParseProxyCertPairRoundTrip(t *testing.T) {
	dir := t.TempDir()
	crtPEM, keyPEM := genTestCert(t, []string{"example.com", "*.example.com"}, []net.IP{net.ParseIP("10.0.0.9")}, time.Now().Add(24*time.Hour))
	crtPath := filepath.Join(dir, "t.crt")
	keyPath := filepath.Join(dir, "t.key")
	if err := os.WriteFile(crtPath, crtPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	meta, entry, err := parseProxyCertPair(crtPath, keyPath, "upload:t", "t", "upload", dir)
	if err != nil {
		t.Fatalf("成对证书应解析成功: %v", err)
	}
	if entry == nil || entry.leaf == nil {
		t.Fatal("entry 不应为空")
	}
	if !certCoversDomain(meta, "a.example.com") || certCoversDomain(meta, "a.b.example.com") {
		t.Errorf("解析出的 SAN 不对: %+v", meta.DNSNames)
	}
	if meta.Expired {
		t.Errorf("未到期证书不应标过期")
	}
	// 密钥不匹配应报错
	_, otherKey := genTestCert(t, []string{"example.com"}, nil, time.Now().Add(24*time.Hour))
	badKeyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badKeyPath, otherKey, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseProxyCertPair(crtPath, badKeyPath, "upload:t", "t", "upload", dir); err == nil {
		t.Errorf("密钥不匹配应报错")
	}
}

func TestSelectCertForName(t *testing.T) {
	mk := func(id string, dns []string, after time.Time) *proxyCertEntry {
		return &proxyCertEntry{meta: ProxyCertMeta{ID: id}, leaf: &x509.Certificate{DNSNames: dns, NotAfter: after}}
	}
	now := time.Now()
	serving := map[string]*proxyCertEntry{
		"wild":  mk("wild", []string{"*.example.com"}, now.Add(48*time.Hour)),
		"exact": mk("exact", []string{"a.example.com"}, now.Add(time.Hour)),
		"other": mk("other", []string{"other.com"}, now.Add(72*time.Hour)),
	}
	if got := selectCertForName("a.example.com", serving); got == nil || got.meta.ID != "exact" {
		t.Errorf("精确 SAN 应优先于通配符, 得到 %v", got)
	}
	if got := selectCertForName("b.example.com", serving); got == nil || got.meta.ID != "wild" {
		t.Errorf("b.example.com 应选中通配符, 得到 %v", got)
	}
	if got := selectCertForName("nope.com", serving); got != nil {
		t.Errorf("无覆盖应返回空, 得到 %v", got)
	}
}

// httptest 级别: HTTP 反代透传 + 转发头。
func TestProxyPassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]string{
			"path": r.URL.Path, "xff": r.Header.Get("X-Forwarded-For"),
			"real": r.Header.Get("X-Real-IP"), "proto": r.Header.Get("X-Forwarded-Proto"),
			"host": r.Host,
		}
		b, _ := json.Marshal(out)
		w.Write(b)
	}))
	defer backend.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	rule := ProxyRule{ID: "1", Domain: "app.example.com", Backend: "127.0.0.1:" + port, Enabled: true}
	rp := makeProxyForRule(rule, false)
	req := httptest.NewRequest("GET", "http://app.example.com/foo?x=1", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("透传应返回 200, 得到 %d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("后端回包解析失败: %v", err)
	}
	if got["path"] != "/foo" {
		t.Errorf("路径应透传 /foo, 得到 %q", got["path"])
	}
	if got["xff"] != "198.51.100.7, 203.0.113.9" {
		t.Errorf("X-Forwarded-For 应追加, 得到 %q", got["xff"])
	}
	if got["real"] != "203.0.113.9" {
		t.Errorf("X-Real-IP 应为客户端 IP, 得到 %q", got["real"])
	}
	if got["proto"] != "http" {
		t.Errorf("X-Forwarded-Proto 应为 http, 得到 %q", got["proto"])
	}
}

// Director 不剥 Upgrade/Connection 头(WebSocket 升级的前提)。
func TestProxyDirectorKeepsUpgradeHeaders(t *testing.T) {
	rule := ProxyRule{Backend: "127.0.0.1:8080"}
	var director func(*http.Request)
	rp := makeProxyForRule(rule, false)
	_ = rp
	director = proxyDirectorForRule(rule, false, func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = rule.Backend
	})
	req := httptest.NewRequest("GET", "http://app.example.com/ws", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	director(req)
	if req.Header.Get("Upgrade") != "websocket" || req.Header.Get("Connection") != "Upgrade" {
		t.Errorf("Director 不应剥掉 Upgrade 相关头, 得到 Upgrade=%q Connection=%q",
			req.Header.Get("Upgrade"), req.Header.Get("Connection"))
	}
	if req.Header.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("X-Forwarded-Proto 应为 http, 得到 %q", req.Header.Get("X-Forwarded-Proto"))
	}
}

// 前端入口(按端口): 透传、未匹配 421、直接 IP 421(1.8.3 起无重定向, 一律代理)。
func TestProxyFrontHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))

	proxyMu.Lock()
	oldCfg, oldServing := proxyCfg, proxyServing
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{
		{ID: "1", Domain: "app.example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "http"}}, Backend: "127.0.0.1:" + port, Enabled: true},
		{ID: "3", Domain: "*.example.com", Listens: []ProxyListen{{Port: 18080, Protocol: "http"}}, Backend: "127.0.0.1:" + port, Enabled: true},
		{ID: "4", Domain: "app.example.com", Listens: []ProxyListen{{Port: 19090, Protocol: "http"}}, Backend: "127.0.0.1:" + port, Enabled: true},
	}}
	proxyMu.Unlock()
	defer func() {
		proxyMu.Lock()
		proxyCfg, proxyServing = oldCfg, oldServing
		proxyMu.Unlock()
	}()

	h := proxyFrontHandler(18080, false)
	do := func(host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://"+host+"/x?y=1", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("app.example.com"); rec.Code != 200 || rec.Body.String() != "backend-ok" {
		t.Errorf("匹配规则应透传, 得到 %d %q", rec.Code, rec.Body.String())
	}
	if rec := do("c.example.com"); rec.Code != 200 {
		t.Errorf("通配符规则应透传, 得到 %d", rec.Code)
	}
	if rec := do("unknown.other.com"); rec.Code != 421 {
		t.Errorf("未匹配域名应 421, 得到 %d", rec.Code)
	}
	if rec := do("192.0.2.55"); rec.Code != 421 {
		t.Errorf("直接 IP 访问应 421, 得到 %d", rec.Code)
	}
	// 同域名在别的端口走别的监听: 18080 的处理器不应受理 19090 的规则语义差异——
	// 这里验证端口隔离: 19090 端口的处理器对 app.example.com 同样透传(规则 4),
	// 而 18080 的处理器对 19090 端口无规则概念(端口是监听属性, 不体现在 Host 里)。
	h2 := proxyFrontHandler(19090, false)
	req := httptest.NewRequest("GET", "http://app.example.com/x", nil)
	rec := httptest.NewRecorder()
	h2.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("19090 端口处理器应透传 app.example.com, 得到 %d", rec.Code)
	}
}

// SNI 回调(按端口): 匹配规则取证书, 无匹配握手失败(返回 error), 别端口的规则不串。
func TestProxyGetCertificate(t *testing.T) {
	crtPEM, keyPEM := genTestCert(t, []string{"example.com", "*.example.com"}, nil, time.Now().Add(24*time.Hour))
	pair, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	proxyMu.Lock()
	oldCfg, oldServing := proxyCfg, proxyServing
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{
		{ID: "1", Domain: "*.example.com", Listens: []ProxyListen{{Port: 18443, Protocol: "https"}}, Backend: "127.0.0.1:8080", Cert: "auto", Enabled: true},
	}}
	proxyServing = map[string]*proxyCertEntry{
		"c1": {meta: ProxyCertMeta{ID: "c1"}, cert: pair, leaf: leaf},
	}
	proxyMu.Unlock()
	defer func() {
		proxyMu.Lock()
		proxyCfg, proxyServing = oldCfg, oldServing
		proxyMu.Unlock()
	}()
	getCert := proxyGetCertificateForPort(18443)
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err != nil {
		t.Errorf("通配符规则 + 通配符 SAN 应取到证书: %v", err)
	}
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Errorf("通配符规则不应匹配 apex, 应握手失败")
	}
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: "other.com"}); err == nil {
		t.Errorf("无匹配 SNI 应握手失败")
	}
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Errorf("空 SNI 应握手失败")
	}
	// 别端口的回调不应命中本端口的规则
	getOther := proxyGetCertificateForPort(19443)
	if _, err := getOther(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err == nil {
		t.Errorf("别端口回调不应命中 18443 的规则")
	}
}

// 旧格式兼容: 无入站端口的规则加载时忽略并写回清理后的文件。
func TestLoadProxyDropsOldRules(t *testing.T) {
	dir := t.TempDir()
	oldFile := proxyFile
	oldCfg := proxyConfigSnapshot()
	proxyFile = filepath.Join(dir, "proxy.json")
	t.Cleanup(func() {
		proxyFile = oldFile
		proxyMu.Lock()
		proxyCfg = oldCfg
		proxyMu.Unlock()
	})
	writeTestFile(t, proxyFile, `{"enabled":true,"httpPort":80,"httpsPort":443,"rules":[
		{"id":"old","domain":"old.example.com","backend":"127.0.0.1:8080","http":true,"https":true,"forceHttps":false,"cert":"auto","enabled":true},
		{"id":"new","domain":"new.example.com","port":18080,"protocol":"http","backend":"127.0.0.1:8080","enabled":true}
	]}`)
	loadProxy()
	proxyMu.Lock()
	n := len(proxyCfg.Rules)
	dom := ""
	if n == 1 {
		dom = proxyCfg.Rules[0].Domain
	}
	proxyMu.Unlock()
	if n != 1 || dom != "new.example.com" {
		t.Fatalf("旧规则应被忽略、新规则保留, 得到 %d 条: %q", n, dom)
	}
	b, _ := os.ReadFile(proxyFile)
	if strings.Contains(string(b), "old.example.com") {
		t.Errorf("清理后的文件不应再含旧规则")
	}
	if !strings.Contains(string(b), "new.example.com") {
		t.Errorf("清理后的文件应保留新规则")
	}
}

// 回归测试(1.8.3 教训): HTTPS 反代监听必须协商出 h2, 不能静默回落 h1.1。
// 构造与生产一致的服务器(ServeTLS + TLSConfig + GetCertificate), 用 ALPN
// [h2, http/1.1] 拨过去, 断言协商出 h2, 且整条 GET 确实走 HTTP/2 到达反代处理器。
func TestProxyHTTPSServerNegotiatesH2(t *testing.T) {
	crtPEM, keyPEM := genTestCert(t, []string{"example.com"}, nil, time.Now().Add(time.Hour))
	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := newProxyHTTPSServer(0)
	srv.TLSConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	addr := ln.Addr().String()

	// 先裸拨验证 ALPN。
	raw, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         "example.com",
	})
	if err != nil {
		t.Fatalf("TLS 拨号失败: %v", err)
	}
	if got := raw.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Errorf("ALPN 应协商出 h2, 得到 %q", got)
	}
	raw.Close()

	// 再走整条 HTTP 客户端, 断言响应协议是 HTTP/2(且请求到达了反代处理器:
	// 直连 IP 无规则, 前端入口应回 421)。
	tr := &http.Transport{
		// 自定义 DialTLSContext 默认会关掉 h2, 必须显式 ForceAttemptHTTP2 才能走 h2。
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{}
			return tls.DialWithDialer(d, network, addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         "example.com",
			})
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("h2 GET 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("响应应为 HTTP/2, 得到 %s", resp.Proto)
	}
	if resp.StatusCode != 421 {
		t.Errorf("无规则应 421, 得到 %d", resp.StatusCode)
	}
}
