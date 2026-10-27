package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

// TestSharedPortSNIRouting: 面板内多域名共用一端口成立（不实际 bind）。
// 两条同端口不同域名的规则：findProxyRule 按 Host 各自命中；
// proxyGetCertificateForPort 按 SNI 各自选证书。
func TestSharedPortSNIRouting(t *testing.T) {
	crtA, keyA := genTestCert(t, []string{"a.example.com"}, nil, time.Now().Add(24*time.Hour))
	crtB, keyB := genTestCert(t, []string{"b.example.com"}, nil, time.Now().Add(24*time.Hour))
	pairA, err := tls.X509KeyPair(crtA, keyA)
	if err != nil {
		t.Fatal(err)
	}
	pairB, err := tls.X509KeyPair(crtB, keyB)
	if err != nil {
		t.Fatal(err)
	}
	leafA, err := x509.ParseCertificate(pairA.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leafB, err := x509.ParseCertificate(pairB.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	rules := []*ProxyRule{
		{ID: "ra", Domain: "a.example.com", Listens: []ProxyListen{{Port: 18443, Protocol: "https"}}, Backend: "127.0.0.1:8080", Cert: "auto", Enabled: true},
		{ID: "rb", Domain: "b.example.com", Listens: []ProxyListen{{Port: 18443, Protocol: "https"}}, Backend: "127.0.0.1:8081", Cert: "auto", Enabled: true},
	}
	proxyMu.Lock()
	oldCfg, oldServing := proxyCfg, proxyServing
	proxyCfg = ProxyConfig{Rules: rules}
	proxyServing = map[string]*proxyCertEntry{
		"ca": {meta: ProxyCertMeta{ID: "ca"}, cert: pairA, leaf: leafA},
		"cb": {meta: ProxyCertMeta{ID: "cb"}, cert: pairB, leaf: leafB},
	}
	proxyMu.Unlock()
	defer func() {
		proxyMu.Lock()
		proxyCfg, proxyServing = oldCfg, oldServing
		proxyMu.Unlock()
	}()

	// 路由：按 Host 各自命中不同规则。
	if r := findProxyRule("a.example.com", 18443, "https", rules); r == nil || r.ID != "ra" {
		t.Errorf("a.example.com 应命中规则 ra，得到 %+v", r)
	}
	if r := findProxyRule("b.example.com", 18443, "https", rules); r == nil || r.ID != "rb" {
		t.Errorf("b.example.com 应命中规则 rb，得到 %+v", r)
	}
	if r := findProxyRule("c.example.com", 18443, "https", rules); r != nil {
		t.Errorf("无规则域名不应命中，得到 %+v", r)
	}

	// SNI 选证书：同端口按 SNI 各自选对证书。
	getCert := proxyGetCertificateForPort(18443)
	certA, err := getCert(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil {
		t.Fatalf("a.example.com 应取到证书: %v", err)
	}
	leaf, err := x509.ParseCertificate(certA.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "a.example.com" {
		t.Errorf("a.example.com 应选到 a 的证书，得到 SAN %v", leaf.DNSNames)
	}
	certB, err := getCert(&tls.ClientHelloInfo{ServerName: "b.example.com"})
	if err != nil {
		t.Fatalf("b.example.com 应取到证书: %v", err)
	}
	leaf, err = x509.ParseCertificate(certB.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "b.example.com" {
		t.Errorf("b.example.com 应选到 b 的证书，得到 SAN %v", leaf.DNSNames)
	}
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: "c.example.com"}); err == nil {
		t.Error("无规则域名 SNI 应握手失败")
	}
}
