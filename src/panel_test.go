package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// panelTestSetup: 临时数据目录 + 一张 example.com 自签证书(上传目录)。
func panelTestSetup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldDataDir, oldPanelPort := dataDir, panelPort
	mu.Lock()
	oldSettings := settings
	mu.Unlock()
	dataDir = dir
	panelPort = 15987
	certDir := filepath.Join(dir, "certs")
	os.MkdirAll(certDir, 0755)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	os.WriteFile(filepath.Join(certDir, "example.crt"), crtPEM, 0644)
	os.WriteFile(filepath.Join(certDir, "example.key"), keyPEM, 0600)
	mu.Lock()
	settings = defaultSettings()
	mu.Unlock()
	proxyMu.Lock()
	proxyCfg = defaultProxyConfig()
	proxyMu.Unlock()
	t.Cleanup(func() {
		dataDir, panelPort = oldDataDir, oldPanelPort
		mu.Lock()
		settings = oldSettings
		mu.Unlock()
		if panelSrv != nil {
			panelSrv.Close()
			panelSrv = nil
		}
	})
	return certDir
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func TestValidatePanelSettings(t *testing.T) {
	panelTestSetup(t)
	// 阈值归一
	s := defaultSettings()
	s.PanelBanThreshold = 0
	if err := validatePanelSettings(&s); err != nil || s.PanelBanThreshold != 5 {
		t.Errorf("阈值 0 应归一为 5, 得到 %d err=%v", s.PanelBanThreshold, err)
	}
	s.PanelBanThreshold = 200
	validatePanelSettings(&s)
	if s.PanelBanThreshold != 100 {
		t.Errorf("阈值 200 应钳制为 100, 得到 %d", s.PanelBanThreshold)
	}
	// 模式空 = off
	s = defaultSettings()
	s.PanelSSLMode = ""
	if err := validatePanelSettings(&s); err != nil || s.PanelSSLMode != "off" {
		t.Errorf("空模式应归一为 off, 得到 %q err=%v", s.PanelSSLMode, err)
	}
	// port 模式: 端口非法 / 未选证书 / 证书不存在
	s = defaultSettings()
	s.PanelSSLMode = "port"
	s.PanelSSLPort = 0
	if err := validatePanelSettings(&s); err == nil {
		t.Error("port 模式端口 0 应报错")
	}
	s.PanelSSLPort = 59188
	if err := validatePanelSettings(&s); err == nil {
		t.Error("port 模式未选证书应报错")
	}
	s.PanelSSLCert = "upload:missing"
	if err := validatePanelSettings(&s); err == nil {
		t.Error("port 模式证书不存在应报错")
	}
	s.PanelSSLCert = "upload:example"
	if err := validatePanelSettings(&s); err != nil {
		t.Errorf("port 模式合法证书应通过, 得到 %v", err)
	}
	// domain 模式: 域名必填 / 被反代占用 / 证书不覆盖 / 合法
	s = defaultSettings()
	s.PanelSSLMode = "domain"
	if err := validatePanelSettings(&s); err == nil {
		t.Error("domain 模式无域名应报错")
	}
	s.PanelDomain = "panel.example.com"
	proxyMu.Lock()
	proxyCfg.Rules = []*ProxyRule{{Domain: "panel.example.com", Enabled: true}}
	proxyMu.Unlock()
	if err := validatePanelSettings(&s); err == nil {
		t.Error("domain 模式域名被反代占用应报错")
	}
	proxyMu.Lock()
	proxyCfg.Rules = nil
	proxyMu.Unlock()
	s.PanelSSLCert = "upload:example" // 只覆盖 example.com, 不覆盖 panel.example.com
	if err := validatePanelSettings(&s); err == nil {
		t.Error("domain 模式证书不覆盖域名应报错")
	}
	s.PanelSSLCert = ""
	if err := validatePanelSettings(&s); err != nil {
		t.Errorf("domain 模式自动匹配(无证书)应通过, 得到 %v", err)
	}
	// 未知模式
	s.PanelSSLMode = "weird"
	if err := validatePanelSettings(&s); err == nil {
		t.Error("未知模式应报错")
	}
}

func TestPanelServerRebuild(t *testing.T) {
	panelTestSetup(t)
	rootMux = http.NewServeMux()
	// off 模式起 HTTP
	mu.Lock()
	settings.PanelSSLMode = "off"
	mu.Unlock()
	startPanelServer()
	mode, port := panelRunning()
	if mode != "off" || port != 15987 {
		t.Fatalf("off 模式应跑在 15987, 得到 %s:%d", mode, port)
	}
	// 切 port 模式(自签证书)重建
	p := freePort(t)
	mu.Lock()
	settings.PanelSSLMode = "port"
	settings.PanelSSLPort = p
	settings.PanelSSLCert = "upload:example"
	mu.Unlock()
	rebuildPanelServer()
	mode, port = panelRunning()
	if mode != "port" || port != p {
		t.Fatalf("port 模式应跑在 %d, 得到 %s:%d", p, mode, port)
	}
	// 真实 TLS 握手: 证书应为 example.com 自签(监听异步起, 重试等待)
	var conn *tls.Conn
	var err error
	for i := 0; i < 30; i++ {
		conn, err = tls.Dial("tcp", "127.0.0.1:"+itoa(p), &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TLS 握手失败: %v", err)
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].DNSNames[0] != "example.com" {
		t.Error("面板 TLS 证书应为 example.com")
	}
}
