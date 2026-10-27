package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// certDeleteSetup: panelTestSetup + 本测试专用的 proxyFile/settingFile 与 proxyCfg 恢复。
func certDeleteSetup(t *testing.T) string {
	t.Helper()
	panelTestSetup(t)
	root := dataDir
	oldProxy, oldSetting := proxyFile, settingFile
	proxyFile = filepath.Join(root, "proxy.json")
	settingFile = filepath.Join(root, "settings.json")
	proxyMu.Lock()
	oldCfg := proxyCfg
	proxyMu.Unlock()
	t.Cleanup(func() {
		proxyFile, settingFile = oldProxy, oldSetting
		proxyMu.Lock()
		proxyCfg = oldCfg
		proxyMu.Unlock()
	})
	return root
}

// makeAcmeCert: 在 dataDir/certs/<域名>/ 下放一对自签证书。
func makeAcmeCert(t *testing.T, root, domain string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(root, "certs", domain)
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(d, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
}

// waitPanelServer: 等异步重建把监听对象建出来(否则清理时关不到, 会泄漏到下个测试)。
func waitPanelServer(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		panelSrvMu.Lock()
		srv := panelSrv
		panelSrvMu.Unlock()
		if srv != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("面板重建后监听未起")
}

func setPanelForDelete(t *testing.T, mode, cert, domain string) {
	t.Helper()
	mu.Lock()
	settings.PanelSSLMode = mode
	settings.PanelSSLCert = cert
	settings.PanelDomain = domain
	mu.Unlock()
}

func setRuleForDelete(t *testing.T, cert string) {
	t.Helper()
	proxyMu.Lock()
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{
		{ID: "r1", Domain: "example.com", Listens: []ProxyListen{{Port: 443, Protocol: "https"}}, Cert: cert, Backend: "127.0.0.1:8080", Enabled: true},
	}}
	proxyMu.Unlock()
}

func TestDeleteAcmeCertPanelPortFallback(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCert(t, root, "example.com")
	defer acmeUnmarkDeleted("example.com")
	setPanelForDelete(t, "port", "acme:example.com", "")
	setRuleForDelete(t, "acme:example.com")
	fb, n, err := deleteCertByID("acme:example.com")
	if err != nil {
		t.Fatalf("删除应成功, 得到 %v", err)
	}
	if !fb {
		t.Error("端口模式显式引用被删, 面板应回落")
	}
	if n != 1 {
		t.Errorf("应摘掉 1 条规则引用, 得到 %d", n)
	}
	waitPanelServer(t)
	if _, err := os.Stat(filepath.Join(root, "certs", "example.com")); !os.IsNotExist(err) {
		t.Error("证书目录应已删除")
	}
	if !acmeIsDeleted("example.com") {
		t.Error("删除后应标记停续期")
	}
	metas, _ := scanProxyCerts()
	for _, m := range metas {
		if m.ID == "acme:example.com" {
			t.Error("证书表里不应再有已删证书")
		}
	}
	mu.Lock()
	mode, cert := settings.PanelSSLMode, settings.PanelSSLCert
	mu.Unlock()
	if mode != "off" || cert != "" {
		t.Errorf("面板应回 HTTP 且清空证书, 得到 mode=%q cert=%q", mode, cert)
	}
	proxyMu.Lock()
	rc := proxyCfg.Rules[0].Cert
	proxyMu.Unlock()
	if rc != "auto" {
		t.Errorf("规则证书应改回 auto, 得到 %q", rc)
	}
	b, _ := os.ReadFile(filepath.Join(root, "proxy.json"))
	var saved ProxyConfig
	json.Unmarshal(b, &saved)
	if len(saved.Rules) != 1 || saved.Rules[0].Cert != "auto" {
		t.Errorf("proxy.json 落盘也应是 auto, 得到 %+v", saved.Rules)
	}
}

func TestDeleteAcmeCertDomainModeKeepsWhenCovered(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCert(t, root, "example.com")
	defer acmeUnmarkDeleted("example.com")
	// panelTestSetup 已放 upload:example(SAN example.com), 可覆盖域名。
	setPanelForDelete(t, "domain", "acme:example.com", "example.com")
	fb, _, err := deleteCertByID("acme:example.com")
	if err != nil {
		t.Fatalf("删除应成功, 得到 %v", err)
	}
	if fb {
		t.Error("仍有证书覆盖域名时, 面板不应回落")
	}
	mu.Lock()
	mode, cert := settings.PanelSSLMode, settings.PanelSSLCert
	mu.Unlock()
	if mode != "domain" || cert != "" {
		t.Errorf("面板应留在域名模式且证书清空走自动匹配, 得到 mode=%q cert=%q", mode, cert)
	}
}

func TestDeleteAcmeCertDomainModeFallsBackWhenUncovered(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCert(t, root, "only.example.com")
	defer acmeUnmarkDeleted("only.example.com")
	setPanelForDelete(t, "domain", "acme:only.example.com", "only.example.com")
	fb, _, err := deleteCertByID("acme:only.example.com")
	if err != nil {
		t.Fatalf("删除应成功, 得到 %v", err)
	}
	if !fb {
		t.Error("无证书覆盖域名时, 面板应回落")
	}
	waitPanelServer(t)
	mu.Lock()
	mode := settings.PanelSSLMode
	mu.Unlock()
	if mode != "off" {
		t.Errorf("面板应回 HTTP, 得到 mode=%q", mode)
	}
}

func TestDeleteAcmeCertGuardedWrite(t *testing.T) {
	root := certDeleteSetup(t)
	acmeMarkDeleted("gone.example.com")
	defer acmeUnmarkDeleted("gone.example.com")
	if err := writeAcmeCertGuarded("gone.example.com", []byte("x"), []byte("y")); err == nil {
		t.Error("已标记删除时落盘应被拦住")
	}
	if _, err := os.Stat(filepath.Join(root, "certs", "gone.example.com")); !os.IsNotExist(err) {
		t.Error("被拦住的落盘不应建目录")
	}
	acmeUnmarkDeleted("gone.example.com")
	if err := writeAcmeCertGuarded("gone.example.com", []byte("x"), []byte("y")); err != nil {
		t.Errorf("清除标记后落盘应成功, 得到 %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "certs", "gone.example.com", "fullchain.pem")); err != nil {
		t.Error("清除标记后应写出证书文件")
	}
}

func TestDeleteCertInvalidIDs(t *testing.T) {
	certDeleteSetup(t)
	for _, id := range []string{"scan:/x", "acme:", "acme:../evil", "acme:a/b", "upload:", "upload:a/b", "other:x"} {
		if _, _, err := deleteCertByID(id); err == nil {
			t.Errorf("非法 ID %q 应被拒绝", id)
		}
	}
}

func TestDeleteUploadCertDetaches(t *testing.T) {
	certDeleteSetup(t)
	setPanelForDelete(t, "port", "upload:example", "")
	setRuleForDelete(t, "upload:example")
	fb, n, err := deleteCertByID("upload:example")
	if err != nil {
		t.Fatalf("删除应成功, 得到 %v", err)
	}
	if !fb || n != 1 {
		t.Errorf("应回落面板并摘掉规则, 得到 fb=%v n=%d", fb, n)
	}
	waitPanelServer(t)
	mu.Lock()
	mode := settings.PanelSSLMode
	mu.Unlock()
	if mode != "off" {
		t.Errorf("面板应回 HTTP, 得到 mode=%q", mode)
	}
}

func TestDeleteCertHandler(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCert(t, root, "example.com")
	defer acmeUnmarkDeleted("example.com")
	req := httptest.NewRequest("DELETE", "/api/proxy/certs/acme%3Aexample.com", nil)
	rec := httptest.NewRecorder()
	handleProxyCertItem(rec, req)
	if rec.Code != 200 {
		t.Fatalf("handler 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["ok"] != true {
		t.Errorf("handler 应返回 ok, 得到 %v", body)
	}
	if _, err := os.Stat(filepath.Join(root, "certs", "example.com")); !os.IsNotExist(err) {
		t.Error("handler 删除后目录应没了")
	}
	if !strings.Contains(rec.Body.String(), "panelFallback") {
		t.Error("handler 应返回 panelFallback 字段")
	}
}
