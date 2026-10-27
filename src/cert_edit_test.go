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

	"golang.org/x/crypto/ocsp"
)

// writeTestAcmeMeta: 往 certs/<域名>/meta.json 写 meta。
func writeTestAcmeMeta(t *testing.T, root, domain string, m acmeCertMeta) {
	t.Helper()
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(root, "certs", domain, "meta.json"), b, 0644); err != nil {
		t.Fatal(err)
	}
}

func readTestAcmeMeta(t *testing.T, root, domain string) acmeCertMeta {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "certs", domain, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m acmeCertMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// makeAcmeCertExpiry: 带指定到期时间的 ACME 证书（makeAcmeCert 的到期可调版）。
func makeAcmeCertExpiry(t *testing.T, root, domain string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
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

// makeUploadCertPair: 写一对上传证书，返回 crt/key 文本（供替换测试用）。
func makeUploadCertPair(t *testing.T, root, name string, notAfter time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name + ".example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crtPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	d := filepath.Join(root, "certs")
	os.MkdirAll(d, 0755)
	os.WriteFile(filepath.Join(d, name+".crt"), []byte(crtPEM), 0644)
	os.WriteFile(filepath.Join(d, name+".key"), []byte(keyPEM), 0600)
	return crtPEM, keyPEM
}

// callCertItem: 直接调证书单项 handler（PUT 编辑 / DELETE），返回状态码与 JSON。
func callCertItem(t *testing.T, method, id, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "/api/proxy/certs/"+id, strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleProxyCertItem(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func callCertRefresh(t *testing.T, id string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/proxy/certs/refresh", strings.NewReader(`{"id":"`+id+`"}`))
	rec := httptest.NewRecorder()
	handleProxyCertRefresh(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func boolPtr(b bool) *bool { return &b }

func TestAcmeMetaForOrderPreservesAutoRenew(t *testing.T) {
	root := certDeleteSetup(t)
	// 无 meta：新证书默认开（nil）。
	if m := acmeMetaForOrder("nometa.example.com", []string{"nometa.example.com"}, "dns-01"); m.AutoRenew != nil {
		t.Errorf("无旧 meta 时 AutoRenew 应为 nil（默认开），得到 %v", *m.AutoRenew)
	}
	// 旧 meta 关掉的：续期写 meta 不能悄悄开回去。
	makeAcmeCert(t, root, "off.example.com")
	writeTestAcmeMeta(t, root, "off.example.com", acmeCertMeta{Domains: []string{"off.example.com"}, Method: "dns-01", AutoRenew: boolPtr(false)})
	if m := acmeMetaForOrder("off.example.com", []string{"off.example.com"}, "dns-01"); m.AutoRenew == nil || *m.AutoRenew {
		t.Error("旧 meta 关掉的，续期 meta 应继续关")
	}
	if acmeAutoRenewEnabled("off.example.com") {
		t.Error("acmeAutoRenewEnabled 应读到关（关掉的证书应返回 false）")
	}
	if !acmeAutoRenewEnabled("nometa.example.com") {
		t.Error("无 meta 应视为开")
	}
}

func TestCertEditAutoRenewToggleAndRenewalSkip(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCertExpiry(t, root, "edit.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "edit.example.com", acmeCertMeta{Domains: []string{"edit.example.com"}, Method: "dns-01"})
	// 关掉自动续签。
	code, _ := callCertItem(t, "PUT", "acme:edit.example.com", `{"autoRenew":false}`)
	if code != 200 {
		t.Fatalf("编辑开关应 200，得到 %d", code)
	}
	if m := readTestAcmeMeta(t, root, "edit.example.com"); m.AutoRenew == nil || *m.AutoRenew {
		t.Error("meta 里的 autoRenew 应为 false")
	}
	// 续期检查应跳过关掉的证书。
	oldFn := acmeOrderFunc
	var calls []string
	acmeOrderFunc = func(domains []string, method, tok string) error {
		calls = append(calls, domains[0]+"/"+method)
		return nil
	}
	t.Cleanup(func() { acmeOrderFunc = oldFn })
	acmeRenewalCheck()
	if len(calls) != 0 {
		t.Errorf("关掉自动续签的证书不应被续期，实际调用 %v", calls)
	}
	// 再打开 + 一张已过期无 meta 证书 + 一张 60 天后到期证书。
	code, _ = callCertItem(t, "PUT", "acme:edit.example.com", `{"autoRenew":true}`)
	if code != 200 {
		t.Fatalf("重新打开应 200，得到 %d", code)
	}
	makeAcmeCertExpiry(t, root, "expired.example.com", time.Now().Add(-time.Hour))
	makeAcmeCertExpiry(t, root, "future.example.com", time.Now().Add(60*24*time.Hour))
	acmeRenewalCheck()
	if len(calls) != 2 {
		t.Fatalf("应续期 2 张（开着的 24h 证 + 已过期证），实际 %v", calls)
	}
	for _, want := range []string{"edit.example.com/dns-01", "expired.example.com/http-01"} {
		found := false
		for _, c := range calls {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("应续期 %s，实际 %v", want, calls)
		}
	}
}

func TestCertEditTokenGlobal(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCert(t, root, "tok.example.com")
	writeTestAcmeMeta(t, root, "tok.example.com", acmeCertMeta{Domains: []string{"tok.example.com"}, Method: "dns-01"})
	// 填 Token：更新全局文件，响应里绝不明文回显。
	code, out := callCertItem(t, "PUT", "acme:tok.example.com", `{"cfToken":"tok-xyz-123"}`)
	if code != 200 {
		t.Fatalf("编辑 Token 应 200，得到 %d", code)
	}
	if cfLoadToken() != "tok-xyz-123" {
		t.Errorf("全局 Token 应更新，实际 %q", cfLoadToken())
	}
	if strings.Contains(jsonString(out), "tok-xyz-123") {
		t.Error("编辑响应里不应明文回显 Token")
	}
	// 空与星号占位 = 不改。
	callCertItem(t, "PUT", "acme:tok.example.com", `{"cfToken":""}`)
	if cfLoadToken() != "tok-xyz-123" {
		t.Error("空 Token 不应改动全局 Token")
	}
	callCertItem(t, "PUT", "acme:tok.example.com", `{"cfToken":"********"}`)
	if cfLoadToken() != "tok-xyz-123" {
		t.Error("星号占位不应改动全局 Token")
	}
	// 上传证书编辑不碰 Token（UI 根本不提供该字段）。
	makeUploadCertPair(t, root, "up-tok", time.Now().Add(24*time.Hour))
	callCertItem(t, "PUT", "upload:up-tok", `{"cfToken":"tok-should-not-apply"}`)
	if cfLoadToken() != "tok-xyz-123" {
		t.Error("上传证书编辑不应改动全局 Token")
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestCertEditUploadReplace(t *testing.T) {
	root := certDeleteSetup(t)
	oldCrt, oldKey := makeUploadCertPair(t, root, "up1", time.Now().Add(24*time.Hour))
	newCrt, newKey := makeUploadCertPair(t, root, "up2-tmp", time.Now().Add(72*time.Hour))
	// 注意：up2-tmp 的文件也要清掉，避免干扰列表（只用它的文本做替换内容）。
	os.Remove(filepath.Join(root, "certs", "up2-tmp.crt"))
	os.Remove(filepath.Join(root, "certs", "up2-tmp.key"))
	body, _ := json.Marshal(map[string]string{"crt": newCrt, "key": newKey})
	code, _ := callCertItem(t, "PUT", "upload:up1", string(body))
	if code != 200 {
		t.Fatalf("替换应 200，得到 %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(root, "certs", "up1.crt"))
	// 编辑接口会对粘贴内容 TrimSpace（去首尾空白），故按 TrimSpace 后比对。
	if strings.TrimSpace(string(got)) != strings.TrimSpace(newCrt) {
		t.Error("替换后 crt 文件应为新内容")
	}
	// 不成对：400，且原文件纹丝不动。
	before, _ := os.ReadFile(filepath.Join(root, "certs", "up1.crt"))
	body, _ = json.Marshal(map[string]string{"crt": oldCrt, "key": newKey})
	code, _ = callCertItem(t, "PUT", "upload:up1", string(body))
	if code != 400 {
		t.Fatalf("不成对替换应 400，得到 %d", code)
	}
	after, _ := os.ReadFile(filepath.Join(root, "certs", "up1.crt"))
	if string(before) != string(after) {
		t.Error("校验失败时原证书文件不应被动")
	}
	if _, err := os.Stat(filepath.Join(root, "certs", "up1.crt.tmp")); err == nil {
		t.Error("校验失败不应残留临时文件")
	}
	// 只填一项：400。
	_ = oldKey
	body, _ = json.Marshal(map[string]string{"crt": newCrt})
	code, _ = callCertItem(t, "PUT", "upload:up1", string(body))
	if code != 400 {
		t.Fatalf("只填证书应 400，得到 %d", code)
	}
}

func TestCertEditAcmeRejectReplace(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCert(t, root, "rej.example.com")
	code, _ := callCertItem(t, "PUT", "acme:rej.example.com", `{"crt":"x","key":"y"}`)
	if code != 400 {
		t.Fatalf("ACME 证书替换内容应 400，得到 %d", code)
	}
}

// makeOCSPAcmeCertDir: 带 OCSP 地址的 ACME 证书目录（leaf + issuer 全链 + leaf 私钥）。
func makeOCSPAcmeCertDir(t *testing.T, root, domain string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ocspURL string, notAfter time.Time) {
	t.Helper()
	leaf, leafKey := ocspTestLeaf(t, ca, caKey, 41, ocspURL, "", notAfter)
	d := filepath.Join(root, "certs", domain)
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatal(err)
	}
	chain := append(pemEncodeCert(leaf), pemEncodeCert(ca)...)
	if err := os.WriteFile(filepath.Join(d, "fullchain.pem"), chain, 0644); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	if err := os.WriteFile(filepath.Join(d, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCertRefreshFlow(t *testing.T) {
	root := certDeleteSetup(t)
	ca, caKey := ocspTestCA(t)
	// 吊销：刷新后状态 revoked + 缓存落盘。
	revSrv := ocspTestResponder(t, ca, caKey, ocsp.Revoked)
	defer revSrv.Close()
	makeOCSPAcmeCertDir(t, root, "rev.example.com", ca, caKey, revSrv.URL, time.Now().Add(24*time.Hour))
	code, out := callCertRefresh(t, "acme:rev.example.com")
	if code != 200 {
		t.Fatalf("刷新吊销证书应 200，得到 %d", code)
	}
	cert, _ := out["cert"].(map[string]any)
	if cert["status"] != "revoked" {
		t.Errorf("吊销证书刷新后状态应为 revoked，得到 %v", cert["status"])
	}
	if _, err := os.Stat(filepath.Join(root, "certs", "rev.example.com", "ocsp.json")); err != nil {
		t.Error("吊销结果应写 ocsp.json 缓存")
	}
	// 有效：状态 valid。
	goodSrv := ocspTestResponder(t, ca, caKey, ocsp.Good)
	defer goodSrv.Close()
	makeOCSPAcmeCertDir(t, root, "good.example.com", ca, caKey, goodSrv.URL, time.Now().Add(24*time.Hour))
	code, out = callCertRefresh(t, "acme:good.example.com")
	if code != 200 || out["cert"].(map[string]any)["status"] != "valid" {
		t.Errorf("有效证书刷新后状态应为 valid，得到 %d/%v", code, out)
	}
	// 响应方不可达：200 + unknown + 吊销未确认，证书仍在且不标吊销。
	deadSrv := ocspTestResponder(t, ca, caKey, ocsp.Good)
	deadURL := deadSrv.URL
	deadSrv.Close()
	makeOCSPAcmeCertDir(t, root, "dead.example.com", ca, caKey, deadURL, time.Now().Add(24*time.Hour))
	code, out = callCertRefresh(t, "acme:dead.example.com")
	if code != 200 {
		t.Fatalf("OCSP 不可达时刷新本身仍应 200，得到 %d", code)
	}
	if out["ocsp"] != "unknown" || !strings.Contains(out["note"].(string), "吊销未确认") {
		t.Errorf("OCSP 不可达应为 unknown + 吊销未确认，得到 %v", out)
	}
	if out["cert"].(map[string]any)["status"] != "valid" {
		t.Errorf("OCSP 查不到时不应标吊销，状态应为 valid，得到 %v", out["cert"])
	}
	if _, err := os.Stat(filepath.Join(root, "certs", "dead.example.com", "ocsp.json")); err == nil {
		t.Error("unknown 不应写缓存")
	}
	// 已过期：OCSP 再好也先按过期标（过期优先于吊销缓存）。
	makeOCSPAcmeCertDir(t, root, "exp.example.com", ca, caKey, goodSrv.URL, time.Now().Add(-time.Hour))
	code, out = callCertRefresh(t, "acme:exp.example.com")
	if code != 200 || out["cert"].(map[string]any)["status"] != "expired" {
		t.Errorf("已过期证书刷新后状态应为 expired，得到 %d/%v", code, out)
	}
}

func TestValidateSelfPanelRule(t *testing.T) {
	metas := []ProxyCertMeta{
		{ID: "acme:panel.example.com", Name: "panel.example.com", Source: "acme", DNSNames: []string{"panel.example.com"}, NotAfter: time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04")},
	}
	// 面板自身反代规则：443 HTTPS + 已有证书 + 上游 127.0.0.1:面板端口，应通过。
	cfg := ProxyConfig{Rules: []*ProxyRule{
		{ID: "r1", Domain: "panel.example.com", Listens: []ProxyListen{{Port: 443, Protocol: "https"}}, Cert: "acme:panel.example.com", Backend: "127.0.0.1:59188", Enabled: true},
	}}
	if err := validateProxyConfig(cfg, metas); err != nil {
		t.Errorf("面板自身反代规则应通过校验，得到 %v", err)
	}
	// 上游端口撞入站端口 = 自环，应拦住。
	cfg.Rules[0].Backend = "127.0.0.1:443"
	if err := validateProxyConfig(cfg, metas); err == nil {
		t.Error("上游撞入站端口应判自环")
	}
}
