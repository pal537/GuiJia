package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveAcmeApply(t *testing.T) {
	cases := []struct {
		name     string
		in       acmeApplyInput
		port80OK bool
		stored   string
		wantDom  []string
		wantMeth string
		wantTok  string
		wantErr  string // 非空 = 期望报错且包含该子串
	}{
		{"空域名", acmeApplyInput{}, true, "", nil, "", "", "请填写域名"},
		{"坏域名", acmeApplyInput{Domains: []string{"not a domain!!"}}, true, "", nil, "", "", "域名无效"},
		{"去重归一", acmeApplyInput{Domains: []string{" Example.COM. ", "example.com", "a.example.com"}}, true, "", []string{"example.com", "a.example.com"}, "http-01", "", ""},
		{"老单字段兼容", acmeApplyInput{Domain: "old.example.com"}, true, "", []string{"old.example.com"}, "http-01", "", ""},
		{"未知方式", acmeApplyInput{Domains: []string{"example.com"}, Method: "tls-alpn"}, true, "", nil, "", "", "未知的验证方式"},
		{"自动80空闲", acmeApplyInput{Domains: []string{"example.com"}}, true, "", []string{"example.com"}, "http-01", "", ""},
		{"自动80被占无Token", acmeApplyInput{Domains: []string{"example.com"}}, false, "", nil, "", "", "自动切换到 DNS-01"},
		{"自动80被占已存Token", acmeApplyInput{Domains: []string{"example.com"}}, false, "stored-tok", []string{"example.com"}, "dns-01", "stored-tok", ""},
		{"自动80被占显式Token", acmeApplyInput{Domains: []string{"example.com"}, CFToken: "new-tok"}, false, "stored-tok", []string{"example.com"}, "dns-01", "new-tok", ""},
		{"显式HTTP80被占", acmeApplyInput{Domains: []string{"example.com"}, Method: "http-01"}, false, "", nil, "", "", "80 端口被占用"},
		{"显式HTTP80空闲", acmeApplyInput{Domains: []string{"example.com"}, Method: "http-01"}, true, "", []string{"example.com"}, "http-01", "", ""},
		{"显式DNS无Token", acmeApplyInput{Domains: []string{"example.com"}, Method: "dns-01"}, true, "", nil, "", "", "需要 Cloudflare API Token"},
		{"显式DNS星号用已存", acmeApplyInput{Domains: []string{"example.com"}, Method: "dns-01", CFToken: "********"}, true, "stored-tok", []string{"example.com"}, "dns-01", "stored-tok", ""},
		{"通配符保留", acmeApplyInput{Domains: []string{"*.example.com", "example.com"}, Method: "dns-01", CFToken: "tok"}, true, "", []string{"*.example.com", "example.com"}, "dns-01", "tok", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			domains, method, tok, err := resolveAcmeApply(c.in, c.port80OK, c.stored)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("期望报错含 %q，实际 %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应报错: %v", err)
			}
			if strings.Join(domains, ",") != strings.Join(c.wantDom, ",") {
				t.Errorf("domains = %v, 期望 %v", domains, c.wantDom)
			}
			if method != c.wantMeth {
				t.Errorf("method = %q, 期望 %q", method, c.wantMeth)
			}
			if tok != c.wantTok {
				t.Errorf("token = %q, 期望 %q", tok, c.wantTok)
			}
		})
	}
	// 域名过多。
	many := make([]string, 101)
	for i := range many {
		many[i] = "d" + itoa(i) + ".example.com"
	}
	if _, _, _, err := resolveAcmeApply(acmeApplyInput{Domains: many}, true, ""); err == nil {
		t.Error("101 个域名应报错")
	}
}

func TestAcmeMetaRoundTripAndRenewalPlan(t *testing.T) {
	dir := t.TempDir()
	old := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = old })
	// 写 meta → 读回 → 续期计划原样沿用。
	if err := writeAcmeMetaGuarded("a.example.com", acmeCertMeta{Domains: []string{"a.example.com", "b.example.com"}, Method: "dns-01"}); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	m, ok := readAcmeMeta("a.example.com")
	if !ok || len(m.Domains) != 2 || m.Method != "dns-01" {
		t.Fatalf("read meta = %+v, %v", m, ok)
	}
	domains, method := acmeRenewalPlan("a.example.com")
	if strings.Join(domains, ",") != "a.example.com,b.example.com" || method != "dns-01" {
		t.Errorf("renewal plan = %v %q", domains, method)
	}
	// 无 meta 的老证书：默认单域名 http-01。
	domains, method = acmeRenewalPlan("old.example.com")
	if strings.Join(domains, ",") != "old.example.com" || method != "http-01" {
		t.Errorf("无 meta 默认 = %v %q", domains, method)
	}
	// meta 里写了非法 method：回落 http-01。
	os.MkdirAll(filepath.Join(dir, "certs", "bad.example.com"), 0755)
	os.WriteFile(filepath.Join(dir, "certs", "bad.example.com", "meta.json"), []byte(`{"domains":["bad.example.com"],"method":"bogus"}`), 0644)
	_, method = acmeRenewalPlan("bad.example.com")
	if method != "http-01" {
		t.Errorf("非法 method 应回落 http-01，实际 %q", method)
	}
	// 删除标记期间写 meta 应被拦住。
	acmeMarkDeleted("gone.example.com")
	defer acmeUnmarkDeleted("gone.example.com")
	if err := writeAcmeMetaGuarded("gone.example.com", acmeCertMeta{Domains: []string{"gone.example.com"}, Method: "http-01"}); err == nil {
		t.Error("已标记删除时写 meta 应被拒绝")
	}
}

func TestCertListSourcesOnlyUploadAndAcme(t *testing.T) {
	dir := t.TempDir()
	old := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = old })
	// 一张上传证书 + 一张 ACME 证书。
	certPEM, keyPEM := makeSelfSignedPEM(t, "up.example.com", time.Now().Add(90*24*time.Hour))
	os.MkdirAll(filepath.Join(dir, "certs"), 0755)
	os.WriteFile(filepath.Join(dir, "certs", "myup.crt"), certPEM, 0644)
	os.WriteFile(filepath.Join(dir, "certs", "myup.key"), keyPEM, 0600)
	acmePEM, acmeKey := makeSelfSignedPEM(t, "ac.example.com", time.Now().Add(90*24*time.Hour))
	if err := writeAcmeCert("ac.example.com", acmePEM, acmeKey); err != nil {
		t.Fatalf("writeAcmeCert: %v", err)
	}
	metas, _ := scanProxyCerts()
	if len(metas) != 2 {
		t.Fatalf("应扫到 2 张证书，实际 %d", len(metas))
	}
	for _, m := range metas {
		if m.Source != "upload" && m.Source != "acme" {
			t.Errorf("证书来源只能是 upload/acme，实际 %q（id %q）", m.Source, m.ID)
		}
		if strings.HasPrefix(m.ID, "scan:") {
			t.Errorf("不应再有 scan: 来源，实际 %q", m.ID)
		}
	}
}
