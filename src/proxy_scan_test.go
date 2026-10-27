package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProxyScanDirs(t *testing.T) {
	dirs := proxyScanDirs()
	want := []string{
		filepath.Join(dataDir, "certs"),
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		if seen[d] {
			t.Fatalf("扫描目录重复: %s", d)
		}
		seen[d] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("扫描目录缺少 %s, 得到 %v", w, dirs)
		}
	}
}

// ACME 证书 fixture: 布局 certs/<域名>/{fullchain.pem, privkey.pem}。
func TestScanAcmeCerts(t *testing.T) {
	root := t.TempDir()
	old := dataDir
	dataDir = root
	t.Cleanup(func() { dataDir = old })
	mk := func(domain string, dns []string, notAfter time.Time) {
		crt, key := genTestCert(t, dns, nil, notAfter)
		d := filepath.Join(root, "certs", domain)
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(d, "fullchain.pem"), string(crt))
		writeTestFile(t, filepath.Join(d, "privkey.pem"), string(key))
	}
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)
	mk("a.example.com", []string{"a.example.com"}, future)
	mk("b.example.com", []string{"*.example.com", "b.example.com"}, future)
	mk("old.example.com", []string{"old.example.com"}, past)
	// 残缺目录: 只有 fullchain 无 key, 应跳过
	d := filepath.Join(root, "certs", "broken.example.com")
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatal(err)
	}
	crtB, _ := genTestCert(t, []string{"broken.example.com"}, nil, future)
	writeTestFile(t, filepath.Join(d, "fullchain.pem"), string(crtB))

	metas := []ProxyCertMeta{}
	serving := map[string]*proxyCertEntry{}
	seen := map[string]bool{}
	scanAcmeCerts(&metas, serving, seen)
	if len(metas) != 3 {
		t.Fatalf("应扫到 3 张证书, 得到 %d: %+v", len(metas), metas)
	}
	byName := map[string]ProxyCertMeta{}
	for _, m := range metas {
		byName[m.Name] = m
		if m.Source != "acme" {
			t.Errorf("证书 %s 来源应为 acme, 得到 %q", m.Name, m.Source)
		}
		if m.ID != "acme:"+m.Name {
			t.Errorf("证书 %s ID 应为 acme:<域名>, 得到 %q", m.Name, m.ID)
		}
	}
	for _, name := range []string{"a.example.com", "b.example.com", "old.example.com"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("缺少证书 %s", name)
		}
	}
	if !byName["old.example.com"].Expired {
		t.Errorf("过期证书应标 Expired")
	}
	if len(serving) != 2 {
		t.Errorf("serving 应只有 2 张未过期证书, 得到 %d", len(serving))
	}
}

// 1.8.1 单端口形状(port/protocol)应转成 listens; 新形状原样保留。
func TestProxyRuleLegacyUnmarshal(t *testing.T) {
	var r ProxyRule
	if err := json.Unmarshal([]byte(`{"id":"x","domain":"a.example.com","port":18080,"protocol":"https","backend":"127.0.0.1:8080","cert":"auto","enabled":true}`), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Listens) != 1 || r.Listens[0].Port != 18080 || r.Listens[0].Protocol != "https" {
		t.Fatalf("旧形状应转成 listens, 得到 %+v", r.Listens)
	}
	var r2 ProxyRule
	if err := json.Unmarshal([]byte(`{"id":"y","domain":"b.example.com","listens":[{"port":8443,"protocol":"https"}],"backend":"127.0.0.1:8080","cert":"auto","enabled":true}`), &r2); err != nil {
		t.Fatal(err)
	}
	if len(r2.Listens) != 1 || r2.Listens[0].Port != 8443 || r2.Listens[0].Protocol != "https" {
		t.Fatalf("新形状应原样保留, 得到 %+v", r2.Listens)
	}
}
