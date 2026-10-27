package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestOrderCertDNS01: 完整 DNS-01 流程（mock ACME + mock Cloudflare + mock DoH，零真实网络）。
// 验证：TXT 建记录 → DoH 确认生效 → 触发验证 → 签发成功 → TXT 记录被清理。
func TestOrderCertDNS01(t *testing.T) {
	m := newMockAcme(t, "example.com", false)
	m.challengeType = "dns-01"
	acmeTestSetup(t, m)
	cf, cfSrv := newMockCF(t)
	// DoH 模拟：记录存在才返回其值（拆成两段引号字符串），模拟真实传播确认。
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		cf.mu.Lock()
		var ans []map[string]string
		for _, rec := range cf.records {
			if rec["name"] == name {
				v := rec["content"]
				half := len(v) / 2
				ans = append(ans, map[string]string{"data": `"` + v[:half] + `" "` + v[half:] + `"`})
			}
		}
		cf.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"Answer": ans})
	}))
	t.Cleanup(doh.Close)
	oldCF, oldDoH, oldEvery, oldTimeout := cfAPIBase, cfDoHBase, cfDoHPollEvery, cfDoHTimeout
	cfAPIBase, cfDoHBase, cfDoHPollEvery, cfDoHTimeout = cfSrv.URL, doh.URL, 10*time.Millisecond, 10*time.Second
	t.Cleanup(func() { cfAPIBase, cfDoHBase, cfDoHPollEvery, cfDoHTimeout = oldCF, oldDoH, oldEvery, oldTimeout })

	client, err := newAcmeClient()
	if err != nil {
		t.Fatalf("newAcmeClient: %v", err)
	}
	chain, priv, err := client.orderCert([]string{"example.com"}, "dns-01", "cf-test-token")
	if err != nil {
		t.Fatalf("dns-01 orderCert: %v", err)
	}
	if !strings.Contains(string(chain), "CERTIFICATE") || !strings.Contains(string(priv), "PRIVATE KEY") {
		t.Error("应返回证书链与私钥 PEM")
	}
	cf.mu.Lock()
	left := len(cf.records)
	cf.mu.Unlock()
	if left != 0 {
		t.Errorf("验证完 TXT 记录应全部删除，残留 %d 条", left)
	}
}

// TestOrderCertDNS01NoToken: dns-01 无 Token 应在建记录前就失败。
func TestOrderCertDNS01NoToken(t *testing.T) {
	m := newMockAcme(t, "example.com", false)
	m.challengeType = "dns-01"
	acmeTestSetup(t, m)
	client, err := newAcmeClient()
	if err != nil {
		t.Fatalf("newAcmeClient: %v", err)
	}
	if _, _, err := client.orderCert([]string{"example.com"}, "dns-01", ""); err == nil {
		t.Error("dns-01 无 Token 应报错")
	}
}
