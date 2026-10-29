package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 手动立即续期：校验（来源/存在/Token/忙）+ 认领（任务字段同步落位）+ 手动不受自动开关限制。

// resetAcmeJobIdle: 测试前后强制任务空闲（防上一个测试的后台任务串扰）。
func resetAcmeJobIdle(t *testing.T) {
	t.Helper()
	acmeJobMu.Lock()
	acmeJobSt.Running = false
	acmeJobSt.Name = ""
	acmeJobSt.Domain = ""
	acmeJobSt.Domains = nil
	acmeJobSt.Method = ""
	acmeJobSt.LastErr = ""
	acmeJobSt.LastOK = ""
	acmeJobMu.Unlock()
	t.Cleanup(func() {
		acmeJobMu.Lock()
		acmeJobSt.Running = false
		acmeJobSt.Name = ""
		acmeJobMu.Unlock()
	})
}

func callAcmeRenew(t *testing.T, body string) int {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/certs/acme/renew", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleAcmeRenew(rec, req)
	return rec.Code
}

func TestAcmeRenewValidation(t *testing.T) {
	root := certDeleteSetup(t)
	resetAcmeJobIdle(t)
	makeAcmeCertExpiry(t, root, "rn.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "rn.example.com", acmeCertMeta{Domains: []string{"rn.example.com"}, Method: "dns-01"})

	// 非 ACME 来源。
	if code := callAcmeRenew(t, `{"id":"upload:whatever"}`); code != 400 {
		t.Errorf("上传证书续期应 400，得到 %d", code)
	}
	// 证书不存在。
	if code := callAcmeRenew(t, `{"id":"acme:missing.example.com"}`); code != 400 {
		t.Errorf("不存在的证书续期应 400，得到 %d", code)
	}
	// DNS-01 且无 Token（全新数据目录，无存量 Token）。
	if code := callAcmeRenew(t, `{"id":"acme:rn.example.com"}`); code != 400 {
		t.Errorf("DNS-01 无 Token 续期应 400，得到 %d", code)
	}
}

func TestAcmeRenewClaimAndBypassAutoRenewOff(t *testing.T) {
	root := certDeleteSetup(t)
	resetAcmeJobIdle(t)
	// 自动续签关掉的证书：手动续期仍应放行（手动一次与自动无关）。
	makeAcmeCertExpiry(t, root, "off.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "off.example.com", acmeCertMeta{Domains: []string{"off.example.com"}, Method: "http-01", AutoRenew: boolPtr(false)})

	oldWork := acmeOrderWorkFunc
	called := make(chan [3]string, 1)
	acmeOrderWorkFunc = func(domains []string, method, tok string) error {
		called <- [3]string{strings.Join(domains, ","), method, tok}
		return nil
	}
	t.Cleanup(func() { acmeOrderWorkFunc = oldWork })

	if code := callAcmeRenew(t, `{"id":"acme:off.example.com"}`); code != 200 {
		t.Fatalf("手动续期应 200（started），得到 %d", code)
	}
	// 认领同步落位：响应返回时任务字段已是本次的。
	acmeJobMu.Lock()
	running, domain, method := acmeJobSt.Running, acmeJobSt.Domain, acmeJobSt.Method
	acmeJobMu.Unlock()
	if !running || domain != "off.example.com" || method != "http-01" {
		t.Errorf("认领后任务字段应为 off.example.com/http-01/running，得到 %v/%q/%q", running, domain, method)
	}
	// 后台任务确实以续期计划（meta 的域名组与方式）起单。
	select {
	case got := <-called:
		if got[0] != "off.example.com" || got[1] != "http-01" {
			t.Errorf("起单参数应为 off.example.com/http-01，得到 %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Error("续期任务应在 5 秒内起单")
	}
}

func TestAcmeRenewBusy409(t *testing.T) {
	root := certDeleteSetup(t)
	resetAcmeJobIdle(t)
	makeAcmeCertExpiry(t, root, "busy.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "busy.example.com", acmeCertMeta{Domains: []string{"busy.example.com"}, Method: "http-01"})

	acmeJobMu.Lock()
	acmeJobSt.Running = true
	acmeJobMu.Unlock()
	if code := callAcmeRenew(t, `{"id":"acme:busy.example.com"}`); code != 409 {
		t.Errorf("已有任务进行中时续期应 409，得到 %d", code)
	}
}
