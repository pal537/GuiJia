package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 证书备注名：编辑（改名/重名/非法/清空/与自身同名/与开关同改）+ 续期沿用 + 申请校验。

func TestCertRenameEdit(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCertExpiry(t, root, "ren.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "ren.example.com", acmeCertMeta{Domains: []string{"ren.example.com"}, Method: "http-01"})

	// 改名：meta 落备注，列表显示新名。
	code, out := callCertItem(t, "PUT", "acme:ren.example.com", `{"name":"我的主站"}`)
	if code != 200 {
		t.Fatalf("改名应 200，得到 %d", code)
	}
	if m := readTestAcmeMeta(t, root, "ren.example.com"); m.Name != "我的主站" {
		t.Errorf("meta 备注应为“我的主站”，得到 %q", m.Name)
	}
	if cert, _ := out["cert"].(map[string]any); cert["name"] != "我的主站" {
		t.Errorf("编辑响应里的显示名应为新备注，得到 %v", cert["name"])
	}
	if cert, _ := out["cert"].(map[string]any); cert["remark"] != "我的主站" {
		t.Errorf("编辑响应里的 remark 应为新备注，得到 %v", cert["remark"])
	}
}

func TestCertRenameDuplicateAndInvalid(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCertExpiry(t, root, "a.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "a.example.com", acmeCertMeta{Domains: []string{"a.example.com"}, Method: "http-01"})
	makeAcmeCertExpiry(t, root, "b.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "b.example.com", acmeCertMeta{Domains: []string{"b.example.com"}, Method: "http-01", Name: "已有备注"})

	// 重名：与 B 的备注撞 → 400；与 B 的域名撞 → 400（B 无备注时显示名即域名，见下）。
	if code, _ := callCertItem(t, "PUT", "acme:a.example.com", `{"name":"已有备注"}`); code != 400 {
		t.Errorf("与他人备注重名应 400，得到 %d", code)
	}
	// 非法：含 /、超长 → 400。
	if code, _ := callCertItem(t, "PUT", "acme:a.example.com", `{"name":"a/b"}`); code != 400 {
		t.Errorf("含 / 的备注应 400，得到 %d", code)
	}
	if code, _ := callCertItem(t, "PUT", "acme:a.example.com", `{"name":"`+strings.Repeat("名", 65)+`"}`); code != 400 {
		t.Errorf("超 64 字的备注应 400，得到 %d", code)
	}
	// 与自身显示名同名不算冲突：B 的备注改回自己的域名应 200（显示不变）。
	if code, _ := callCertItem(t, "PUT", "acme:b.example.com", `{"name":"b.example.com"}`); code != 200 {
		t.Errorf("改成自身域名应 200，得到 %d", code)
	}
}

func TestCertRenameClearAndToggleTogether(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCertExpiry(t, root, "c.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "c.example.com", acmeCertMeta{Domains: []string{"c.example.com"}, Method: "http-01", Name: "旧备注", AutoRenew: boolPtr(true)})

	// 清空：备注清掉，显示回首域名。
	code, out := callCertItem(t, "PUT", "acme:c.example.com", `{"name":""}`)
	if code != 200 {
		t.Fatalf("清空备注应 200，得到 %d", code)
	}
	if m := readTestAcmeMeta(t, root, "c.example.com"); m.Name != "" {
		t.Errorf("清空后 meta 备注应为空，得到 %q", m.Name)
	}
	if cert, _ := out["cert"].(map[string]any); cert["name"] != "c.example.com" {
		t.Errorf("清空后显示名应回首域名，得到 %v", cert["name"])
	}
	// 与开关同改：一次写盘，两项都生效。
	code, _ = callCertItem(t, "PUT", "acme:c.example.com", `{"autoRenew":false,"name":"新名"}`)
	if code != 200 {
		t.Fatalf("同改开关与备注应 200，得到 %d", code)
	}
	m := readTestAcmeMeta(t, root, "c.example.com")
	if m.AutoRenew == nil || *m.AutoRenew {
		t.Error("同改后 autoRenew 应为 false")
	}
	if m.Name != "新名" {
		t.Errorf("同改后备注应为“新名”，得到 %q", m.Name)
	}
}

func TestCertRenameUploadNameIgnored(t *testing.T) {
	root := certDeleteSetup(t)
	makeUploadCertPair(t, root, "upcert", time.Now().Add(24*time.Hour))
	// 上传证书名即文件名：编辑传 name 应忽略（不报错、不改名）。
	code, out := callCertItem(t, "PUT", "upload:upcert", `{"name":"别想改我"}`)
	if code != 200 {
		t.Fatalf("上传证书编辑传 name 应 200（忽略），得到 %d", code)
	}
	if cert, _ := out["cert"].(map[string]any); cert["name"] != "upcert" {
		t.Errorf("上传证书名应仍为文件名，得到 %v", cert["name"])
	}
}

func TestAcmeMetaForOrderPreservesName(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCert(t, root, "named.example.com")
	writeTestAcmeMeta(t, root, "named.example.com", acmeCertMeta{Domains: []string{"named.example.com"}, Method: "http-01", Name: "旧备注"})
	// 续期（无待写备注）：沿用旧备注。
	if m := acmeMetaForOrder("named.example.com", []string{"named.example.com"}, "http-01"); m.Name != "旧备注" {
		t.Errorf("续期 meta 应沿用旧备注，得到 %q", m.Name)
	}
	// 申请（带新备注）：覆盖旧备注。
	acmeJobMu.Lock()
	acmeJobSt.Name = "新备注"
	acmeJobMu.Unlock()
	t.Cleanup(func() {
		acmeJobMu.Lock()
		acmeJobSt.Name = ""
		acmeJobMu.Unlock()
	})
	if m := acmeMetaForOrder("named.example.com", []string{"named.example.com"}, "http-01"); m.Name != "新备注" {
		t.Errorf("申请备注应覆盖旧备注，得到 %q", m.Name)
	}
}

func TestAcmeApplyNameValidation(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCertExpiry(t, root, "dup.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "dup.example.com", acmeCertMeta{Domains: []string{"dup.example.com"}, Method: "dns-01"})

	callApply := func(body string) int {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/certs/acme/apply", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handleAcmeApply(rec, req)
		return rec.Code
	}
	// dns-01 + Token 绕开 80 端口检查，直达备注校验。
	if code := callApply(`{"domains":["new.example.com"],"method":"dns-01","cfToken":"tok-x","name":"a/b"}`); code != 400 {
		t.Errorf("申请备注含 / 应 400，得到 %d", code)
	}
	if code := callApply(`{"domains":["new.example.com"],"method":"dns-01","cfToken":"tok-x","name":"dup.example.com"}`); code != 400 {
		t.Errorf("申请备注与已有证书显示名重名应 400，得到 %d", code)
	}
}
