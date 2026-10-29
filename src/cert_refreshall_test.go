package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 刷新全部：重读全部证书 + 逐张 OCSP 备注，返回最新表。

func TestCertRefreshAll(t *testing.T) {
	root := certDeleteSetup(t)
	makeAcmeCertExpiry(t, root, "ra.example.com", time.Now().Add(24*time.Hour))
	writeTestAcmeMeta(t, root, "ra.example.com", acmeCertMeta{Domains: []string{"ra.example.com"}, Method: "http-01"})
	makeUploadCertPair(t, root, "raup", time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("POST", "/api/proxy/certs/refresh-all", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handleProxyCertRefreshAll(rec, req)
	if rec.Code != 200 {
		t.Fatalf("刷新全部应 200，得到 %d", rec.Code)
	}
	var out struct {
		Certs []ProxyCertMeta   `json:"certs"`
		Notes map[string]string `json:"notes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// 测试底座自带一张 example 上传证书，故只断言自建的两张在内，不卡总数。
	ids := map[string]bool{}
	for _, c := range out.Certs {
		ids[c.ID] = true
	}
	if !ids["acme:ra.example.com"] || !ids["upload:raup"] {
		t.Errorf("应含自建的 acme 与 upload 两张，得到 %v", ids)
	}
	// 自签证书无 OCSP 可查：备注非空（吊销未确认类），前端据此写进状态格。
	if out.Notes["acme:ra.example.com"] == "" {
		t.Error("自签证书的 OCSP 备注不应为空")
	}
}
