package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCertViewFieldsAndDownload: 查看字段齐全（绝不含私钥）、下载为含私钥的 zip、未登录 401。
func TestCertViewFieldsAndDownload(t *testing.T) {
	root := certDeleteSetup(t)
	crtPEM, keyPEM := makeUploadCertPair(t, root, "viewcert", time.Now().Add(24*time.Hour))

	rescanProxyCertsLocked()
	meta, ok := findProxyCertMeta("upload:viewcert")
	if !ok {
		t.Fatal("扫描后应找到 upload:viewcert")
	}
	if meta.Issuer == "" || meta.Subject == "" || meta.NotBefore == "" || meta.Serial == "" || meta.Fingerprint == "" {
		t.Errorf("查看字段应齐全，得到 issuer=%q subject=%q notBefore=%q serial=%q fingerprint=%q",
			meta.Issuer, meta.Subject, meta.NotBefore, meta.Serial, meta.Fingerprint)
	}
	block, _ := pem.Decode([]byte(crtPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(sum[:]) != meta.Fingerprint {
		t.Error("指纹应为叶子 SHA256")
	}

	// 下载：200、zip 附件 <证书名>.zip，内含证书与私钥且内容等于存盘文件。
	req := httptest.NewRequest("GET", "/api/proxy/certs/upload:viewcert/download", nil)
	rec := httptest.NewRecorder()
	handleProxyCertItem(rec, req)
	if rec.Code != 200 {
		t.Fatalf("下载应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "viewcert.zip") {
		t.Errorf("下载应为附件 viewcert.zip，得到 %q", rec.Header().Get("Content-Disposition"))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("下载 Content-Type 应为 application/zip，得到 %q", ct)
	}
	assertCertZip(t, rec.Body.Bytes(), map[string]string{
		"viewcert.crt": string(crtPEM),
		"viewcert.key": string(keyPEM),
	})

	// 不存在的证书：404。
	req = httptest.NewRequest("GET", "/api/proxy/certs/upload:nope/download", nil)
	rec = httptest.NewRecorder()
	handleProxyCertItem(rec, req)
	if rec.Code != 404 {
		t.Errorf("不存在的证书下载应 404，得到 %d", rec.Code)
	}

	// 未登录：经 authMiddleware 应 401（下载接口走 /api/ 全量鉴权）。
	req = httptest.NewRequest("GET", "/api/proxy/certs/upload:viewcert/download", nil)
	rec = httptest.NewRecorder()
	authMiddleware(http.HandlerFunc(handleProxyCertItem)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("未登录下载应 401，得到 %d", rec.Code)
	}
}

// TestCertDownloadAcmeZip: ACME 证书下载为 zip，内含 fullchain.pem + privkey.pem。
func TestCertDownloadAcmeZip(t *testing.T) {
	root := certDeleteSetup(t)
	domain := "acmezip.example.com"
	makeAcmeCert(t, root, domain)
	rescanProxyCertsLocked()
	if _, ok := findProxyCertMeta("acme:" + domain); !ok {
		t.Fatal("扫描后应找到 acme:" + domain)
	}
	req := httptest.NewRequest("GET", "/api/proxy/certs/acme:"+domain+"/download", nil)
	rec := httptest.NewRecorder()
	handleProxyCertItem(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ACME 下载应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), domain+".zip") {
		t.Errorf("ACME 下载应为附件 %s.zip，得到 %q", domain, rec.Header().Get("Content-Disposition"))
	}
	crt, err := os.ReadFile(filepath.Join(root, "certs", domain, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(root, "certs", domain, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	assertCertZip(t, rec.Body.Bytes(), map[string]string{
		"fullchain.pem": string(crt),
		"privkey.pem":   string(key),
	})
}

// assertCertZip: 解开 zip，断言文件集合与内容与预期一致。
func assertCertZip(t *testing.T, data []byte, want map[string]string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("下载内容应为合法 zip: %v", err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		got[f.Name] = string(b)
	}
	if len(got) != len(want) {
		t.Fatalf("zip 应含 %d 个文件，得到 %v", len(want), got)
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("zip 内 %s 内容应等于存盘文件", name)
		}
	}
}
