package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func pemEncodeCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// ocspTestSetup: 建 CA + 一张叶子证书（OCSP 地址与 AIA 地址可配）。
func ocspTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1000),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func ocspTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, ocspURL, aiaURL string, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ocspURL != "" {
		tpl.OCSPServer = []string{ocspURL}
	}
	if aiaURL != "" {
		tpl.IssuingCertificateURL = []string{aiaURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// ocspTestResponder: 按给定状态回 OCSP 响应的 httptest 服务（CA 自己当 responder）。
func ocspTestResponder(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(raw)
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		tpl := ocsp.Response{
			Status:       status,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   time.Now().Add(-5 * time.Minute),
			NextUpdate:   time.Now().Add(time.Hour),
			RevokedAt:    time.Now(),
			Certificate:  ca,
		}
		der, err := ocsp.CreateResponse(ca, ca, tpl, caKey)
		if err != nil {
			http.Error(w, "create failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(der)
	}))
}

func TestOCSPGoodRevokedUnknown(t *testing.T) {
	ca, caKey := ocspTestCA(t)
	for _, tc := range []struct {
		status int
		want   string
	}{
		{ocsp.Good, "good"},
		{ocsp.Revoked, "revoked"},
		{ocsp.Unknown, "unknown"},
	} {
		srv := ocspTestResponder(t, ca, caKey, tc.status)
		leaf, _ := ocspTestLeaf(t, ca, caKey, 7, srv.URL, "", time.Now().Add(24*time.Hour))
		got, err := ocspCheckLeaf(leaf, ca)
		srv.Close()
		if got != tc.want {
			t.Errorf("status %d: 得到 %q(%v)，想要 %q", tc.status, got, err, tc.want)
		}
	}
}

func TestOCSPNoServerOrIssuer(t *testing.T) {
	ca, caKey := ocspTestCA(t)
	// 无 OCSP 地址。
	leaf, _ := ocspTestLeaf(t, ca, caKey, 8, "", "", time.Now().Add(24*time.Hour))
	if got, _ := ocspCheckLeaf(leaf, ca); got != "unknown" {
		t.Errorf("无 OCSP 地址应为 unknown，得到 %q", got)
	}
	// 无 issuer。
	srv := ocspTestResponder(t, ca, caKey, ocsp.Good)
	defer srv.Close()
	leaf2, _ := ocspTestLeaf(t, ca, caKey, 9, srv.URL, "", time.Now().Add(24*time.Hour))
	if got, _ := ocspCheckLeaf(leaf2, nil); got != "unknown" {
		t.Errorf("无 issuer 应为 unknown，得到 %q", got)
	}
}

func TestOCSPIssuerFromChainAndAIA(t *testing.T) {
	ca, caKey := ocspTestCA(t)
	srv := ocspTestResponder(t, ca, caKey, ocsp.Good)
	defer srv.Close()
	leaf, _ := ocspTestLeaf(t, ca, caKey, 11, srv.URL, "", time.Now().Add(24*time.Hour))
	// fullchain 第二张即 issuer。
	if got := ocspIssuerFor(leaf, []*x509.Certificate{leaf, ca}); got != ca {
		t.Error("fullchain 第二张应为 issuer")
	}
	// 只有一张时走 AIA 拉取 issuer（DER）。
	aia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(ca.Raw)
	}))
	defer aia.Close()
	leafAIA, _ := ocspTestLeaf(t, ca, caKey, 12, srv.URL, aia.URL, time.Now().Add(24*time.Hour))
	if got := ocspIssuerFor(leafAIA, []*x509.Certificate{leafAIA}); got == nil || got.SerialNumber.Cmp(ca.SerialNumber) != 0 {
		t.Error("AIA 应拉到 issuer 证书")
	}
	// 既无第二张又无 AIA。
	if got := ocspIssuerFor(leaf, []*x509.Certificate{leaf}); got != nil {
		t.Error("无 issuer 来源时应返回 nil")
	}
}

func TestOCSPCacheSerialBinding(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := ocspTestCA(t)
	leaf, _ := ocspTestLeaf(t, ca, caKey, 21, "", "", time.Now().Add(24*time.Hour))
	path := filepath.Join(dir, "ocsp.json")
	if err := writeOCSPCache(path, leaf, "revoked"); err != nil {
		t.Fatal(err)
	}
	if c, ok := readOCSPCache(path, leaf); !ok || c.Status != "revoked" {
		t.Errorf("序列号一致的缓存应命中，得到 %+v,%v", c, ok)
	}
	// 换一张序列号不同的叶子，旧缓存自动失效。
	leaf2, _ := ocspTestLeaf(t, ca, caKey, 22, "", "", time.Now().Add(24*time.Hour))
	if _, ok := readOCSPCache(path, leaf2); ok {
		t.Error("序列号不一致的缓存不应命中")
	}
	// unknown 不落盘。
	if err := writeOCSPCache(filepath.Join(dir, "u.json"), leaf, "unknown"); err == nil {
		t.Error("unknown 不应写入缓存")
	}
	if _, err := os.Stat(filepath.Join(dir, "u.json")); err == nil {
		t.Error("unknown 不应留下缓存文件")
	}
}

func TestOCSPCheckForFile(t *testing.T) {
	ca, caKey := ocspTestCA(t)
	srv := ocspTestResponder(t, ca, caKey, ocsp.Revoked)
	defer srv.Close()
	leaf, _ := ocspTestLeaf(t, ca, caKey, 31, srv.URL, "", time.Now().Add(24*time.Hour))
	// fullchain 文件：leaf + issuer。
	dir := t.TempDir()
	p := filepath.Join(dir, "fullchain.pem")
	pemBytes := append(pemEncodeCert(leaf), pemEncodeCert(ca)...)
	if err := os.WriteFile(p, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
	st, note := ocspCheckForFile(p)
	if st != "revoked" || !strings.Contains(note, "吊销") {
		t.Errorf("吊销响应应返回 revoked，得到 %q/%q", st, note)
	}
	// 响应方挂了：unknown + 吊销未确认，绝不标吊销。
	srv2 := ocspTestResponder(t, ca, caKey, ocsp.Good)
	url2 := srv2.URL
	srv2.Close()
	leaf2, _ := ocspTestLeaf(t, ca, caKey, 32, url2, "", time.Now().Add(24*time.Hour))
	p2 := filepath.Join(dir, "fullchain2.pem")
	if err := os.WriteFile(p2, append(pemEncodeCert(leaf2), pemEncodeCert(ca)...), 0644); err != nil {
		t.Fatal(err)
	}
	st, note = ocspCheckForFile(p2)
	if st != "unknown" || !strings.Contains(note, "吊销未确认") {
		t.Errorf("响应方不可达应为 unknown + 吊销未确认，得到 %q/%q", st, note)
	}
}
