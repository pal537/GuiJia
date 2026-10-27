package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// makeSelfSignedPEM: 生成一张自签证书 PEM(供 mock ACME 与续期判断测试)。
func makeSelfSignedPEM(t *testing.T, domain string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
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
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

type mockAcme struct {
	t                 *testing.T
	srv               *httptest.Server
	mu                sync.Mutex
	domain            string
	authzValid        bool
	failOrderFirst    bool
	orderCount        int
	key               *ecdsa.PublicKey
	expectedKeyAuth   string
	certPEM           []byte // /cert 回退用(未走 finalize 时)
	issuedPEM         []byte // finalize 按 CSR 真签发的证书
	caKey             *ecdsa.PrivateKey
	caCert            *x509.Certificate
	challengeType     string // 为空 = http-01；dns-01 测试时设为 "dns-01"
	nginxChallengeDir string // 非空时 nginx 方式：校验验证文件内容而非前置挑战表
}

// verifyJWS 校验 JWS 签名, 返回解码后的 payload 与是否通过。
func (m *mockAcme) verifyJWS(body []byte, r *http.Request) (payload []byte, ok bool) {
	var j struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if json.Unmarshal(body, &j) != nil {
		return nil, false
	}
	protJSON, err := base64.RawURLEncoding.DecodeString(j.Protected)
	if err != nil {
		return nil, false
	}
	var prot struct {
		Alg   string            `json:"alg"`
		Nonce string            `json:"nonce"`
		URL   string            `json:"url"`
		Kid   string            `json:"kid"`
		JWK   map[string]string `json:"jwk"`
	}
	if json.Unmarshal(protJSON, &prot) != nil {
		return nil, false
	}
	if prot.Alg != "ES256" || prot.Nonce == "" {
		return nil, false
	}
	if prot.URL != m.srv.URL+r.URL.Path {
		return nil, false
	}
	if prot.JWK != nil {
		x, _ := base64.RawURLEncoding.DecodeString(prot.JWK["x"])
		y, _ := base64.RawURLEncoding.DecodeString(prot.JWK["y"])
		m.key = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	}
	if m.key == nil {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil || len(sig) != 64 {
		return nil, false
	}
	h := sha256.Sum256([]byte(j.Protected + "." + j.Payload))
	if !ecdsa.Verify(m.key, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, false
	}
	payload, _ = base64.RawURLEncoding.DecodeString(j.Payload)
	return payload, true
}

func (m *mockAcme) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", "mock-nonce")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (m *mockAcme) handler(w http.ResponseWriter, r *http.Request) {
	u := m.srv.URL
	var reqBody []byte
	if r.Method == "POST" {
		reqBody, _ = io.ReadAll(r.Body)
	}
	switch r.URL.Path {
	case "/directory":
		m.writeJSON(w, 200, map[string]string{
			"newNonce": u + "/nonce", "newAccount": u + "/account", "newOrder": u + "/order",
		})
	case "/nonce":
		w.Header().Set("Replay-Nonce", "mock-nonce")
		w.WriteHeader(200)
	case "/account":
		if _, ok := m.verifyJWS(reqBody, r); !ok {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "bad jws"})
			return
		}
		w.Header().Set("Location", u+"/acct/1")
		m.writeJSON(w, 201, map[string]any{})
	case "/order":
		if _, ok := m.verifyJWS(reqBody, r); !ok {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "bad jws"})
			return
		}
		m.mu.Lock()
		m.orderCount++
		first := m.failOrderFirst && m.orderCount == 1
		m.mu.Unlock()
		if first {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:badNonce", "detail": "retry"})
			return
		}
		m.writeJSON(w, 201, map[string]any{
			"status": "pending", "authorizations": []string{u + "/authz/1"},
			"finalize": u + "/finalize", "certificate": u + "/cert",
		})
	case "/authz/1":
		if _, ok := m.verifyJWS(reqBody, r); !ok {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "bad jws"})
			return
		}
		m.mu.Lock()
		valid := m.authzValid
		m.mu.Unlock()
		st := "pending"
		if valid {
			st = "valid"
		}
		ct := m.challengeType
		if ct == "" {
			ct = "http-01"
		}
		m.writeJSON(w, 200, map[string]any{
			"identifier": map[string]string{"type": "dns", "value": m.domain},
			"status":     st,
			"challenges": []map[string]string{{"type": ct, "status": st, "url": u + "/chall/1", "token": "tok-123"}},
		})
	case "/chall/1":
		if _, ok := m.verifyJWS(reqBody, r); !ok {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "bad jws"})
			return
		}
		// dns-01 不走前置 HTTP-01 挑战表，直接放行；http-01 仍校验挑战已注册；
		// nginx 方式校验验证文件内容（测试注入的 dataDir）。
		if m.challengeType == "dns-01" {
			// 直接放行
		} else if m.nginxChallengeDir != "" {
			b, err := os.ReadFile(filepath.Join(m.nginxChallengeDir, "acme-challenge", "tok-123"))
			if err != nil || (m.expectedKeyAuth != "" && string(b) != m.expectedKeyAuth) {
				m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "challenge file mismatch"})
				return
			}
		} else {
			frontMu.Lock()
			ka := frontChallenges["tok-123"]
			frontMu.Unlock()
			if m.expectedKeyAuth != "" && ka != m.expectedKeyAuth {
				m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "challenge not registered"})
				return
			}
		}
		m.mu.Lock()
		m.authzValid = true
		m.mu.Unlock()
		m.writeJSON(w, 200, map[string]string{"type": "http-01", "status": "valid", "url": u + "/chall/1", "token": "tok-123"})
	case "/finalize":
		payload, ok := m.verifyJWS(reqBody, r)
		if !ok {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "bad jws"})
			return
		}
		// 像真 CA 一样按 CSR 签发: 证书公钥必须与 CSR 公钥一致, 否则配对校验会跳过。
		var finReq struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(payload, &finReq)
		csrDER, _ := base64.RawURLEncoding.DecodeString(finReq.CSR)
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil || csr.CheckSignature() != nil {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "bad csr"})
			return
		}
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(100),
			Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, leafTpl, m.caCert, csr.PublicKey, m.caKey)
		if err != nil {
			m.writeJSON(w, 500, map[string]string{"type": "urn:ietf:params:acme:error:serverInternal", "detail": err.Error()})
			return
		}
		m.mu.Lock()
		m.issuedPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		m.mu.Unlock()
		m.writeJSON(w, 200, map[string]any{"status": "valid", "certificate": u + "/cert"})
	case "/cert":
		if _, ok := m.verifyJWS(reqBody, r); !ok {
			m.writeJSON(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "bad jws"})
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		m.mu.Lock()
		pemOut := m.issuedPEM
		m.mu.Unlock()
		if pemOut == nil {
			pemOut = m.certPEM
		}
		w.Write(pemOut)
	default:
		http.NotFound(w, r)
	}
}

func newMockAcme(t *testing.T, domain string, failOrderFirst bool) *mockAcme {
	t.Helper()
	certPEM, _ := makeSelfSignedPEM(t, domain, time.Now().Add(90*24*time.Hour))
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mock CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockAcme{t: t, domain: domain, failOrderFirst: failOrderFirst, certPEM: certPEM, caKey: caKey, caCert: caCert}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handler))
	t.Cleanup(m.srv.Close)
	return m
}

// acmeTestSetup: 临时数据目录 + 缩短轮询 + 指向 mock 目录。
func acmeTestSetup(t *testing.T, m *mockAcme) {
	t.Helper()
	dir := t.TempDir()
	oldDataDir, oldDirURL, oldEvery, oldTimeout := dataDir, acmeDirURL, acmePollEvery, acmePollTimeout
	dataDir = dir
	acmeDirURL = m.srv.URL + "/directory"
	acmePollEvery = 10 * time.Millisecond
	acmePollTimeout = 10 * time.Second
	t.Cleanup(func() {
		dataDir, acmeDirURL, acmePollEvery, acmePollTimeout = oldDataDir, oldDirURL, oldEvery, oldTimeout
	})
}

func TestAcmeFullFlow(t *testing.T) {
	m := newMockAcme(t, "example.com", false)
	acmeTestSetup(t, m)
	client, err := newAcmeClient()
	if err != nil {
		t.Fatalf("newAcmeClient: %v", err)
	}
	thumb, err := client.thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if len(thumb) != 43 {
		t.Errorf("指纹应为 43 字符 base64url, 得到 %q", thumb)
	}
	m.expectedKeyAuth = "tok-123." + thumb
	chain, priv, err := client.orderCert([]string{"example.com"}, "http-01", "")
	if err != nil {
		t.Fatalf("orderCert: %v", err)
	}
	if !strings.Contains(string(chain), "CERTIFICATE") {
		t.Error("证书链应含 PEM 证书")
	}
	if !strings.Contains(string(priv), "PRIVATE KEY") {
		t.Error("私钥应为 PEM")
	}
	// 挑战已清理
	frontMu.Lock()
	left := len(frontChallenges)
	frontMu.Unlock()
	if left != 0 {
		t.Errorf("签发后挑战应清理, 残留 %d", left)
	}
	// 落盘 + 扫描 + 续期判断
	if err := writeAcmeCert("example.com", chain, priv); err != nil {
		t.Fatalf("writeAcmeCert: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "certs", "example.com", "fullchain.pem")); err != nil {
		t.Error("fullchain.pem 应落盘")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "certs", "example.com", "privkey.pem")); err != nil {
		t.Error("privkey.pem 应落盘")
	}
	if acmeNeedsRenewal("example.com") {
		t.Error("90 天后到期的证书不应判定需续期")
	}
	metas, serving := scanProxyCerts()
	found := false
	for _, mt := range metas {
		if mt.ID == "acme:example.com" {
			found = true
		}
	}
	if !found || serving["acme:example.com"] == nil {
		t.Error("扫描应找到 acme:example.com 且可用于握手")
	}
}

func TestAcmeBadNonceRetry(t *testing.T) {
	m := newMockAcme(t, "example.com", true)
	acmeTestSetup(t, m)
	client, err := newAcmeClient()
	if err != nil {
		t.Fatalf("newAcmeClient: %v", err)
	}
	thumb, _ := client.thumbprint()
	m.expectedKeyAuth = "tok-123." + thumb
	if _, _, err := client.orderCert([]string{"example.com"}, "http-01", ""); err != nil {
		t.Fatalf("badNonce 后重试应成功, 得到 %v", err)
	}
}

func TestAcmeNeedsRenewal(t *testing.T) {
	dir := t.TempDir()
	oldDataDir := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = oldDataDir })
	// 10 天后到期 -> 需续期
	certPEM, keyPEM := makeSelfSignedPEM(t, "soon.example.com", time.Now().Add(10*24*time.Hour))
	writeAcmeCert("soon.example.com", certPEM, keyPEM)
	if !acmeNeedsRenewal("soon.example.com") {
		t.Error("10 天后到期的证书应判定需续期")
	}
	// 90 天后到期 -> 不需续期
	certPEM, keyPEM = makeSelfSignedPEM(t, "later.example.com", time.Now().Add(90*24*time.Hour))
	writeAcmeCert("later.example.com", certPEM, keyPEM)
	if acmeNeedsRenewal("later.example.com") {
		t.Error("90 天后到期的证书不应判定需续期")
	}
	// 不存在 -> 需续期(读不到到期时间)
	if !acmeNeedsRenewal("missing.example.com") {
		t.Error("不存在的证书应判定需续期")
	}
}

func TestFrontChallenge(t *testing.T) {
	port := freePort(t)
	srv, err := startFront80On("127.0.0.1:" + itoa(port))
	if err != nil {
		t.Fatalf("startFront80On: %v", err)
	}
	defer srv.Close()
	frontRegisterChallenge("tok-abc", "tok-abc.thumbprint")
	defer frontClearChallenge("tok-abc")
	resp, err := http.Get("http://127.0.0.1:" + itoa(port) + "/.well-known/acme-challenge/tok-abc")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "tok-abc.thumbprint" {
		t.Errorf("挑战应答应为 keyAuth, 得到 %q", string(body))
	}
	resp, _ = http.Get("http://127.0.0.1:" + itoa(port) + "/.well-known/acme-challenge/nope")
	if resp.StatusCode != 404 {
		t.Errorf("未注册的 token 应 404, 得到 %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = http.Get("http://127.0.0.1:" + itoa(port) + "/other")
	if resp.StatusCode != 421 {
		t.Errorf("直接 IP 访问应 421, 得到 %d", resp.StatusCode)
	}
	resp.Body.Close()
}
