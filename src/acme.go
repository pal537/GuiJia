package main

// ACME 在线证书: HTTP-01 / DNS-01(Cloudflare), CA 默认 Let's Encrypt, 自动续期(到期前 30 天)。
// 证书按首域名分子目录存放: <数据目录>/certs/<首域名>/fullchain.pem + privkey.pem + meta.json，
// 一张证书可含多个域名（SAN），目录名取域名组第一个；续期按 meta.json 原样沿用域名组与验证方式。
// 本文件先放证书扫描(供反代/面板选证书); 在线申请客户端见本文件后半部分。

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// acmeCertDir 返回某域名的 ACME 证书目录。
func acmeCertDir(domain string) string {
	return filepath.Join(dataDir, "certs", domain)
}

// scanAcmeCerts 扫描 ACME 域名子目录: 每目录一对 fullchain.pem + privkey.pem
// 即一张证书, id 为 "acme:<域名>", 来源 "acme"。配不齐的目录直接跳过。
func scanAcmeCerts(metas *[]ProxyCertMeta, serving map[string]*proxyCertEntry, seen map[string]bool) {
	root := filepath.Join(dataDir, "certs")
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		crtPath := filepath.Join(dir, "fullchain.pem")
		keyPath := filepath.Join(dir, "privkey.pem")
		if _, err := os.Stat(crtPath); err != nil {
			continue
		}
		if _, err := os.Stat(keyPath); err != nil {
			continue
		}
		id := "acme:" + e.Name()
		if seen[id] {
			continue
		}
		meta, entry, err := parseProxyCertPair(crtPath, keyPath, id, e.Name(), "acme", dir)
		if err != nil {
			continue
		}
		// 编辑弹窗与续期开关用：方式与自动续签取自 meta.json（无字段视为开）。
		// 备注名也在此覆盖显示名（无备注则仍显示首域名）。
		if m, ok := readAcmeMeta(e.Name()); ok {
			meta.Method = m.Method
			meta.AutoRenew = m.AutoRenew == nil || *m.AutoRenew
			if strings.TrimSpace(m.Name) != "" {
				meta.Name = strings.TrimSpace(m.Name)
				meta.Remark = strings.TrimSpace(m.Name)
			}
			entry.meta = meta
		} else {
			meta.AutoRenew = true
			entry.meta = meta
		}
		seen[id] = true
		*metas = append(*metas, meta)
		if !meta.Expired && entry != nil {
			serving[id] = entry
		}
	}
}

// ---------- ACME 客户端(RFC 8555, HTTP-01, 纯标准库) ----------

const defaultAcmeDirURL = "https://acme-v02.api.letsencrypt.org/directory"

// 可测试变量: 目录地址、轮询间隔与超时(测试用 httptest 缩短)。
var (
	acmeDirURL      = defaultAcmeDirURL
	acmePollEvery   = 2 * time.Second
	acmePollTimeout = 120 * time.Second
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// loadOrCreateAccountKey: 账户密钥 ECDSA P256, 存 certs/acme-account.key(0600)。
func loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dataDir, "certs", "acme-account.key")
	if der, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(der); block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	os.MkdirAll(filepath.Join(dataDir, "certs"), 0755)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type acmeClient struct {
	dirURL  string
	http    *http.Client
	key     *ecdsa.PrivateKey
	kid     string
	dir     acmeDirectory
	nonceMu sync.Mutex
	nonce   string
}

func newAcmeClient() (*acmeClient, error) {
	key, err := loadOrCreateAccountKey()
	if err != nil {
		return nil, err
	}
	c := &acmeClient{dirURL: acmeDirURL, http: &http.Client{Timeout: 30 * time.Second}, key: key}
	if err := c.loadDirectory(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *acmeClient) loadDirectory() error {
	resp, err := c.http.Get(c.dirURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ACME 目录请求失败: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(&c.dir)
}

func (c *acmeClient) fetchNonce() error {
	req, _ := http.NewRequest("HEAD", c.dir.NewNonce, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonceMu.Lock()
		c.nonce = n
		c.nonceMu.Unlock()
		return nil
	}
	return errors.New("ACME 服务端未返回 Replay-Nonce")
}

func (c *acmeClient) takeNonce() string {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	n := c.nonce
	c.nonce = ""
	return n
}

func (c *acmeClient) storeNonce(h http.Header) {
	if n := h.Get("Replay-Nonce"); n != "" {
		c.nonceMu.Lock()
		c.nonce = n
		c.nonceMu.Unlock()
	}
}

// jwkMap: 账户公钥 JWK。
func (c *acmeClient) jwkMap() map[string]string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	c.key.PublicKey.X.FillBytes(x)
	c.key.PublicKey.Y.FillBytes(y)
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64url(x), "y": b64url(y)}
}

// thumbprint: RFC 7638 JWK 指纹。
func (c *acmeClient) thumbprint() (string, error) {
	jwk := c.jwkMap()
	// 键按字母序: crv,kty,x,y; Go map 序列化本身已按字母序, 显式拼串更稳。
	raw := `{"crv":"P-256","kty":"EC","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `"}`
	sum := sha256.Sum256([]byte(raw))
	return b64url(sum[:]), nil
}

// jwsBody: ES256 签名; payload 为 nil 时表示 POST-as-GET(空字符串载荷)。
func (c *acmeClient) jwsBody(url string, payload any, useKid bool) ([]byte, error) {
	nonce := c.takeNonce()
	if nonce == "" {
		if err := c.fetchNonce(); err != nil {
			return nil, err
		}
		nonce = c.takeNonce()
	}
	prot := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if useKid {
		prot["kid"] = c.kid
	} else {
		prot["jwk"] = c.jwkMap()
	}
	protJSON, _ := json.Marshal(prot)
	var payloadB64 string
	if payload != nil {
		pb, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadB64 = b64url(pb)
	}
	sigInput := b64url(protJSON) + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, h[:])
	if err != nil {
		return nil, err
	}
	rb := make([]byte, 32)
	sb := make([]byte, 32)
	r.FillBytes(rb)
	s.FillBytes(sb)
	body, _ := json.Marshal(map[string]string{
		"protected": b64url(protJSON),
		"payload":   payloadB64,
		"signature": b64url(append(rb, sb...)),
	})
	return body, nil
}

type acmeError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (e *acmeError) Error() string {
	if e.Detail != "" {
		return e.Type + ": " + e.Detail
	}
	return e.Type
}

// post: 发 JWS 请求; 遇 badNonce 自动换 nonce 重试一次。
// payload=nil 表示 POST-as-GET。
func (c *acmeClient) post(url string, payload any, useKid bool) (body []byte, hdr http.Header, status int, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		jb, err := c.jwsBody(url, payload, useKid)
		if err != nil {
			return nil, nil, 0, err
		}
		req, _ := http.NewRequest("POST", url, bytes.NewReader(jb))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, 0, err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		c.storeNonce(resp.Header)
		if resp.StatusCode == 400 {
			var ae acmeError
			if json.Unmarshal(b, &ae) == nil && strings.Contains(ae.Type, "badNonce") && attempt == 0 {
				c.nonceMu.Lock()
				c.nonce = ""
				c.nonceMu.Unlock()
				continue
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var ae acmeError
			if json.Unmarshal(b, &ae) == nil && ae.Type != "" {
				return nil, resp.Header, resp.StatusCode, &ae
			}
			return nil, resp.Header, resp.StatusCode, fmt.Errorf("ACME 请求失败: %s %s", resp.Status, strings.TrimSpace(string(b)))
		}
		return b, resp.Header, resp.StatusCode, nil
	}
	return nil, nil, 0, errors.New("ACME 请求重试失败")
}

func (c *acmeClient) ensureAccount() error {
	_, hdr, _, err := c.post(c.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true}, false)
	if err != nil {
		return err
	}
	if loc := hdr.Get("Location"); loc != "" {
		c.kid = loc
		return nil
	}
	return errors.New("ACME 账户创建未返回 Location")
}

type acmeOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type acmeAuthz struct {
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Status     string `json:"status"`
	Challenges []struct {
		Type   string `json:"type"`
		Status string `json:"status"`
		URL    string `json:"url"`
		Token  string `json:"token"`
	} `json:"challenges"`
}

// pollUntil: POST-as-GET 轮询, 直到 fn 返回 true(完成)或超时。
func (c *acmeClient) pollUntil(url string, fn func([]byte) (done bool, err error)) error {
	deadline := time.Now().Add(acmePollTimeout)
	for {
		b, _, _, err := c.post(url, nil, true)
		if err != nil {
			return err
		}
		done, err := fn(b)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("ACME 轮询超时")
		}
		time.Sleep(acmePollEvery)
	}
}

// orderCert: 为域名组申请证书, 返回 fullchain PEM 与域名私钥 PEM。
// method 只能是 http-01、dns-01 或 nginx（自动已在调用方解析）；dns-01 需要 cfToken。
// nginx 走 http-01 挑战，但满足方式是往数据目录写 token 文件、由 nginx 代答，
// 不占用面板自身的前置 80 服务（frontRegisterChallenge）。
func (c *acmeClient) orderCert(domains []string, method, cfToken string) (fullchainPEM, privkeyPEM []byte, err error) {
	if len(domains) == 0 {
		return nil, nil, errors.New("域名为空")
	}
	if method != "http-01" && method != "dns-01" && method != "nginx" {
		return nil, nil, errors.New("未知的验证方式: " + method)
	}
	if method == "dns-01" && cfToken == "" {
		return nil, nil, errors.New("DNS-01 需要 Cloudflare API Token")
	}
	// nginx 与 http-01 拿的是同一种挑战（http-01），只换满足方式。
	challengeType := method
	if method == "nginx" {
		challengeType = "http-01"
	}
	if err := c.ensureAccount(); err != nil {
		return nil, nil, err
	}
	idents := []map[string]string{}
	for _, d := range domains {
		idents = append(idents, map[string]string{"type": "dns", "value": d})
	}
	ob, _, _, err := c.post(c.dir.NewOrder, map[string]any{"identifiers": idents}, true)
	if err != nil {
		return nil, nil, err
	}
	var order acmeOrder
	if err := json.Unmarshal(ob, &order); err != nil {
		return nil, nil, err
	}
	thumb, err := c.thumbprint()
	if err != nil {
		return nil, nil, err
	}
	// 逐个授权做验证；清理函数统一 deferred，失败路径也尽力清理 TXT 记录与 HTTP-01 挑战。
	cleanups := []func(){}
	defer func() {
		for _, fn := range cleanups {
			fn()
		}
	}()
	for _, authzURL := range order.Authorizations {
		ab, _, _, err := c.post(authzURL, nil, true)
		if err != nil {
			return nil, nil, err
		}
		var authz acmeAuthz
		if err := json.Unmarshal(ab, &authz); err != nil {
			return nil, nil, err
		}
		var challURL, token string
		for _, ch := range authz.Challenges {
			if ch.Type == challengeType {
				challURL, token = ch.URL, ch.Token
				break
			}
		}
		if challURL == "" {
			return nil, nil, errors.New("授权中没有 " + challengeType + " 验证方式")
		}
		if method == "http-01" {
			keyAuth := token + "." + thumb
			frontRegisterChallenge(token, keyAuth)
			tok := token
			cleanups = append(cleanups, func() { frontClearChallenge(tok) })
		} else if method == "nginx" {
			// nginx 代答：写 token 文件（内容 keyAuth），验证完删除，失败也清理。
			keyAuth := token + "." + thumb
			if err := nginxWriteChallenge(token, keyAuth); err != nil {
				return nil, nil, err
			}
			tok := token
			cleanups = append(cleanups, func() { nginxRemoveChallenge(tok) })
		} else {
			// DNS-01：按授权标识建 TXT → 等 DoH 生效 → 再触发验证；记录按 ID 删除。
			// 通配符与根域名共用一条 _acme-challenge 记录名，但值不同，可并存多条。
			domain := authz.Identifier.Value
			name := dns01RecordName(domain)
			value := dns01TXTValue(token, thumb)
			cfc := newCFClient(cfToken)
			zoneID, err := cfc.findZoneID(domain)
			if err != nil {
				return nil, nil, err
			}
			recID, err := cfc.createTXT(zoneID, name, value)
			if err != nil {
				return nil, nil, err
			}
			z, rid := zoneID, recID
			cleanups = append(cleanups, func() { cfc.deleteTXT(z, rid) })
			if err := cfWaitTXT(name, value); err != nil {
				return nil, nil, err
			}
		}
		if _, _, _, err := c.post(challURL, map[string]any{}, true); err != nil {
			return nil, nil, err
		}
		invalidMsg := "域名验证失败(请确认域名已解析到本机且 80 端口可达)"
		if method == "dns-01" {
			invalidMsg = "域名验证失败(请确认域名已托管到 Cloudflare 且 Token 有 DNS 编辑权限)"
		}
		if method == "nginx" {
			invalidMsg = "域名验证失败(请确认域名已解析到本机且 nginx 代答配置已生效)"
		}
		if err := c.pollUntil(authzURL, func(b []byte) (bool, error) {
			var az acmeAuthz
			if err := json.Unmarshal(b, &az); err != nil {
				return false, err
			}
			if az.Status == "valid" {
				return true, nil
			}
			if az.Status == "invalid" {
				return false, errors.New(invalidMsg)
			}
			return false, nil
		}); err != nil {
			return nil, nil, err
		}
	}
	// 生成域名密钥与 CSR, 提交 finalize。
	domKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, domKey)
	if err != nil {
		return nil, nil, err
	}
	fb, _, _, err := c.post(order.Finalize, map[string]any{"csr": b64url(csrDER)}, true)
	if err != nil {
		return nil, nil, err
	}
	var fin acmeOrder
	if err := json.Unmarshal(fb, &fin); err != nil {
		return nil, nil, err
	}
	certURL := fin.Certificate
	if certURL == "" {
		if err := c.pollUntil(order.Finalize, func(b []byte) (bool, error) {
			var o acmeOrder
			if err := json.Unmarshal(b, &o); err != nil {
				return false, err
			}
			if o.Status == "valid" && o.Certificate != "" {
				certURL = o.Certificate
				return true, nil
			}
			if o.Status == "invalid" {
				return false, errors.New("证书签发失败")
			}
			return false, nil
		}); err != nil {
			return nil, nil, err
		}
	}
	// 下载证书链(PEM)。
	req, _ := http.NewRequest("POST", certURL, bytes.NewReader(mustJWS(c, certURL)))
	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("Accept", "application/pem-certificate-chain")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	chain, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("证书下载失败: %s", resp.Status)
	}
	keyDER, err := x509.MarshalECPrivateKey(domKey)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return chain, privPEM, nil
}

// mustJWS: 证书下载用的 POST-as-GET JWS(失败返回空体, 调用方按状态码处理)。
func mustJWS(c *acmeClient, url string) []byte {
	b, err := c.jwsBody(url, nil, true)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// ---------- 证书落盘与续期 ----------

// writeAcmeCert: 写 certs/<域名>/fullchain.pem + privkey.pem(先写临时文件再改名)。
func writeAcmeCert(domain string, fullchainPEM, privkeyPEM []byte) error {
	dir := acmeCertDir(domain)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem.tmp"), fullchainPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem.tmp"), privkeyPEM, 0600); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(dir, "fullchain.pem.tmp"), filepath.Join(dir, "fullchain.pem")); err != nil {
		return err
	}
	return os.Rename(filepath.Join(dir, "privkey.pem.tmp"), filepath.Join(dir, "privkey.pem"))
}

// acmeCertMeta: 证书目录里的 meta.json——申请时的域名组与验证方式，供续期原样沿用。
// AutoRenew 为 nil（老证书无该字段）视为开；编辑弹窗可显式开关。
// Name 为用户备注名，只影响列表显示；目录与证书 ID 仍用首域名，改名绝不影响反代引用。
type acmeCertMeta struct {
	Domains   []string `json:"domains"`
	Method    string   `json:"method"`
	AutoRenew *bool    `json:"autoRenew,omitempty"`
	Name      string   `json:"name,omitempty"`
}

// acmeMetaForOrder: 续期/重新申请写 meta 时用——域名组与方式取本次值，
// 自动续签开关沿用旧 meta（用户在编辑里关掉的，续期不能悄悄开回去；新证书默认开）。
func acmeMetaForOrder(dir string, domains []string, method string) acmeCertMeta {
	m := acmeCertMeta{Domains: append([]string{}, domains...), Method: method}
	if old, ok := readAcmeMeta(dir); ok {
		if old.AutoRenew != nil {
			m.AutoRenew = old.AutoRenew
		}
		// 备注沿用旧 meta（续期/自动续期不丢用户备注）；本次申请带了新备注则覆盖。
		m.Name = strings.TrimSpace(old.Name)
	}
	if jobName := acmeJobPendingName(); jobName != "" {
		m.Name = jobName
	}
	return m
}

// acmeAutoRenewEnabled: 该证书是否允许自动续期（无 meta 或无字段都视为开）。
func acmeAutoRenewEnabled(dir string) bool {
	m, ok := readAcmeMeta(dir)
	if !ok || m.AutoRenew == nil {
		return true
	}
	return *m.AutoRenew
}

// writeAcmeMetaGuarded: 与落盘保护同一把锁，删标记检查后写 meta，避免删完又写回来。
func writeAcmeMetaGuarded(domain string, meta acmeCertMeta) error {
	acmeDeletedMu.Lock()
	defer acmeDeletedMu.Unlock()
	if acmeDeleted[domain] {
		return errors.New("证书在申请过程中被删除, 放弃写 meta")
	}
	if err := os.MkdirAll(acmeCertDir(domain), 0755); err != nil {
		return err
	}
	b, _ := json.Marshal(meta)
	return os.WriteFile(filepath.Join(acmeCertDir(domain), "meta.json"), b, 0644)
}

func readAcmeMeta(domain string) (acmeCertMeta, bool) {
	b, err := os.ReadFile(filepath.Join(acmeCertDir(domain), "meta.json"))
	if err != nil {
		return acmeCertMeta{}, false
	}
	var m acmeCertMeta
	if json.Unmarshal(b, &m) != nil || len(m.Domains) == 0 {
		return acmeCertMeta{}, false
	}
	if m.Method != "http-01" && m.Method != "dns-01" && m.Method != "nginx" {
		m.Method = "http-01"
	}
	return m, true
}

// acmeRenewalPlan: 续期按什么域名组、什么方式续；无 meta 的老证书默认单域名 http-01。
func acmeRenewalPlan(dir string) (domains []string, method string) {
	if m, ok := readAcmeMeta(dir); ok {
		return m.Domains, m.Method
	}
	return []string{dir}, "http-01"
}

// acmeCertExpiry: 读 fullchain.pem 首张证书的到期时间。
func acmeCertExpiry(domain string) (time.Time, error) {
	der, err := os.ReadFile(filepath.Join(acmeCertDir(domain), "fullchain.pem"))
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(der)
	if block == nil {
		return time.Time{}, errors.New("无证书块")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// acmeNeedsRenewal: 到期前 30 天内(或读不到到期时间)即需续期。
func acmeNeedsRenewal(domain string) bool {
	exp, err := acmeCertExpiry(domain)
	if err != nil {
		return true
	}
	return time.Until(exp) < 30*24*time.Hour
}

// acmeCertDomains: 现有 ACME 证书的域名列表。
func acmeCertDomains() []string {
	root := filepath.Join(dataDir, "certs")
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func refreshProxyCerts() {
	proxyMu.Lock()
	metas, serving := scanProxyCerts()
	proxyCerts = metas
	proxyServing = serving
	proxyMu.Unlock()
}

// ---------- 删除保护: 删域名时标记, 防止进行中的申请/续期把目录写回来 ----------
var (
	acmeDeletedMu sync.Mutex
	acmeDeleted   = map[string]bool{}
)

func acmeMarkDeleted(domain string) {
	acmeDeletedMu.Lock()
	defer acmeDeletedMu.Unlock()
	acmeDeleted[domain] = true
}

func acmeUnmarkDeleted(domain string) {
	acmeDeletedMu.Lock()
	defer acmeDeletedMu.Unlock()
	delete(acmeDeleted, domain)
}

func acmeIsDeleted(domain string) bool {
	acmeDeletedMu.Lock()
	defer acmeDeletedMu.Unlock()
	return acmeDeleted[domain]
}

// writeAcmeCertGuarded: 删标记检查与落盘串行化——删除流程持同一把锁先标记后删目录,
// 进行中的申请持锁先检查后落盘, 两者不可能交错出"删完又写回来"。
func writeAcmeCertGuarded(domain string, fullchainPEM, privkeyPEM []byte) error {
	acmeDeletedMu.Lock()
	defer acmeDeletedMu.Unlock()
	if acmeDeleted[domain] {
		return errors.New("证书在申请过程中被删除, 放弃落盘")
	}
	return writeAcmeCert(domain, fullchainPEM, privkeyPEM)
}

// deleteAcmeCertDir: 标记删除 + 删目录(持锁串行, 与进行中的落盘互斥)。
func deleteAcmeCertDir(domain string) {
	acmeDeletedMu.Lock()
	defer acmeDeletedMu.Unlock()
	acmeDeleted[domain] = true
	os.RemoveAll(acmeCertDir(domain))
}

// ---------- 申请任务(单飞行)与续期循环 ----------

type acmeJob struct {
	Running bool     `json:"running"`
	Domain  string   `json:"domain"` // 首域名（兼容老字段）
	Domains []string `json:"domains"`
	Method  string   `json:"method"` // 本次/上次任务的验证方式：http-01、dns-01 或 nginx
	LastOK  string   `json:"lastOk"`
	LastErr string   `json:"lastError"`
	Name    string   `json:"name,omitempty"` // 本次申请待写入的备注（续期/自动续期为空 = 沿用旧备注）
}

var (
	acmeJobMu sync.Mutex
	acmeJobSt acmeJob
)

func acmeJobSnapshot() acmeJob {
	acmeJobMu.Lock()
	defer acmeJobMu.Unlock()
	return acmeJobSt
}

// acmeClaimJob: 单飞行认领——调用方同步认领，杜绝“检查时空闲、起 goroutine 前又被抢”的竞态。
// 认领成功才设 Name（申请备注）；失败不碰任何字段。
func acmeClaimJob(domains []string, method, name string) bool {
	if len(domains) == 0 {
		return false
	}
	acmeJobMu.Lock()
	defer acmeJobMu.Unlock()
	if acmeJobSt.Running {
		return false
	}
	acmeJobSt.Running = true
	acmeJobSt.Domain = domains[0]
	acmeJobSt.Domains = append([]string{}, domains...)
	acmeJobSt.Method = method
	acmeJobSt.LastErr = ""
	acmeJobSt.Name = name
	return true
}

// acmeJobPendingName: 当前任务待写入的备注（acmeMetaForOrder 消费；无任务/续期时为空）。
func acmeJobPendingName() string {
	acmeJobMu.Lock()
	defer acmeJobMu.Unlock()
	return acmeJobSt.Name
}

// runAcmeOrder: 申请/续期一张证书（域名组共一张 SAN 证书，目录取首域名），
// 成功后写 meta、刷新证书表，并在面板用它时重建面板监听。
func runAcmeOrder(domains []string, method, cfToken string) error {
	if len(domains) == 0 {
		return errors.New("域名为空")
	}
	if !acmeClaimJob(domains, method, "") {
		return errors.New("已有证书申请在进行中")
	}
	return runAcmeOrderWork(domains, method, cfToken)
}

// runAcmeOrderWork: 订单实干（调用方须已认领且域名非空；结束时清 Running 与待写备注，防旧备注漏到下次续期）。
func runAcmeOrderWork(domains []string, method, cfToken string) error {
	dir := domains[0]
	defer func() {
		acmeJobMu.Lock()
		acmeJobSt.Running = false
		acmeJobSt.Name = ""
		acmeJobMu.Unlock()
	}()
	fail := func(err error) error {
		acmeJobMu.Lock()
		acmeJobSt.LastErr = err.Error()
		acmeJobMu.Unlock()
		return err
	}
	// nginx 方式：先装常驻代答块（幂等，无改动不 reload），再对命中块做临时改写；
	// 临时改写无论成败都在本函数返回时还原（defer），崩溃残留由启动自愈处理。
	if method == "nginx" {
		if _, err := nginxInstallDefault(); err != nil {
			return fail(fmt.Errorf("nginx 代答配置失败: %w", err))
		}
		restore, err := nginxTempEdit(domains)
		if err != nil {
			if restore != nil {
				restore() // reload 失败路径：尽力还原，失败则留给启动自愈
			}
			return fail(fmt.Errorf("nginx 临时改写失败: %w", err))
		}
		defer func() {
			if rerr := restore(); rerr != nil {
				fmt.Fprintln(os.Stderr, "nginx 临时改写还原失败:", rerr)
			}
		}()
	}
	client, err := newAcmeClient()
	if err != nil {
		return fail(err)
	}
	chain, priv, err := client.orderCert(domains, method, cfToken)
	if err != nil {
		return fail(err)
	}
	if err := writeAcmeCertGuarded(dir, chain, priv); err != nil {
		return fail(err)
	}
	// meta 写失败不致命：续期回落到单域名 http-01，记日志即可。
	// 自动续签开关沿用旧 meta（见 acmeMetaForOrder），不在这里丢掉用户设置。
	if err := writeAcmeMetaGuarded(dir, acmeMetaForOrder(dir, domains, method)); err != nil {
		fmt.Fprintln(os.Stderr, "acme meta write", dir, "failed:", err)
	}
	refreshProxyCerts()
	// 面板用了证书就重建监听：端口模式的构建期快照必须换新；域名模式下
	// 自动匹配（certID 为空）或显式选了这张时也重建，显式选了别张则不动。
	mu.Lock()
	mode := settings.PanelSSLMode
	certID := settings.PanelSSLCert
	mu.Unlock()
	rebuild := false
	if mode == "port" && certID == "acme:"+dir {
		rebuild = true
	} else if mode == "domain" && (certID == "" || certID == "acme:"+dir) {
		rebuild = true
	}
	if rebuild {
		go rebuildPanelServer()
	}
	acmeJobMu.Lock()
	acmeJobSt.LastOK = time.Now().Format("2006-01-02 15:04")
	acmeJobMu.Unlock()
	return nil
}

// acmeOrderFunc: 续期循环调的下单函数（变量，单测可拦截；申请入口直接调 runAcmeOrder）。
var acmeOrderFunc = runAcmeOrder

// acmeOrderWorkFunc: 申请/续期入口调的订单实干（变量，单测可拦截；调用方须先认领）。
var acmeOrderWorkFunc = runAcmeOrderWork

// acmeRenewalCheck: 跑一轮续期检查——自动续签关掉的跳过；已过期证书本来就在
// 续期范围内（acmeNeedsRenewal：到期前 30 天内或读不到到期时间即续），不用另加触发器。
func acmeRenewalCheck() {
	for _, d := range acmeCertDomains() {
		if !acmeAutoRenewEnabled(d) {
			continue
		}
		if !acmeNeedsRenewal(d) {
			continue
		}
		domains, method := acmeRenewalPlan(d)
		tok := ""
		if method == "dns-01" {
			tok = cfLoadToken()
		}
		if err := acmeOrderFunc(domains, method, tok); err != nil {
			fmt.Fprintln(os.Stderr, "acme renew", d, "failed:", err)
		}
	}
}

// acmeRenewalLoop: 面板启动时立即检查一次（不用等 6 小时），之后每 6 小时检查一次，
// 到期前 30 天自动续期；失败只记日志与任务状态，下个周期重试。
// 续期按 meta 原样沿用域名组与验证方式（无 meta 的老证书默认单域名 http-01）。
// 循环跑在 goroutine 里，不阻塞面板启动；续期成功后的面板重建本身也是异步的。
func acmeRenewalLoop() {
	acmeRenewalCheck()
	for {
		time.Sleep(6 * time.Hour)
		acmeRenewalCheck()
	}
}

// ---------- 申请入参解析（纯函数，可单测） ----------

type acmeApplyInput struct {
	Domain  string   `json:"domain"`  // 老单字段兼容
	Domains []string `json:"domains"` // 新多行域名
	Method  string   `json:"method"`  // auto | http-01 | dns-01，空 = auto
	CFToken string   `json:"cfToken"`
	Name    string   `json:"name"` // 备注名，空 = 不指定
}

// resolveCFToken: 显式新 Token 优先（星号占位 = 未改动，用已存的），否则用已存 Token。
func resolveCFToken(explicit, stored string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" && explicit != tgTokenMask {
		return explicit
	}
	return strings.TrimSpace(stored)
}

// resolveAcmeApply: 域名归一去重 + 验证方式解析。
// 自动：80 空闲走 HTTP-01，80 被占走 DNS-01（保持原样，不悄悄改成 nginx）；
// 显式 HTTP-01 但 80 被占时报错说明；走 DNS-01 但无 Token 时报错说明；
// nginx 代答不占 80、不用 Token；通配符域名只能用 DNS-01（CA 不给通配符发 http-01）。
// 任何分支都只说缺什么、怎么补，不留死胡同。
func resolveAcmeApply(in acmeApplyInput, port80OK bool, storedToken string) (domains []string, method, token string, err error) {
	raw := append([]string{}, in.Domains...)
	if len(raw) == 0 && in.Domain != "" {
		raw = []string{in.Domain}
	}
	seen := map[string]bool{}
	hasWildcard := false
	for _, d := range raw {
		nd, nerr := normalizeDomain(d)
		if nerr != nil || nd == "" {
			return nil, "", "", fmt.Errorf("域名无效: %s", strings.TrimSpace(d))
		}
		if strings.HasPrefix(nd, "*.") {
			hasWildcard = true
		}
		if !seen[nd] {
			seen[nd] = true
			domains = append(domains, nd)
		}
	}
	if len(domains) == 0 {
		return nil, "", "", errors.New("请填写域名")
	}
	if len(domains) > 100 {
		return nil, "", "", errors.New("域名过多（最多 100 个）")
	}
	m := strings.ToLower(strings.TrimSpace(in.Method))
	if m == "" {
		m = "auto"
	}
	if m != "auto" && m != "http-01" && m != "dns-01" && m != "nginx" {
		return nil, "", "", errors.New("未知的验证方式")
	}
	switch m {
	case "nginx":
		if hasWildcard {
			return nil, "", "", errors.New("通配符域名只能用 DNS-01 验证，nginx 代答与 HTTP-01 拿不到通配符证书")
		}
		return domains, "nginx", "", nil
	case "http-01":
		if hasWildcard {
			return nil, "", "", errors.New("通配符域名只能用 DNS-01 验证")
		}
		if !port80OK {
			return nil, "", "", errors.New("80 端口被占用，HTTP-01 无法验证：请改选自动（自动走 DNS-01）、DNS-01 或 nginx 代答，或先释放 80 端口")
		}
		return domains, "http-01", "", nil
	case "dns-01":
		tok := resolveCFToken(in.CFToken, storedToken)
		if tok == "" {
			return nil, "", "", errors.New("DNS-01 需要 Cloudflare API Token：请填写 Token 后再申请")
		}
		return domains, "dns-01", tok, nil
	default: // auto
		if hasWildcard {
			tok := resolveCFToken(in.CFToken, storedToken)
			if tok == "" {
				return nil, "", "", errors.New("通配符域名只能用 DNS-01 验证，请填写 Cloudflare API Token 后再申请")
			}
			return domains, "dns-01", tok, nil
		}
		if port80OK {
			return domains, "http-01", "", nil
		}
		tok := resolveCFToken(in.CFToken, storedToken)
		if tok == "" {
			return nil, "", "", errors.New("80 端口被占用，已自动切换到 DNS-01，但未填写 Cloudflare API Token：请填写 Token 后再申请")
		}
		return domains, "dns-01", tok, nil
	}
}

// ---------- 接口 ----------

func handleAcmeApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in acmeApplyInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	domains, method, token, err := resolveAcmeApply(in, frontPort80OK(), cfLoadToken())
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	// 备注名：空 = 不指定（新证书默认显示首域名，重新申请沿用旧备注）；非空须合法且未被占用。
	remark := strings.TrimSpace(in.Name)
	if remark != "" {
		if err := validateCertRemark(remark); err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		rescanProxyCertsLocked()
		if certDisplayNameTaken(remark, "acme:"+domains[0]) {
			errJSON(w, 400, "证书名称已被使用")
			return
		}
	}
	acmeJobMu.Lock()
	running := acmeJobSt.Running
	acmeJobMu.Unlock()
	if running {
		errJSON(w, 409, "已有证书申请在进行中")
		return
	}
	// nginx 方式：发单前先同步安装常驻代答块并两路自测，任一步失败都不发单；
	// 命中块的临时改写在任务内做（runAcmeOrder），不在这里做。
	if method == "nginx" {
		if _, err := nginxInstallDefaultAndProbe(); err != nil {
			errJSON(w, 400, "nginx 代答配置失败: "+err.Error())
			return
		}
	}
	// 新填的 Token 一并保存，供续期使用；保存失败不拦本次申请。
	if strings.TrimSpace(in.CFToken) != "" && strings.TrimSpace(in.CFToken) != tgTokenMask {
		if err := cfSaveToken(in.CFToken); err != nil {
			fmt.Fprintln(os.Stderr, "acme cf token save failed:", err)
		}
	}
	acmeUnmarkDeleted(domains[0]) // 用户显式重新申请: 清除删除标记
	// 同步认领后再起任务（认领失败 = 方才检查后又被抢，同样 409）。
	if !acmeClaimJob(domains, method, remark) {
		errJSON(w, 409, "已有证书申请在进行中")
		return
	}
	go acmeOrderWorkFunc(domains, method, token)
	writeJSON(w, 200, map[string]any{"started": true, "domains": domains, "method": method})
}

// handleAcmeRenew: 手动立即续期——不看到期时间（点了就是要现在换），不看自动续签开关
// （手动一次与自动无关）；域名组与方式按 meta 原样沿用（无 meta 的老证书默认单域名 http-01）。
// 单飞行，忙时 409；续期本身走与申请同一条订单路径（含面板重建）。
func handleAcmeRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || strings.TrimSpace(in.ID) == "" {
		errJSON(w, 400, "请求无效")
		return
	}
	if !strings.HasPrefix(in.ID, "acme:") {
		errJSON(w, 400, "只有 ACME 证书可以立即续期")
		return
	}
	domain := strings.TrimPrefix(in.ID, "acme:")
	nd, nerr := normalizeDomain(domain)
	if nerr != nil || nd == "" || nd != domain {
		errJSON(w, 400, "域名无效")
		return
	}
	rescanProxyCertsLocked()
	if _, ok := findProxyCertMeta(in.ID); !ok {
		errJSON(w, 400, "证书不存在")
		return
	}
	domains, method := acmeRenewalPlan(domain)
	tok := ""
	if method == "dns-01" {
		tok = cfLoadToken()
		if tok == "" {
			errJSON(w, 400, "DNS-01 续期需要 Cloudflare API Token：请先在编辑里填写 Token")
			return
		}
	}
	if method == "nginx" {
		if _, err := nginxInstallDefaultAndProbe(); err != nil {
			errJSON(w, 400, "nginx 代答配置失败: "+err.Error())
			return
		}
	}
	if !acmeClaimJob(domains, method, "") {
		errJSON(w, 409, "已有证书申请在进行中")
		return
	}
	go acmeOrderWorkFunc(domains, method, tok)
	writeJSON(w, 200, map[string]any{"started": true, "domains": domains, "method": method})
}

func handleAcmeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	j := acmeJobSnapshot()
	writeJSON(w, 200, map[string]any{
		"running": j.Running, "domain": j.Domain, "domains": j.Domains, "method": j.Method,
		"lastOk": j.LastOK, "lastError": j.LastErr,
		"port80OK": frontPort80OK(),
	})
}
