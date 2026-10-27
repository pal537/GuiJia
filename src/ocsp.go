package main

// 证书吊销检查（OCSP，golang.org/x/crypto/ocsp）：
//   - 刷新按钮触发时实时查一次；列表加载时只读缓存，不阻塞等网络。
//   - 状态三档：good（有效）/ revoked（已吊销，写缓存）/ unknown（查不到或失败，
//     绝不凭猜测标吊销，刷新结果里注明“吊销未确认”）。
//   - 缓存绑定证书序列号：续期换证后序列号变了，旧缓存自动失效，不会误标新证。
//   - issuer 取 fullchain 第二张；只有一张时走 AIA caIssuers 拉取，拉不到则跳过。

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ocsp"
)

// 可测试变量：OCSP 请求超时（测试可调小）。
var ocspHTTPTimeout = 10 * time.Second

// ocspCacheFile: certs/<目录>/ocsp.json（ACME）或 certs/<名>.ocsp.json（上传）。
type ocspCacheFile struct {
	Status    string `json:"status"`    // "good" | "revoked"
	Serial    string `json:"serial"`    // 叶子证书序列号（十进制字符串）
	CheckedAt string `json:"checkedAt"` // "2006-01-02 15:04"
}

// ocspCachePathFor: 按证书来源定缓存路径（上传证书没有独立目录，用同名 .ocsp.json 避免互串）。
func ocspCachePathFor(source, dir, name string) string {
	if source == "acme" {
		return filepath.Join(dir, "ocsp.json")
	}
	return filepath.Join(dir, name+".ocsp.json")
}

// readOCSPCache: 只有序列号与当前叶子一致的缓存才有效。
func readOCSPCache(path string, leaf *x509.Certificate) (ocspCacheFile, bool) {
	var c ocspCacheFile
	b, err := os.ReadFile(path)
	if err != nil {
		return c, false
	}
	if json.Unmarshal(b, &c) != nil {
		return ocspCacheFile{}, false
	}
	if c.Status != "good" && c.Status != "revoked" {
		return ocspCacheFile{}, false
	}
	if leaf == nil || c.Serial != leaf.SerialNumber.String() {
		return ocspCacheFile{}, false
	}
	return c, true
}

// writeOCSPCache: 只缓存 good / revoked，unknown 不落盘（下次刷新再查）。
func writeOCSPCache(path string, leaf *x509.Certificate, status string) error {
	if status != "good" && status != "revoked" {
		return errors.New("unknown 不缓存")
	}
	if leaf == nil {
		return errors.New("无叶子证书")
	}
	c := ocspCacheFile{
		Status:    status,
		Serial:    leaf.SerialNumber.String(),
		CheckedAt: time.Now().Format("2006-01-02 15:04"),
	}
	b, _ := json.Marshal(c)
	return os.WriteFile(path, b, 0644)
}

// parseCertChainPEM: 解析 PEM 里的全部证书块（fullchain：首张 leaf，其后 issuer）。
func parseCertChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{}
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, errors.New("无证书块")
	}
	return chain, nil
}

// ocspIssuerFor: fullchain 第二张即 issuer；只有一张时走 AIA caIssuers 拉取。
func ocspIssuerFor(leaf *x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	if len(chain) > 1 {
		return chain[1]
	}
	client := &http.Client{Timeout: ocspHTTPTimeout}
	for _, u := range leaf.IssuingCertificateURL {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		der, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			return cert
		}
		if block, _ := pem.Decode(der); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				return cert
			}
		}
	}
	return nil
}

// ocspCheckLeaf: 对一张叶子证书查 OCSP。返回 good / revoked / unknown；
// unknown 含“无 OCSP 地址、无 issuer、网络或解析失败”，调用方不得据此标吊销。
func ocspCheckLeaf(leaf, issuer *x509.Certificate) (string, error) {
	if leaf == nil || issuer == nil {
		return "unknown", errors.New("无叶子或 issuer 证书")
	}
	if len(leaf.OCSPServer) == 0 {
		return "unknown", errors.New("叶子证书无 OCSP 地址")
	}
	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return "unknown", err
	}
	client := &http.Client{Timeout: ocspHTTPTimeout}
	resp, err := client.Post(leaf.OCSPServer[0], "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return "unknown", err
	}
	defer resp.Body.Close()
	der, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "unknown", err
	}
	parsed, err := ocsp.ParseResponse(der, issuer)
	if err != nil {
		return "unknown", err
	}
	// 响应必须对应本张叶子证书，串证的响应不算数。
	if parsed.SerialNumber == nil || parsed.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return "unknown", errors.New("OCSP 响应序列号与叶子证书不符")
	}
	switch parsed.Status {
	case ocsp.Good:
		return "good", nil
	case ocsp.Revoked:
		return "revoked", nil
	default:
		return "unknown", nil
	}
}

// ocspCheckForFile: 对证书文件查吊销（供刷新按钮用）。返回状态与中文备注，
// unknown 时备注“吊销未确认”；调用方不得把 unknown 当失败处理。
func ocspCheckForFile(crtPath string) (status, note string) {
	pemBytes, err := os.ReadFile(crtPath)
	if err != nil {
		return "unknown", "吊销未确认（读证书失败）"
	}
	chain, err := parseCertChainPEM(pemBytes)
	if err != nil || len(chain) == 0 {
		return "unknown", "吊销未确认（解析证书失败）"
	}
	leaf := chain[0]
	issuer := ocspIssuerFor(leaf, chain)
	if issuer == nil {
		return "unknown", "吊销未确认（找不到 issuer 证书）"
	}
	st, err := ocspCheckLeaf(leaf, issuer)
	if err != nil {
		return "unknown", "吊销未确认（" + err.Error() + "）"
	}
	switch st {
	case "good":
		return "good", ""
	case "revoked":
		return "revoked", "该证书已被吊销"
	default:
		return "unknown", "吊销未确认"
	}
}

// ocspStatusForMeta: 列表状态判定——先看过期，再看序列号匹配的吊销缓存。
func ocspStatusForMeta(meta *ProxyCertMeta, leaf *x509.Certificate) {
	meta.Status = "valid"
	meta.OCSPCheckedAt = ""
	if meta.Expired {
		meta.Status = "expired"
		return
	}
	if leaf == nil {
		return
	}
	cache, ok := readOCSPCache(ocspCachePathFor(meta.Source, meta.Dir, meta.Name), leaf)
	if !ok {
		return
	}
	meta.OCSPCheckedAt = cache.CheckedAt
	if cache.Status == "revoked" {
		meta.Status = "revoked"
	}
}

// certLeafByPath: 读证书文件首张（供刷新写缓存时取序列号）。
func certLeafByPath(crtPath string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, err
	}
	chain, err := parseCertChainPEM(pemBytes)
	if err != nil || len(chain) == 0 {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}
	return chain[0], nil
}

// certLeafSerialString: 叶子序列号（缓存绑定用），读不到则为空（缓存自然失效）。
func certLeafSerialString(crtPath string) string {
	leaf, err := certLeafByPath(crtPath)
	if err != nil {
		return ""
	}
	return leaf.SerialNumber.String()
}
