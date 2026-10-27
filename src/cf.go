package main

// Cloudflare DNS-01: 纯标准库 API v4 客户端 + DoH TXT 生效确认。
// Token 只存服务器本地 certs/cf-token(0600)，独立接口读写，绝不进通用设置保存流程；
// 读接口只返回星号占位（与 Bot Token 同一套前后端约定：原样回传 = 未改动）。
// DNS-01 续期也靠这份 Token，申请时新填的 Token 会一并保存，供续期使用。

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 可测试变量：API 与 DoH 地址、轮询间隔与超时（测试用 httptest 覆盖）。
var (
	cfAPIBase      = "https://api.cloudflare.com/client/v4"
	cfDoHBase      = "https://cloudflare-dns.com/dns-query"
	cfDoHPollEvery = 5 * time.Second
	cfDoHTimeout   = 120 * time.Second
)

// ---------- Token 存取（独立文件，不进通用设置） ----------

func cfTokenPath() string { return filepath.Join(dataDir, "certs", "cf-token") }

func cfLoadToken() string {
	b, err := os.ReadFile(cfTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func cfSaveToken(tok string) error {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		os.Remove(cfTokenPath())
		return nil
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "certs"), 0755); err != nil {
		return err
	}
	return os.WriteFile(cfTokenPath(), []byte(tok), 0600)
}

func cfTokenConfigured() bool { return cfLoadToken() != "" }

// ---------- API v4 客户端 ----------

type cfClient struct {
	token string
	http  *http.Client
	base  string
}

func newCFClient(token string) *cfClient {
	return &cfClient{token: token, http: &http.Client{Timeout: 30 * time.Second}, base: cfAPIBase}
}

type cfAPIResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *cfClient) do(method, path string, payload any) (json.RawMessage, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var r cfAPIResp
	if json.Unmarshal(b, &r) != nil {
		return nil, fmt.Errorf("Cloudflare 返回无法解析: %s", resp.Status)
	}
	if !r.Success {
		msgs := []string{}
		for _, e := range r.Errors {
			if e.Message != "" {
				msgs = append(msgs, e.Message)
			}
		}
		if len(msgs) == 0 {
			msgs = append(msgs, resp.Status)
		}
		return nil, fmt.Errorf("Cloudflare API 失败: %s", strings.Join(msgs, "; "))
	}
	return r.Result, nil
}

// dns01BaseDomain: 通配符 *.example.com 的 DNS-01 落在 example.com 上。
func dns01BaseDomain(domain string) string { return strings.TrimPrefix(domain, "*.") }

// findZoneID: 按域名找最长匹配的托管 zone（子域名归属父 zone，如 a.b.example.com → example.com）。
func (c *cfClient) findZoneID(domain string) (string, error) {
	raw, err := c.do("GET", "/zones?per_page=100", nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &zones) != nil {
		return "", errors.New("Cloudflare zone 列表解析失败")
	}
	base := strings.ToLower(dns01BaseDomain(domain))
	best, bestLen := "", -1
	for _, z := range zones {
		zn := strings.ToLower(z.Name)
		if base == zn || strings.HasSuffix(base, "."+zn) {
			if len(zn) > bestLen {
				best, bestLen = z.ID, len(zn)
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("Cloudflare 未找到域名 %s 的托管 zone（域名须托管到 Cloudflare）", domain)
	}
	return best, nil
}

func (c *cfClient) createTXT(zoneID, name, value string) (string, error) {
	raw, err := c.do("POST", "/zones/"+zoneID+"/dns_records", map[string]any{
		"type": "TXT", "name": name, "content": value, "ttl": 120, "proxied": false,
	})
	if err != nil {
		return "", err
	}
	var res struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &res) != nil || res.ID == "" {
		return "", errors.New("Cloudflare 未返回 TXT 记录 ID")
	}
	return res.ID, nil
}

func (c *cfClient) deleteTXT(zoneID, recordID string) error {
	_, err := c.do("DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil)
	return err
}

// ---------- DNS-01 计算与生效确认 ----------

// dns01RecordName: 验证记录名（通配符与根域名共用一条 _acme-challenge 记录名）。
func dns01RecordName(domain string) string {
	return "_acme-challenge." + dns01BaseDomain(domain)
}

// dns01TXTValue: RFC 8555 DNS-01 值 = base64url(SHA256(token + "." + thumbprint))。
func dns01TXTValue(token, thumbprint string) string {
	sum := sha256.Sum256([]byte(token + "." + thumbprint))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// cfDoHHasTXT: 经 Cloudflare DoH 查一条 TXT 是否已生效（值可能被拆成多段引号字符串）。
func cfDoHHasTXT(name, value string) bool {
	req, err := http.NewRequest("GET", cfDoHBase+"?name="+url.QueryEscape(name)+"&type=TXT", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var dr struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.NewDecoder(resp.Body).Decode(&dr) != nil {
		return false
	}
	for _, a := range dr.Answer {
		joined := strings.ReplaceAll(strings.Join(strings.Fields(a.Data), ""), `"`, "")
		if joined == value {
			return true
		}
	}
	return false
}

// cfWaitTXT: 轮询 DoH 直到 TXT 生效，超时报错（触发验证前必须确认，否则 CA 查不到就判失败）。
func cfWaitTXT(name, value string) error {
	deadline := time.Now().Add(cfDoHTimeout)
	for {
		if cfDoHHasTXT(name, value) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("DNS TXT 记录未生效（超时）：%s，请确认域名已托管到 Cloudflare", name)
		}
		time.Sleep(cfDoHPollEvery)
	}
}

// ---------- Token 独立接口（读遮蔽/写保存） ----------

func handleCFToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if cfTokenConfigured() {
			writeJSON(w, 200, map[string]any{"configured": true, "token": tgTokenMask})
		} else {
			writeJSON(w, 200, map[string]any{"configured": false, "token": ""})
		}
	case "POST":
		var in struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		tok := strings.TrimSpace(in.Token)
		if tok == tgTokenMask {
			writeJSON(w, 200, map[string]any{"ok": true, "configured": true})
			return
		}
		if err := cfSaveToken(tok); err != nil {
			errJSON(w, 500, "保存 Token 失败")
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "configured": tok != ""})
	default:
		errJSON(w, 405, "method")
	}
}
