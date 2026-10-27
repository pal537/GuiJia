package main

// 证书编辑与刷新（反代页证书列表每行的 [编辑] / [刷新] 用）：
//   - 编辑 ACME 证书：自动续签开关（落 meta.json，续期沿用）、Cloudflare Token
//     （空 = 不改，填了 = 更新全局 certs/cf-token，绝不明文回显）。
//   - 编辑上传证书：替换证书与私钥内容（先写临时文件成对校验，校验不过原文件不动）。
//   - 刷新：重读证书文件（到期、SAN）+ 实时 OCSP 查吊销；OCSP 失败绝不阻断刷新本身，
//     结果里注明“吊销未确认”，绝不凭猜测标吊销。

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// rescanProxyCertsLocked: 刷新证书表（调用方不持锁；与上传 handler 同一模式）。
func rescanProxyCertsLocked() {
	proxyMu.Lock()
	metas, serving := scanProxyCerts()
	proxyCerts = metas
	proxyServing = serving
	proxyMu.Unlock()
}

func findProxyCertMeta(id string) (ProxyCertMeta, bool) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for _, c := range proxyCerts {
		if c.ID == id {
			return c, true
		}
	}
	return ProxyCertMeta{}, false
}

// ---------- 刷新 ----------

func handleProxyCertRefresh(w http.ResponseWriter, r *http.Request) {
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
	// 先重读文件（到期、SAN），再找目标证书。
	rescanProxyCertsLocked()
	meta, ok := findProxyCertMeta(in.ID)
	if !ok {
		errJSON(w, 400, "证书不存在")
		return
	}
	// 实时 OCSP 查吊销（不持锁做网络请求）；失败不阻断刷新，只注明未确认。
	ocspStatus, ocspNote := ocspCheckForFile(meta.Path)
	if ocspStatus == "good" || ocspStatus == "revoked" {
		if leaf, err := certLeafByPath(meta.Path); err == nil {
			_ = writeOCSPCache(ocspCachePathFor(meta.Source, meta.Dir, meta.Name), leaf, ocspStatus)
		}
	}
	// 写缓存后重读，列表状态（有效/过期/吊销）即最新。
	rescanProxyCertsLocked()
	meta, ok = findProxyCertMeta(in.ID)
	if !ok {
		errJSON(w, 400, "证书不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cert": meta, "ocsp": ocspStatus, "note": ocspNote})
}

// ---------- 编辑 ----------

func handleProxyCertEdit(w http.ResponseWriter, r *http.Request, id string) {
	// 先重读证书表：编辑 ACME 元数据兜底时要读列表里的 SAN 与方式，不能用过期内存表。
	rescanProxyCertsLocked()
	var in struct {
		AutoRenew *bool   `json:"autoRenew"`
		CFToken   *string `json:"cfToken"`
		Crt       *string `json:"crt"`
		Key       *string `json:"key"`
	}
	body, _ := io.ReadAll(r.Body)
	if json.Unmarshal(body, &in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	switch {
	case strings.HasPrefix(id, "acme:"):
		domain := strings.TrimPrefix(id, "acme:")
		nd, nerr := normalizeDomain(domain)
		if nerr != nil || nd == "" || nd != domain {
			errJSON(w, 400, "域名无效")
			return
		}
		if in.Crt != nil || in.Key != nil {
			errJSON(w, 400, "ACME 证书不支持替换内容，请走续期或重新申请")
			return
		}
		if err := editAcmeCertMeta(id, domain, in.AutoRenew); err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		// Token 由全部 DNS-01 证书共用：空 = 不改，星号占位 = 不改，填了 = 更新全局。
		if in.CFToken != nil {
			tok := strings.TrimSpace(*in.CFToken)
			if tok != "" && tok != tgTokenMask {
				if err := cfSaveToken(tok); err != nil {
					errJSON(w, 500, "保存 Token 失败")
					return
				}
			}
		}
	case strings.HasPrefix(id, "upload:"):
		name := strings.TrimPrefix(id, "upload:")
		if name == "" || !proxyCertNameRe.MatchString(name) || strings.Contains(name, "..") {
			errJSON(w, 400, "证书名称无效")
			return
		}
		if in.Crt != nil || in.Key != nil {
			crt := ""
			key := ""
			if in.Crt != nil {
				crt = strings.TrimSpace(*in.Crt)
			}
			if in.Key != nil {
				key = strings.TrimSpace(*in.Key)
			}
			if crt == "" || key == "" {
				errJSON(w, 400, "请同时填写证书与私钥内容")
				return
			}
			if err := replaceUploadCert(name, []byte(crt), []byte(key)); err != nil {
				errJSON(w, 400, err.Error())
				return
			}
		}
	default:
		errJSON(w, 400, "扫描到的证书不可在此编辑")
		return
	}
	rescanProxyCertsLocked()
	meta, ok := findProxyCertMeta(id)
	if !ok {
		errJSON(w, 400, "证书不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cert": meta})
}

// editAcmeCertMeta: 只改自动续签开关，其余字段原样保留；老证书无 meta 时
// 用列表里的 SAN 与方式兜底建一个（方式未知则 http-01，与续期回落一致）。
func editAcmeCertMeta(id, domain string, autoRenew *bool) error {
	if autoRenew == nil {
		return nil // 本次没改开关
	}
	m, ok := readAcmeMeta(domain)
	if !ok {
		listMeta, found := findProxyCertMeta(id)
		domains := []string{domain}
		method := "http-01"
		if found {
			if len(listMeta.DNSNames) > 0 {
				domains = append([]string{}, listMeta.DNSNames...)
			}
			if listMeta.Method != "" {
				method = listMeta.Method
			}
		}
		m = acmeCertMeta{Domains: domains, Method: method}
	}
	m.AutoRenew = autoRenew
	if err := writeAcmeMetaGuarded(domain, m); err != nil {
		return err
	}
	return nil
}

// replaceUploadCert: 替换上传证书——先写临时文件成对校验，校验不过原文件不动；
// 校验通过才 rename 覆盖（crt 0644、key 0600）。
func replaceUploadCert(name string, crtPEM, keyPEM []byte) error {
	dir := filepath.Join(dataDir, "certs")
	crtPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	crtTmp := crtPath + ".tmp"
	keyTmp := keyPath + ".tmp"
	if err := os.WriteFile(crtTmp, crtPEM, 0644); err != nil {
		return err
	}
	defer os.Remove(crtTmp)
	if err := os.WriteFile(keyTmp, keyPEM, 0600); err != nil {
		return err
	}
	defer os.Remove(keyTmp)
	if _, _, err := parseProxyCertPair(crtTmp, keyTmp, "upload:"+name, name, "upload", dir); err != nil {
		return fmt.Errorf("证书与私钥不成对或格式无效: %w", err)
	}
	if err := os.Rename(crtTmp, crtPath); err != nil {
		return err
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		return errors.New("替换私钥失败")
	}
	return nil
}
