package main

// 反代(reverse proxy): 公网服务器场景。
// 模型: 规则 = 域名 + 若干监听(端口+协议) + 证书 + 内网后端;
// 证书下拉常驻表单, 仅 HTTPS 监听使用, 默认按域名自动挑好, 也可手动任选。
// 无全局开关: 添加规则即启用, 规则自带启用/停用; 绑定失败只在规则状态里报错,
// 不会拖垮主应用与其他端口。
// 核心只用 Go 标准库 httputil.ReverseProxy, 路由/SNI/证书层自己做, 不引入第三方依赖;
// ACME 在线申请见 acme.go, 不做 DNS-01。
// 证书来源: (1)页面上传, 存数据目录 certs/ 子目录;
// (2)ACME 在线申请, 按域名分子目录存放(见 acme.go); 扫描不到也不报错。
// 状态: 规则存数据目录 proxy.json(缺失即默认值), 不动 settings.json 的现有键;
// 后端可达状态只放内存不落盘, 证书私钥内容绝不经 API 外泄。

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- 数据模型 ----------

// 一条监听: 入站端口 + 该端口的协议(HTTP/HTTPS 二选一)。
type ProxyListen struct {
	Port     int    `json:"port"`     // 入站端口, 必填, 1-65535, 无默认, 不限高低
	Protocol string `json:"protocol"` // "http" | "https"
}

// 反代规则(1.8.3 模型): 入站 = 域名 + 若干监听, 后端 = 内网 host:port;
// 只代理到内网已有应用, 不做静态文件搭建与重定向。
type ProxyRule struct {
	ID      string        `json:"id"`
	Domain  string        `json:"domain"` // 已归一化(小写、去端口、去尾点)
	Name    string        `json:"name"`   // 应用名称, 可空, 仅列表展示
	Listens []ProxyListen `json:"listens"`
	Cert    string        `json:"cert"`    // "auto" 或证书 ID; 含 HTTPS 监听时必填, 纯 HTTP 监听忽略
	Backend string        `json:"backend"` // 已归一化为 host:port, 必填
	Enabled bool          `json:"enabled"`
}

// UnmarshalJSON: 兼容 1.8.1 及更早形状(单端口 port/protocol 字段转成 listens;
// 全局 enabled 与旧 redirectPort 字段已废弃, 直接忽略)。
func (r *ProxyRule) UnmarshalJSON(b []byte) error {
	type plain ProxyRule
	var v struct {
		plain
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*r = ProxyRule(v.plain)
	if len(r.Listens) == 0 && v.Port > 0 {
		r.Listens = []ProxyListen{{Port: v.Port, Protocol: v.Protocol}}
	}
	return nil
}

type ProxyConfig struct {
	Rules []*ProxyRule `json:"rules"`
}

func defaultProxyConfig() ProxyConfig {
	return ProxyConfig{Rules: []*ProxyRule{}}
}

// applyProxyRuleDefaults: 公网版默认值——监听为空即 443 HTTPS, 证书为空即 auto。
// 在保存(loadProxy/handleProxy)时物化; 校验层仍严格要求监听非空,
// 因此直接调 validateProxyConfig 的旧数据与旧测试行为不受影响。
func applyProxyRuleDefaults(r *ProxyRule) {
	if r == nil {
		return
	}
	if len(r.Listens) == 0 {
		r.Listens = []ProxyListen{{Port: 443, Protocol: "https"}}
	}
	hasHTTPS := false
	for _, l := range r.Listens {
		if l.Protocol == "https" {
			hasHTTPS = true
			break
		}
	}
	if hasHTTPS && r.Cert == "" {
		r.Cert = "auto"
	}
}

// 证书元数据(API 只返回这些, 绝不返回私钥内容)
type ProxyCertMeta struct {
	ID       string   `json:"id"`       // 上传: "upload:"+名; 在线申请: "acme:"+首域名
	Name     string   `json:"name"`     // 显示名(去掉 .crt 的文件名, ACME 则为域名或备注名)
	Remark   string   `json:"remark,omitempty"` // ACME 备注原值（无备注为空）；编辑弹窗预填用，列表显示仍用 Name
	Source   string   `json:"source"`   // "upload" | "acme"
	Dir      string   `json:"dir"`      // 所在目录
	Path     string   `json:"path"`     // crt 全路径
	DNSNames []string `json:"dnsNames"` // SAN DNS
	IPs      []string `json:"ips"`      // SAN IP
	NotAfter string   `json:"notAfter"` // 到期时间, 格式 2006-01-02 15:04
	Expired  bool     `json:"expired"`
	// 证书状态列：valid（有效）/ expired（已过期）/ revoked（已吊销，序列号匹配的 OCSP 缓存）。
	Status        string `json:"status"`
	OCSPCheckedAt string `json:"ocspCheckedAt,omitempty"` // 吊销缓存的检查时间（无缓存则空）
	Method        string `json:"method,omitempty"`        // ACME 证书的验证方式（http-01/dns-01/nginx）；上传为空
	AutoRenew     bool   `json:"autoRenew"`               // ACME 证书的自动续签开关（无 meta 字段视为开）；上传无意义，恒 false
	// 查看弹窗用（扫描时从叶子证书解析，绝不含私钥）。
	Issuer      string `json:"issuer,omitempty"`      // 签发者
	Subject     string `json:"subject,omitempty"`     // 主题
	NotBefore   string `json:"notBefore,omitempty"`   // 有效期起，格式 2006-01-02 15:04
	Serial      string `json:"serial,omitempty"`      // 序列号（十进制）
	Fingerprint string `json:"fingerprint,omitempty"` // 叶子 SHA256 指纹（小写 hex）
}

type proxyCertEntry struct {
	meta ProxyCertMeta
	cert tls.Certificate
	leaf *x509.Certificate
}

type proxyBackendStatus struct {
	OK        bool   `json:"ok"`
	CheckedAt int64  `json:"checkedAt"` // 毫秒时间戳
	Err       string `json:"err,omitempty"`
}

var (
	proxyFile          string
	proxyCfg           = defaultProxyConfig()
	proxyMu            sync.Mutex
	proxyCerts         []ProxyCertMeta                   // 扫描结果(含已过期, 仅元数据)
	proxyServing       = map[string]*proxyCertEntry{}    // 可用于握手的证书(有效密钥对)
	proxyBackend       = map[string]proxyBackendStatus{} // 规则 ID -> 后端可达状态(内存)
	proxyServers       = map[int]*http.Server{}          // 入站端口 -> 监听服务
	proxyPortProto     = map[int]string{}                // 入站端口 -> 协议
	proxyPortErr       = map[int]string{}                // 入站端口 -> 绑定错误(仅失败端口有)
	proxyTakeover      = map[int]map[string]bool{}       // 入站端口 -> nginx 已接管的规则域名集合（仅绑定冲突且检测命中时有；443 走 front443Takeover）
	proxyConflictPorts = map[int]bool{}                  // 入站端口 -> 是否绑定失败为 address already in use（本轮 apply 绑定结果）
	proxyManaged       = map[int]map[string]bool{}       // 入站端口 -> 面板已生成 vhost 的规则域名集合（nginx_proxy.go 维护）
	proxyGenErr        = map[string]string{}             // 规则域名 -> vhost 生成/同步失败原因（仅失败规则有）
)

func loadProxy() {
	proxyCfg = defaultProxyConfig()
	if b, err := os.ReadFile(proxyFile); err == nil {
		json.Unmarshal(b, &proxyCfg)
	}
	if proxyCfg.Rules == nil {
		proxyCfg.Rules = []*ProxyRule{}
	}
	// 旧格式兼容: 1.8.1 的单端口规则已由 UnmarshalJSON 转成 listens;
	// 无监听的规则(1.8.0 无端口规则等)与无后端的规则(1.8.2 及更早的纯重定向规则)
	// 直接忽略, 不悄悄分配端口, 不留无后端监听;
	// 忽略后把清理结果写回文件, 下次不再重复处理。
	kept := []*ProxyRule{}
	dropped := 0
	for _, r := range proxyCfg.Rules {
		if r == nil || len(r.Listens) == 0 || strings.TrimSpace(r.Backend) == "" {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	if dropped > 0 {
		log.Printf("反代: 忽略 %d 条旧规则(无监听或无后端)", dropped)
		proxyCfg.Rules = kept
		if proxyFile != "" {
			saveProxy()
		}
	}
	// 注意顺序: 默认值必须在旧规则丢弃之后物化, 否则无监听旧规则会被
	// “修好”成 443 从而逃过丢弃(回归: TestLoadProxyDropsOldRules)。
	for _, r := range proxyCfg.Rules {
		applyProxyRuleDefaults(r)
	}
}

func saveProxy() { saveJSON(proxyFile, proxyCfg) }

// ---------- 域名归一化与匹配 ----------

func validHostnameLabels(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, lab := range strings.Split(h, ".") {
		if len(lab) == 0 || len(lab) > 63 {
			return false
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		for _, c := range lab {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// 归一化: 小写、去空格、去端口、去尾点; 空域名与非法域名报错; IP 字面量不许当规则域名
// (直接 IP 访问本来就要一律拒绝, 规则域名只接受主机名, 通配符只支持 *.example.com 单层)。
func normalizeDomain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	if d == "" {
		return "", errors.New("域名不能为空")
	}
	if strings.HasPrefix(d, "[") {
		return "", errors.New("规则域名不支持 IP 地址")
	}
	if strings.Count(d, ":") == 1 {
		host, port, _ := strings.Cut(d, ":")
		if port == "" {
			return "", errors.New("域名格式无效")
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", errors.New("域名格式无效")
			}
		}
		d = host
	} else if strings.Contains(d, ":") {
		return "", errors.New("规则域名不支持 IP 地址")
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", errors.New("域名不能为空")
	}
	if net.ParseIP(d) != nil {
		return "", errors.New("规则域名不支持 IP 地址")
	}
	if strings.HasPrefix(d, "*.") {
		rest := d[2:]
		if strings.Contains(rest, "*") || !validHostnameLabels(rest) {
			return "", errors.New("通配符只支持 *.example.com 单层形式")
		}
		return d, nil
	}
	if strings.Contains(d, "*") || !validHostnameLabels(d) {
		return "", errors.New("域名格式无效")
	}
	return d, nil
}

// host 是否匹配规则域名 pattern(精确或单层通配符)。
func domainMatchesRule(host, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		if !strings.HasSuffix(host, "."+suffix) {
			return false
		}
		prefix := strings.TrimSuffix(host, "."+suffix)
		return prefix != "" && !strings.Contains(prefix, ".")
	}
	return host == pattern
}

// 精确匹配优先于通配符: 先扫一遍精确, 再扫一遍通配符。
// 只看已启用、且某条监听的端口与协议都匹配的规则。
func findProxyRule(host string, port int, protocol string, rules []*ProxyRule) *ProxyRule {
	match := func(wildcard bool) *ProxyRule {
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			hit := false
			for _, l := range r.Listens {
				if l.Port == port && l.Protocol == protocol {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			if wildcard != strings.HasPrefix(r.Domain, "*.") {
				continue
			}
			if domainMatchesRule(host, r.Domain) {
				return r
			}
		}
		return nil
	}
	if r := match(false); r != nil {
		return r
	}
	return match(true)
}

// ---------- 后端解析与自环判定 ----------

// 只接受 host:port 或 http://host:port, 归一化为 host:port; https 后端本轮不支持。
func parseBackend(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", errors.New("后端不能为空")
	}
	if strings.HasPrefix(s, "https://") {
		return "", errors.New("https 后端本轮不支持")
	}
	s = strings.TrimPrefix(s, "http://")
	if strings.Contains(s, "/") {
		return "", errors.New("后端只支持 host:port 或 http://host:port")
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", errors.New("后端格式应为 host:port")
	}
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" || strings.ContainsAny(host, " \t") {
		return "", errors.New("后端主机无效")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("后端端口无效")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// 本机 IP(非回环): 后端指向本机 IP + 反代监听端口同样是自环, 一并拦截。
func isLocalIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var nip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			nip = v.IP
		case *net.IPAddr:
			nip = v.IP
		}
		if nip != nil && nip.Equal(ip) {
			return true
		}
	}
	return false
}

// ---------- 证书: 扫描、解析、SAN 匹配 ----------

// 扫描目录: 上传目录(平面配对)与 ACME 域名子目录(见 acme.go)。
func proxyScanDirs() []string {
	return []string{filepath.Join(dataDir, "certs")}
}

// 解析一对 crt/key: 取第一个证书块的 SAN 与到期时间; 密钥对必须能配对, 否则整对跳过。
func parseProxyCertPair(crtPath, keyPath, id, name, source, dir string) (ProxyCertMeta, *proxyCertEntry, error) {
	var meta ProxyCertMeta
	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return meta, nil, err
	}
	var block *pem.Block
	for {
		block, crtPEM = pem.Decode(crtPEM)
		if block == nil {
			return meta, nil, errors.New("无证书块")
		}
		if block.Type == "CERTIFICATE" {
			break
		}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return meta, nil, err
	}
	pair, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return meta, nil, err
	}
	ips := []string{}
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	dns := append([]string{}, leaf.DNSNames...)
	fpSum := sha256.Sum256(leaf.Raw)
	meta = ProxyCertMeta{
		ID: id, Name: name, Source: source, Dir: dir, Path: crtPath,
		DNSNames: dns, IPs: ips,
		NotAfter:    leaf.NotAfter.Format("2006-01-02 15:04"),
		Expired:     time.Now().After(leaf.NotAfter),
		Issuer:      leaf.Issuer.String(),
		Subject:     leaf.Subject.String(),
		NotBefore:   leaf.NotBefore.Format("2006-01-02 15:04"),
		Serial:      leaf.SerialNumber.String(),
		Fingerprint: hex.EncodeToString(fpSum[:]),
	}
	// 状态：先看过期，再看序列号匹配的 OCSP 吊销缓存（列表加载不做网络请求）。
	ocspStatusForMeta(&meta, leaf)
	return meta, &proxyCertEntry{meta: meta, cert: pair, leaf: leaf}, nil
}

// 扫描: 上传目录只认同名 .crt + .key 成对文件, 无私钥的证书不列入(没法用于握手);
// ACME 申请的证书按域名分子目录存放, 见 acme.go 的 scanAcmeCerts。
// (含已过期, 仅元数据展示, 过期不进 serving)。
func scanProxyCerts() ([]ProxyCertMeta, map[string]*proxyCertEntry) {
	metas := []ProxyCertMeta{}
	serving := map[string]*proxyCertEntry{}
	seen := map[string]bool{}
	add := func(meta ProxyCertMeta, entry *proxyCertEntry) {
		if seen[meta.ID] {
			return
		}
		seen[meta.ID] = true
		metas = append(metas, meta)
		if !meta.Expired && entry != nil {
			serving[meta.ID] = entry
		}
	}
	for _, dir := range proxyScanDirs() {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
				continue
			}
			base := strings.TrimSuffix(e.Name(), ".crt")
			keyPath := filepath.Join(dir, base+".key")
			if _, err := os.Stat(keyPath); err != nil {
				continue
			}
			meta, entry, err := parseProxyCertPair(filepath.Join(dir, e.Name()), keyPath, "upload:"+base, base, "upload", dir)
			if err != nil {
				continue
			}
			add(meta, entry)
		}
	}
	scanAcmeCerts(&metas, serving, seen)
	sort.Slice(metas, func(i, j int) bool {
		if metas[i].Source != metas[j].Source {
			return metas[i].Source < metas[j].Source
		}
		return metas[i].Name < metas[j].Name
	})
	return metas, serving
}

// 证书 SAN 是否覆盖域名: 精确 SAN 或单层通配符 SAN; IP 域名同样按 IP SAN 匹配。
func certCoversDomain(meta ProxyCertMeta, domain string) bool {
	for _, n := range meta.DNSNames {
		if n == domain {
			return true
		}
		if strings.HasPrefix(n, "*.") && domainMatchesRule(domain, n) {
			return true
		}
	}
	if ip := net.ParseIP(domain); ip != nil {
		for _, s := range meta.IPs {
			if pip := net.ParseIP(s); pip != nil && pip.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// SNI 选证书: 精确 SAN 优先于通配符 SAN, 同分取最晚到期。
func selectCertForName(name string, serving map[string]*proxyCertEntry) *proxyCertEntry {
	var best *proxyCertEntry
	bestScore := -1
	for _, ent := range serving {
		score := -1
		for _, n := range ent.leaf.DNSNames {
			if n == name {
				score = 2
				break
			}
			if strings.HasPrefix(n, "*.") && domainMatchesRule(name, n) {
				score = 1
			}
		}
		if score < 0 {
			continue
		}
		if score > bestScore || (score == bestScore && best != nil && ent.leaf.NotAfter.After(best.leaf.NotAfter)) {
			best, bestScore = ent, score
		}
	}
	return best
}

// ---------- 配置校验 ----------

// certs 为最新扫描的元数据; 证书要求只对已启用且含 HTTPS 监听的规则校验
// (停用的规则先放行, 启用时再卡)。去重、端口协议一致、自环按全部规则校验(含停用),
// 避免启用时才冲突。入站端口只校验本身合法(1-65535 的整数): 不限高低、无默认,
// 填 80/443 也不报错, 绑定失败只在监听时记错误, 不在这里卡保存。
func validateProxyConfig(cfg ProxyConfig, certs []ProxyCertMeta) error {
	byID := map[string]ProxyCertMeta{}
	for _, c := range certs {
		byID[c.ID] = c
	}
	// 先归一化域名与后端, 收集去重与自环判定用的集合
	type norm struct {
		rule     *ProxyRule
		domain   string
		backend  string
		host     string
		port     int
		hasHTTPS bool
	}
	norms := []norm{}
	seenDomainPort := map[string]bool{}
	portProto := map[int]string{}
	allPorts := map[int]bool{}
	allDomains := map[string]bool{}
	for _, r := range cfg.Rules {
		if r == nil {
			return errors.New("存在空规则")
		}
		d, err := normalizeDomain(r.Domain)
		if err != nil {
			return fmt.Errorf("域名 %q 无效: %v", r.Domain, err)
		}
		// 面板域名直访与反代规则抢域名时报错(反方向的校验在面板设置里)。
		if pd, ok := panelDomainActive(); ok && d == pd {
			return fmt.Errorf("域名 %s 已被面板域名直访占用", d)
		}
		if len(r.Listens) == 0 {
			return fmt.Errorf("域名 %s: 入站端口必填, 至少需要一个监听端口", d)
		}
		hasHTTPS := false
		seenPortsInRule := map[int]bool{}
		for _, l := range r.Listens {
			if l.Port < 1 || l.Port > 65535 {
				return fmt.Errorf("域名 %s: 入站端口必填, 应为 1-65535 的整数", d)
			}
			if l.Protocol != "http" && l.Protocol != "https" {
				return fmt.Errorf("域名 %s: 协议必须为 HTTP 或 HTTPS", d)
			}
			if seenPortsInRule[l.Port] {
				return fmt.Errorf("域名 %s: 监听端口 %d 在规则内重复", d, l.Port)
			}
			seenPortsInRule[l.Port] = true
			if l.Protocol == "https" {
				hasHTTPS = true
			}
			key := d + "\x00" + strconv.Itoa(l.Port)
			if seenDomainPort[key] {
				return fmt.Errorf("域名+端口重复: %s:%d", d, l.Port)
			}
			seenDomainPort[key] = true
			if prev, ok := portProto[l.Port]; ok && prev != l.Protocol {
				return fmt.Errorf("入站端口 %d 协议不一致: 已有 %s 规则, 不能再加 %s 规则", l.Port, prev, l.Protocol)
			}
			portProto[l.Port] = l.Protocol
			allPorts[l.Port] = true
		}
		allDomains[d] = true
		// 后端必填: 1.8.3 起只代理到内网已有应用, 不做重定向, 后端一律必填。
		b, err := parseBackend(r.Backend)
		if err != nil {
			return fmt.Errorf("后端 %q 无效: %v", r.Backend, err)
		}
		host, portStr, _ := net.SplitHostPort(b)
		bport, _ := strconv.Atoi(portStr)
		norms = append(norms, norm{rule: r, domain: d, backend: b, host: host, port: bport, hasHTTPS: hasHTTPS})
	}
	// 再校验: 证书(仅已启用且含 HTTPS 监听的规则)与自环
	for _, n := range norms {
		r := n.rule
		if r.Enabled && n.hasHTTPS {
			if r.Cert == "" {
				return fmt.Errorf("域名 %s: HTTPS 规则必须选择证书", n.domain)
			}
			if r.Cert == "auto" {
				found := false
				for _, c := range certs {
					if !c.Expired && certCoversDomain(c, n.domain) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("域名 %s: 没有 SAN 覆盖该域名的证书", n.domain)
				}
			} else {
				c, ok := byID[r.Cert]
				if !ok {
					return fmt.Errorf("域名 %s: 证书不存在", n.domain)
				}
				if c.Expired {
					return fmt.Errorf("域名 %s: 证书已过期", n.domain)
				}
				// 不校验 SAN: 用户可自选任意证书(如双线两张证书混用);
				// SAN 对不上时浏览器访问会报证书不匹配, 由用户自担。
			}
		}
		if n.host != "" {
			if (isLoopbackHost(n.host) || isLocalIP(n.host)) && allPorts[n.port] {
				return fmt.Errorf("域名 %s: 后端指向反代自身入站端口, 会自环", n.domain)
			}
			if allDomains[n.host] {
				return fmt.Errorf("域名 %s: 后端主机名等于反代规则域名, 会自环", n.domain)
			}
		}
	}
	return nil
}

func newProxyRuleID() string {
	var b [6]byte
	rand.Read(b[:])
	return "r" + hex.EncodeToString(b[:])
}

// ---------- SNI 与转发 ----------

// TLS 握手按 SNI 选证书: 先按 SNI 在本端口的 HTTPS 规则里找规则(精确优先于通配符),
// 再按规则证书选证书(精确 SAN 优先于通配符 SAN); 无匹配直接握手失败, 不设默认证书。
func proxyGetCertificateForPort(port int) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := strings.ToLower(strings.TrimSpace(hello.ServerName))
		if name == "" {
			return nil, errors.New("缺少 SNI")
		}
		proxyMu.Lock()
		defer proxyMu.Unlock()
		rule := findProxyRule(name, port, "https", proxyCfg.Rules)
		if rule == nil {
			return nil, errors.New("无匹配规则")
		}
		var ent *proxyCertEntry
		if rule.Cert == "auto" {
			ent = selectCertForName(name, proxyServing)
		} else {
			ent = proxyServing[rule.Cert]
		}
		if ent == nil {
			return nil, errors.New("无可用证书")
		}
		return &ent.cert, nil
	}
}

// 从请求 Host 取域名: 去端口、去尾点、小写; 空或 IP 字面量一律拒绝(直接 IP 访问不放行)。
func proxyReqHost(r *http.Request) string {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	return h
}

func proxyDirectorForRule(rule ProxyRule, isTLS bool, origDirector func(*http.Request)) func(*http.Request) {
	return func(req *http.Request) {
		origDirector(req)
		clientIP, _, _ := net.SplitHostPort(req.RemoteAddr)
		if clientIP == "" {
			clientIP = req.RemoteAddr
		}
		// X-Forwarded-For 由标准库 ReverseProxy 按追加语义自己处理, 这里不重复加(否则会追加两次)。
		req.Header.Set("X-Real-IP", clientIP)
		if isTLS {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
		// 不碰 Upgrade/Connection 头: WebSocket 升级由 ReverseProxy 原生处理。
	}
}

func makeProxyForRule(rule ProxyRule, isTLS bool) *httputil.ReverseProxy {
	target := &url.URL{Scheme: "http", Host: rule.Backend}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Director = proxyDirectorForRule(rule, isTLS, rp.Director)
	// 0 = 每次写后立即刷, 流式/SSE 不卡顿; WebSocket 走升级通道, 不受此影响。
	rp.FlushInterval = 0
	rp.Transport = &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConns:        32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "后端不可达或无响应", http.StatusBadGateway)
	}
	return rp
}

// 前端入口(每个入站端口一个): 按 Host/SNI 在本端口、本协议的规则里找规则,
// 找到即代理到内网后端; 未匹配域名 / 直接 IP 访问一律 421
// (不冒充后端内容, 也不暴露规则存在性以外的信息)。
func proxyFrontHandler(port int, isTLS bool) http.Handler {
	proto := "http"
	if isTLS {
		proto = "https"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := proxyReqHost(r)
		if host == "" || net.ParseIP(host) != nil {
			http.Error(w, "域名未匹配任何反代规则", 421)
			return
		}
		proxyMu.Lock()
		var rules []*ProxyRule
		for _, rr := range proxyCfg.Rules {
			cp := *rr
			rules = append(rules, &cp)
		}
		proxyMu.Unlock()
		rule := findProxyRule(host, port, proto, rules)
		if rule == nil {
			http.Error(w, "域名未匹配任何反代规则", 421)
			return
		}
		makeProxyForRule(*rule, isTLS).ServeHTTP(w, r)
	})
}

// newProxyHTTPSServer: HTTPS 反代监听的标准构造。
// 必须走 ServeTLS + TLSConfig, 不能用 tls.NewListener+Serve: 只有前者让标准库
// 自动配好 HTTP/2(ALPN 协商出 h2); 后者静默回落到 HTTP/1.1(1.8.3 的教训,
// 当时只验了状态码和内容、没验协商出的协议, 差距直到与雷池对比才暴露)。
// 动态证书仍走 GetCertificate 按 SNI 挑, 与之前一致。
func newProxyHTTPSServer(port int) *http.Server {
	return &http.Server{
		Handler: proxyFrontHandler(port, true),
		TLSConfig: &tls.Config{
			GetCertificate: proxyGetCertificateForPort(port),
			MinVersion:     tls.VersionTLS12,
		},
	}
}

// ---------- 监听管理: 绑定失败绝不导致应用崩溃, 只记错误状态 ----------

func proxyCloseListenersLocked() {
	for _, srv := range proxyServers {
		srv.Close()
	}
	proxyServers = map[int]*http.Server{}
	proxyPortProto = map[int]string{}
	proxyPortErr = map[int]string{}
	proxyTakeover = map[int]map[string]bool{}
	proxyConflictPorts = map[int]bool{}
	// proxyManaged/proxyGenErr 故意不在此处清零：它们描述磁盘 vhost 文件的现况，
	// 只有 nginxProxyManage 成功/无变化时才重算、门禁不通过时才清零；同步失败时
	// 以还原后磁盘文件为准，不因一次 apply 闪成红字。
}

// 对齐监听与配置: 关掉旧监听, 按已启用规则的监听去重后的入站端口各起一个监听;
// 任一端口绑定失败只记该端口错误, 不影响其他端口与主应用。
// ":端口" 在 Linux 上默认双栈, 同时覆盖 0.0.0.0 与 [::]。
// 80/443 不在这里起: 由前置服务统一管理(80 挑战应答/跳转、443 SNI 分发)。
func proxyApply() {
	proxyMu.Lock()
	metas, serving := scanProxyCerts()
	proxyCerts = metas
	proxyServing = serving
	proxyCloseListenersLocked()
	byPort := map[int]string{}
	for _, r := range proxyCfg.Rules {
		if r == nil || !r.Enabled {
			continue
		}
		for _, l := range r.Listens {
			if prev, ok := byPort[l.Port]; ok && prev != l.Protocol {
				proxyPortErr[l.Port] = "同一入站端口协议不一致, 未监听"
				continue
			}
			byPort[l.Port] = l.Protocol
		}
	}
	ports := []int{}
	for p := range byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		if p == 80 || p == 443 {
			continue // 前置服务统一管理, 见 frontApply
		}
		proto := byPort[p]
		proxyPortProto[p] = proto
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err != nil {
			proxyPortErr[p] = bindErrText(p, err)
			// 仅绑定冲突时记下端口，循环后统一检测一次 nginx 接管（只读 nginx -T）；
			// 非冲突失败、成功绑定都不检测。
			if strings.Contains(err.Error(), "address already in use") {
				proxyConflictPorts[p] = true
			}
			continue
		}
		if proto == "https" {
			srv := newProxyHTTPSServer(p)
			proxyServers[p] = srv
			go func() { _ = srv.ServeTLS(ln, "", "") }()
		} else {
			srv := &http.Server{Handler: proxyFrontHandler(p, false)}
			proxyServers[p] = srv
			go func() { _ = srv.Serve(ln) }()
		}
	}
	// 绑定冲突端口统一检测一次 nginx 接管：命中则规则行显示“由 nginx 接管”而非红字失败；
	// 检测失败（无 nginx 二进制、超时）视为未接管，红字行为不变。下次 apply 会重新绑定并重新检测，
	// 因此 vhost 被删后回落到红字。
	if len(proxyConflictPorts) > 0 {
		if dump, derr := nginxTDumpFunc(); derr == nil {
			servers := parseNginxServers(dump)
			for p := range proxyConflictPorts {
				proto := byPort[p]
				var domains []string
				for _, r := range proxyCfg.Rules {
					if r == nil || !r.Enabled {
						continue
					}
					for _, l := range r.Listens {
						if l.Port == p && l.Protocol == proto {
							domains = append(domains, r.Domain)
						}
					}
				}
				if len(domains) > 0 {
					if got := matchNginxTakeover(servers, domains, p, proto == "https"); len(got) > 0 {
						proxyTakeover[p] = got
					}
				}
			}
		}
	}
	proxyMu.Unlock()
	frontApply()
	// 此时 proxyPortErr 与 front443Err 已知：接管 nginx vhost 生命周期（见 nginx_proxy.go）。
	// 启用 → 规则进 guijia-proxy.conf → 域名通；停用/删除 → 规则出文件 → reload 后域名不再反代。
	nginxProxyManage()
}

// ---------- 后端可达探测: 只放内存, 不落盘 ----------

func proxyProbeOne(backend string) (bool, string) {
	conn, err := net.DialTimeout("tcp", backend, 2*time.Second)
	if err != nil {
		return false, err.Error()
	}
	conn.Close()
	return true, ""
}

// 拨测对象: 已启用且有后端的规则(1.8.3 起所有规则都代理, 无重定向规则)。
func proxyRuleServesProxy(rr *ProxyRule) bool {
	return rr.Enabled && strings.TrimSpace(rr.Backend) != ""
}

func proxyProbeAll() {
	proxyMu.Lock()
	var rules []*ProxyRule
	for _, rr := range proxyCfg.Rules {
		if proxyRuleServesProxy(rr) {
			cp := *rr
			rules = append(rules, &cp)
		}
	}
	proxyMu.Unlock()
	type res struct {
		id string
		ok bool
		er string
	}
	ch := make(chan res, len(rules))
	for _, rr := range rules {
		go func(rr *ProxyRule) {
			ok, er := proxyProbeOne(rr.Backend)
			ch <- res{rr.ID, ok, er}
		}(rr)
	}
	now := time.Now().UnixMilli()
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for range rules {
		r := <-ch
		proxyBackend[r.id] = proxyBackendStatus{OK: r.ok, CheckedAt: now, Err: r.er}
	}
}

func proxyHealthLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		proxyProbeAll()
	}
}

// ---------- API ----------

func proxySnapshot() map[string]any {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	rules := []*ProxyRule{}
	for _, rr := range proxyCfg.Rules {
		cp := *rr
		rules = append(rules, &cp)
	}
	cfg := proxyCfg
	cfg.Rules = rules
	certs := append([]ProxyCertMeta{}, proxyCerts...)
	backend := map[string]proxyBackendStatus{}
	for k, v := range proxyBackend {
		backend[k] = v
	}
	ports := []map[string]any{}
	seen := map[int]bool{}
	// 已启用规则的去重监听端口(监听目标) + 有绑定错误的端口, 按端口排序
	for _, r := range proxyCfg.Rules {
		if r == nil || !r.Enabled {
			continue
		}
		for _, l := range r.Listens {
			seen[l.Port] = true
		}
	}
	for p := range proxyPortErr {
		seen[p] = true
	}
	plist := []int{}
	for p := range seen {
		plist = append(plist, p)
	}
	sort.Ints(plist)
	for _, p := range plist {
		_, listening := proxyServers[p]
		proto := proxyPortProto[p]
		errStr := proxyPortErr[p]
		// 80/443 由前置服务管理: 监听状态与错误以前置为准。
		if p == 80 {
			if frontPort80OK() {
				listening = true
			} else if errStr == "" {
				errStr = "80 端口未被本应用占用"
			}
		}
		if p == 443 {
			if on, ferr := front443Status(); on {
				listening = true
			} else if ferr != "" {
				errStr = ferr
			}
		}
		// nginx 接管域名集：443 走前置服务的 front443Takeover，其余端口走 proxyTakeover；
		// UI 据此把命中规则渲染为“由 nginx 接管”（绿字），而非红字失败。
		takeover := []string{}
		if p == 443 {
			takeover = front443TakeoverList()
		} else if tk, ok := proxyTakeover[p]; ok {
			for d := range tk {
				takeover = append(takeover, d)
			}
			sort.Strings(takeover)
		}
		// 面板已生成 vhost 的域名集（nginx_proxy.go 维护）：443 与非 443 走同一张表。
		managed := []string{}
		if mg, ok := proxyManaged[p]; ok {
			for d := range mg {
				managed = append(managed, d)
			}
			sort.Strings(managed)
		}
		if proto == "" {
			// 监听未起时协议从规则监听里取, 方便 UI 展示
			for _, r := range proxyCfg.Rules {
				if r == nil {
					continue
				}
				for _, l := range r.Listens {
					if l.Port == p {
						proto = l.Protocol
						break
					}
				}
				if proto != "" {
					break
				}
			}
		}
		ports = append(ports, map[string]any{
			"port": p, "protocol": proto,
			"listening": listening, "error": errStr,
			"takeover": takeover, "managed": managed,
		})
	}
	genErr := map[string]string{}
	for d, e := range proxyGenErr {
		genErr[d] = e
	}
	return map[string]any{
		"config": cfg, "certs": certs,
		"status":  map[string]any{"ports": ports, "genErr": genErr},
		"backend": backend,
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, 200, proxySnapshot())
	case "POST":
		var in ProxyConfig
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		if in.Rules == nil {
			in.Rules = []*ProxyRule{}
		}
		// 归一化后写回, 再校验; 监听/证书缺失时先物化公网版默认值
		// (监听空 = 443 HTTPS, 证书空 = auto), 再进严格校验。
		for _, rr := range in.Rules {
			if d, err := normalizeDomain(rr.Domain); err == nil {
				rr.Domain = d
			}
			applyProxyRuleDefaults(rr)
			for i := range rr.Listens {
				rr.Listens[i].Protocol = strings.ToLower(strings.TrimSpace(rr.Listens[i].Protocol))
			}
			if strings.TrimSpace(rr.Backend) != "" {
				if b, err := parseBackend(rr.Backend); err == nil {
					rr.Backend = b
				}
			}
			if rr.ID == "" {
				rr.ID = newProxyRuleID()
			}
		}
		metas, _ := scanProxyCerts()
		if err := validateProxyConfig(in, metas); err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		proxyMu.Lock()
		proxyCfg = in
		proxyMu.Unlock()
		saveProxy()
		proxyApply()
		proxyProbeAll()
		writeJSON(w, 200, proxySnapshot())
	default:
		errJSON(w, 405, "method")
	}
}

func handleProxyRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	proxyApply()
	proxyProbeAll()
	writeJSON(w, 200, proxySnapshot())
}

var proxyCertNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func handleProxyCertUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		errJSON(w, 400, "上传无效")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || !proxyCertNameRe.MatchString(name) || strings.Contains(name, "..") {
		errJSON(w, 400, "证书名称只支持字母、数字、. _ -")
		return
	}
	crtF, _, err1 := r.FormFile("crt")
	keyF, _, err2 := r.FormFile("key")
	if err1 != nil || err2 != nil {
		errJSON(w, 400, "请同时上传 .crt 与 .key")
		return
	}
	defer crtF.Close()
	defer keyF.Close()
	crtPEM, err := io.ReadAll(io.LimitReader(crtF, 1<<20))
	if err != nil {
		errJSON(w, 400, "读取证书失败")
		return
	}
	keyPEM, err := io.ReadAll(io.LimitReader(keyF, 1<<20))
	if err != nil {
		errJSON(w, 400, "读取私钥失败")
		return
	}
	dir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		errJSON(w, 500, "创建证书目录失败")
		return
	}
	crtPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	// 先落盘再成对校验, 校验不过删掉, 不留半对文件
	if err := os.WriteFile(crtPath, crtPEM, 0644); err != nil {
		errJSON(w, 500, "保存证书失败")
		return
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		os.Remove(crtPath)
		errJSON(w, 500, "保存私钥失败")
		return
	}
	if _, _, err := parseProxyCertPair(crtPath, keyPath, "upload:"+name, name, "upload", dir); err != nil {
		os.Remove(crtPath)
		os.Remove(keyPath)
		errJSON(w, 400, "证书与私钥不成对或格式无效: "+err.Error())
		return
	}
	proxyMu.Lock()
	metas, serving := scanProxyCerts()
	proxyCerts = metas
	proxyServing = serving
	proxyMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleProxyCertDownload: 下载证书 + 私钥的 zip 作附件（下载就是拿到别处部署，
// 只有证书没私钥没用）。ACME: fullchain.pem + privkey.pem；上传: <名>.crt + <名>.key。
// 查看弹窗仍绝不显示私钥；下载走 authMiddleware 鉴权，未登录 401。
func handleProxyCertDownload(w http.ResponseWriter, r *http.Request, id string) {
	rescanProxyCertsLocked()
	meta, ok := findProxyCertMeta(id)
	if !ok {
		errJSON(w, 404, "证书不存在")
		return
	}
	var keyPath, crtName, keyName string
	if meta.Source == "acme" {
		keyPath = filepath.Join(meta.Dir, "privkey.pem")
		crtName, keyName = "fullchain.pem", "privkey.pem"
	} else {
		keyPath = strings.TrimSuffix(meta.Path, ".crt") + ".key"
		crtName = filepath.Base(meta.Path)
		keyName = filepath.Base(keyPath)
	}
	crt, err := os.ReadFile(meta.Path)
	if err != nil {
		errJSON(w, 500, "读取证书失败")
		return
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		errJSON(w, 500, "读取私钥失败")
		return
	}
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	if err := zipWriteFile(zw, crtName, crt, 0644); err != nil {
		errJSON(w, 500, "打包证书失败")
		return
	}
	if err := zipWriteFile(zw, keyName, key, 0600); err != nil {
		errJSON(w, 500, "打包私钥失败")
		return
	}
	if err := zw.Close(); err != nil {
		errJSON(w, 500, "打包证书失败")
		return
	}
	name := strings.ReplaceAll(meta.Name, `"`, "")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.zip"`)
	w.WriteHeader(200)
	w.Write(buf.Bytes())
}

// zipWriteFile: 往 zip 里写一个文件（私钥条目权限 0600，证书 0644）。
func zipWriteFile(zw *zip.Writer, name string, data []byte, mode os.FileMode) error {
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(mode)
	fw, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = fw.Write(data)
	return err
}

func handleProxyCertItem(w http.ResponseWriter, r *http.Request) {
	id, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/proxy/certs/"))
	// 下载：GET /api/proxy/certs/<id>/download，返回证书 + 私钥的 zip；
	// 鉴权走外层 authMiddleware（/api/ 全量），未登录 401。
	if r.Method == "GET" && strings.HasSuffix(id, "/download") {
		handleProxyCertDownload(w, r, strings.TrimSuffix(id, "/download"))
		return
	}
	if r.Method == "PUT" {
		handleProxyCertEdit(w, r, id)
		return
	}
	if r.Method != "DELETE" {
		errJSON(w, 405, "method")
		return
	}
	panelFallback, rulesDetached, err := deleteCertByID(id)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "panelFallback": panelFallback, "rulesDetached": rulesDetached})
}

// deleteCertByID: 删除一张证书并清理全部引用。
// upload: 删 certs/<名>.crt + <名>.key; acme: 删 certs/<域名>/ 目录并停续期
// (目录没了续期循环自然不再选中它; 进行中的申请由落盘保护拦住)。
// 面板显式引用 -> 回 HTTP(端口模式)或清空走自动匹配(域名模式, 无覆盖证书时也回 HTTP);
// 反代规则显式引用 -> 改回 auto, 规则不断服务, 握手时按 SNI 自动匹配。
// 证书只有 upload: 与 acme: 两个来源，其余前缀不可在此删除。
func deleteCertByID(id string) (panelFallback bool, rulesDetached int, err error) {
	dir := filepath.Join(dataDir, "certs")
	switch {
	case strings.HasPrefix(id, "upload:"):
		name := strings.TrimPrefix(id, "upload:")
		if name == "" || !proxyCertNameRe.MatchString(name) || strings.Contains(name, "..") {
			return false, 0, errors.New("证书名称无效")
		}
		os.Remove(filepath.Join(dir, name+".crt"))
		os.Remove(filepath.Join(dir, name+".key"))
	case strings.HasPrefix(id, "acme:"):
		domain := strings.TrimPrefix(id, "acme:")
		nd, nerr := normalizeDomain(domain)
		if nerr != nil || nd == "" || nd != domain {
			return false, 0, errors.New("域名无效")
		}
		deleteAcmeCertDir(domain)
	default:
		return false, 0, errors.New("扫描到的证书不可在此删除")
	}
	proxyMu.Lock()
	metas, serving := scanProxyCerts()
	proxyCerts = metas
	proxyServing = serving
	proxyMu.Unlock()
	panelFallback, rulesDetached = detachDeletedCert(id, serving)
	if panelFallback {
		// 异步重建: 不能在当前请求的 handler 里同步 Shutdown(会等自身连接空闲而死锁)。
		go rebuildPanelServer()
	}
	return panelFallback, rulesDetached, nil
}

// detachDeletedCert: 摘掉面板与反代规则对已删证书的引用, 返回面板是否回落到 HTTP。
// 调用方须已刷新证书表; serving 为刷新后的表(用于域名模式覆盖检查)。
// 锁按 proxyMu -> mu 顺序先后持有、绝不嵌套, 不与其它路径的锁序冲突。
// 注意: 域名模式下显式证书被清、但仍有别的证书覆盖时, 面板继续走域名自动匹配
// (443 前置按次握手实时读配置, 无需重建), 只有模式真的变回 off 才算回落。
func detachDeletedCert(id string, serving map[string]*proxyCertEntry) (panelFallback bool, rulesDetached int) {
	proxyMu.Lock()
	for _, r := range proxyCfg.Rules {
		if r != nil && r.Cert == id {
			r.Cert = "auto"
			rulesDetached++
		}
	}
	changed := rulesDetached > 0
	proxyMu.Unlock()
	if changed {
		saveProxy()
	}
	mu.Lock()
	mode := settings.PanelSSLMode
	certID := settings.PanelSSLCert
	domain := settings.PanelDomain
	settingsChanged := false
	if mode == "port" && certID == id {
		settings.PanelSSLMode = "off"
		settings.PanelSSLCert = ""
		settingsChanged = true
		panelFallback = true
	} else if mode == "domain" {
		if certID == id {
			settings.PanelSSLCert = ""
			settingsChanged = true
		}
		if settings.PanelSSLMode == "domain" && selectCertForName(domain, serving) == nil {
			settings.PanelSSLMode = "off"
			settings.PanelSSLCert = ""
			settingsChanged = true
			panelFallback = true
		}
	}
	mu.Unlock()
	if settingsChanged {
		saveSettings()
	}
	return panelFallback, rulesDetached
}
