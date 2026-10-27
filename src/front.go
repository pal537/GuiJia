package main

// 前置服务: 80/443 统一入口。
// 阶段 5: 只起 80, 仅应答 ACME HTTP-01 验证(/.well-known/acme-challenge/*);
//         非验证路径暂 404, 反代与 HTTPS 跳转在阶段 6 接入。
// 80 绑定失败(被其他服务占用)时 port80OK=false, 证书申请前据此报错,
// 应用其余功能不受影响; 80 是否被占的唯一判定就是本服务是否成功绑定,
// 不另做端口探测(避免把别人的监听误判成自己的)。

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	frontMu         sync.Mutex
	frontChallenges = map[string]string{} // token -> keyAuth
	front80         *http.Server
	port80OK        bool
)

func frontRegisterChallenge(token, keyAuth string) {
	frontMu.Lock()
	defer frontMu.Unlock()
	frontChallenges[token] = keyAuth
}

func frontClearChallenge(token string) {
	frontMu.Lock()
	defer frontMu.Unlock()
	delete(frontChallenges, token)
}

func frontPort80OK() bool {
	frontMu.Lock()
	defer frontMu.Unlock()
	return port80OK
}

// startFront80On 在指定地址起 80 服务(供测试用任意端口)。
func startFront80On(addr string) (*http.Server, error) {
	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(front80Handler)}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "front80:", err)
			// 监听异常死亡也要把全局状态清掉, 重试循环才能把它起回来。
			// 测试用服务从不进全局 front80(恒为 nil), 此处对它们是空操作。
			frontMu.Lock()
			if front80 == srv {
				front80 = nil
				port80OK = false
			}
			frontMu.Unlock()
		}
	}()
	return srv, nil
}

// startFront80 起生产 80 服务; 绑定失败只记日志并置 port80OK=false, 不致命。
// 接管失败不代表放弃: frontRetryLoop 会定期重试, 占用释放后自动接管。
func startFront80() {
	if !frontEnsure80(":80") {
		fmt.Fprintln(os.Stderr, "front80 bind failed (port 80 occupied?), will retry")
	}
}

// frontEnsure80: 80 前置缺失时尝试补起(幂等); 返回当前是否在跑。
func frontEnsure80(addr string) bool {
	frontMu.Lock()
	if front80 != nil {
		ok := port80OK
		frontMu.Unlock()
		return ok
	}
	frontMu.Unlock()
	srv, err := startFront80On(addr)
	frontMu.Lock()
	defer frontMu.Unlock()
	if err != nil {
		// 并发补起时对方已成功不算失败。
		if front80 == nil {
			port80OK = false
		}
		return front80 != nil
	}
	front80 = srv
	port80OK = true
	return true
}

// frontEnsure443: 443 前置有需求但未在跑时尝试补起(幂等); 返回当前是否在跑。
// 无需求时确保停掉(与 frontApplyOn 的语义一致)。
func frontEnsure443(addr string) bool {
	frontApplyOn(addr)
	on, _ := front443Status()
	return on
}

// frontRetryEvery: 前置重试间隔(可测试变量, 生产 60 秒)。
var frontRetryEvery = 60 * time.Second

// frontRetryLoop: 生产 80/443 前置定期重试接管。
func frontRetryLoop() { frontRetryLoopAddrs(nil, ":80", ":443") }

// frontRetryLoopAddrs: 可指定地址与停止通道的重试循环(供测试)。
// 面板本身绝不因前置绑定失败而起不来(面板有 HTTP 回落); 443 接管成功且面板
// 正处于域名模式 HTTP 回落时, 重建面板监听, 让面板切回 443 前置。
func frontRetryLoopAddrs(stop <-chan struct{}, addr80, addr443 string) {
	t := time.NewTicker(frontRetryEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			was80 := frontPort80OK()
			if ok := frontEnsure80(addr80); ok && !was80 {
				fmt.Fprintln(os.Stderr, "front80 recovered")
			}
			was443, _ := front443Status()
			if ok := frontEnsure443(addr443); ok && !was443 {
				fmt.Fprintln(os.Stderr, "front443 recovered")
				if panelInHTTPFallback() {
					go rebuildPanelServer()
				}
			}
		}
	}
}

// ---------- 阶段 6: 80/443 统一前置 ----------

// panelDomainActive: 面板域名直访是否启用 + 域名。
func panelDomainActive() (string, bool) {
	mu.Lock()
	defer mu.Unlock()
	if settings.PanelSSLMode == "domain" && settings.PanelDomain != "" {
		return settings.PanelDomain, true
	}
	return "", false
}

// redirectPortForDomain: 80 跳转目标端口——该域名唯一 HTTPS 监听端口, 否则 443。
func redirectPortForDomain(host string) int {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	ports := map[int]bool{}
	for _, r := range proxyCfg.Rules {
		if r == nil || !r.Enabled {
			continue
		}
		if !domainMatchesRule(host, r.Domain) {
			continue
		}
		for _, l := range r.Listens {
			if l.Protocol == "https" {
				ports[l.Port] = true
			}
		}
	}
	if len(ports) == 1 {
		for p := range ports {
			return p
		}
	}
	return 443
}

// front80Handler: ACME 验证 -> 匹配的 80 反代规则 -> 其余跳转 HTTPS。
func front80Handler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		frontMu.Lock()
		keyAuth, ok := frontChallenges[token]
		frontMu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(keyAuth))
		return
	}
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
	if rule := findProxyRule(host, 80, "http", rules); rule != nil {
		makeProxyForRule(*rule, false).ServeHTTP(w, r)
		return
	}
	port := redirectPortForDomain(host)
	target := "https://" + host
	if port != 443 {
		target += ":" + itoa(port)
	}
	target += r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// ---------- 443 前置(SNI 分发) ----------

var (
	front443Mu       sync.Mutex
	front443Srv      *http.Server
	front443On       bool
	front443Err      string
	front443Takeover = map[string]bool{} // nginx 已接管的 443/https 规则域名（仅绑定冲突且检测命中时有）
	front443Conflict bool                // 443 绑定失败是否为 address already in use（nginx_proxy.go 的管理候选依据）
)

// front443TakeoverList: 快照用 443 接管域名列表（front443Mu 守卫，与 front443Status 同一加锁顺序）。
func front443TakeoverList() []string {
	front443Mu.Lock()
	defer front443Mu.Unlock()
	out := []string{}
	for d := range front443Takeover {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func front443Status() (bool, string) {
	front443Mu.Lock()
	defer front443Mu.Unlock()
	return front443On, front443Err
}

// front443HasConflict: 443 是否因被占用而绑定失败（供 nginxProxyManage 判断管理候选）。
// 锁顺序与快照一致：proxyMu → front443Mu，manage 全程持有 proxyMu 时调用本函数是安全的。
func front443HasConflict() bool {
	front443Mu.Lock()
	defer front443Mu.Unlock()
	return front443Conflict
}

// front443GetCertificate: 面板域名优先(显式证书 > 自动匹配), 否则走反代规则证书。
func front443GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSpace(hello.ServerName))
	if pd, ok := panelDomainActive(); ok && name == pd {
		mu.Lock()
		certID := settings.PanelSSLCert
		mu.Unlock()
		_, serving := scanProxyCerts()
		if certID != "" {
			if ent := serving[certID]; ent != nil {
				return &ent.cert, nil
			}
			return nil, errors.New("面板证书不可用")
		}
		if ent := selectCertForName(name, serving); ent != nil {
			return &ent.cert, nil
		}
		return nil, errors.New("无覆盖面板域名的证书")
	}
	return proxyGetCertificateForPort(443)(hello)
}

// front443Handler: 面板域名 -> 面板, 否则 443 反代规则。
func front443Handler(w http.ResponseWriter, r *http.Request) {
	host := proxyReqHost(r)
	if pd, ok := panelDomainActive(); ok && host == pd {
		authMiddleware(rootMux).ServeHTTP(w, r)
		return
	}
	proxyFrontHandler(443, true).ServeHTTP(w, r)
}

// frontApply: 按需起/停 443 前置监听(幂等; handler 与证书选择读实时配置,
// 规则变化无需重启监听; 绑定失败只记错, 不致命)。
func frontApply() { frontApplyOn(":443") }

func frontApplyOn(addr string) {
	proxyMu.Lock()
	has443 := false
	var domains443 []string
	for _, r := range proxyCfg.Rules {
		if r == nil || !r.Enabled {
			continue
		}
		for _, l := range r.Listens {
			if l.Port == 443 && l.Protocol == "https" {
				has443 = true
				domains443 = append(domains443, r.Domain)
			}
		}
	}
	proxyMu.Unlock()
	_, pdOn := panelDomainActive()
	want := has443 || pdOn
	front443Mu.Lock()
	defer front443Mu.Unlock()
	if !want {
		if front443Srv != nil {
			front443Srv.Close()
			front443Srv = nil
		}
		front443On, front443Err = false, ""
		front443Takeover = map[string]bool{}
		front443Conflict = false
		return
	}
	if front443Srv != nil && front443On {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		front443On, front443Err = false, bindErrText(portFromAddr(addr, 443), err)
		front443Takeover = map[string]bool{}
		front443Conflict = strings.Contains(err.Error(), "address already in use")
		// 仅绑定冲突时检测 nginx 接管（只读 nginx -T，不写任何配置）；
		// 命中则规则行显示“由 nginx 接管”而非红字失败；检测失败视为未接管。
		if front443Conflict && len(domains443) > 0 {
			front443Takeover = detectNginxTakeover(domains443, 443, true)
		}
		return
	}
	srv := &http.Server{
		Handler:   http.HandlerFunc(front443Handler),
		TLSConfig: &tls.Config{GetCertificate: front443GetCertificate, MinVersion: tls.VersionTLS12},
	}
	front443Srv = srv
	front443On, front443Err = true, ""
	front443Takeover = map[string]bool{}
	front443Conflict = false
	go func() { _ = srv.ServeTLS(ln, "", "") }()
}
