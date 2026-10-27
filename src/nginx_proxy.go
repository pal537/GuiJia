package main

// nginx vhost 生命周期管理：让反代规则开关真正控制反代。
//
// 背景：面板规则开关和 nginx vhost 各管各的——停用面板规则删不掉 nginx 那个 vhost，
// 域名还通着，开关是假的。本文件把开关变实：proxyApply 之后，对“已启用且至少一个
// 监听端口被 nginx 占着”的规则，面板在 conf.d/guijia-proxy.conf 里全量生成对应的
// server 块；停用/删除的规则不出块；nginx -t 通过才 reload，不通过则全部还原、
// 不 reload。80 端口规则不在管理范围（前置服务负责 80 挑战应答，见 front.go）。
//
// 命名空间：conf.d 下 guijia-*.conf 归面板管；其中 guijia-proxy.conf 是面板唯一
// vhost 管理文件，guijia-acme-default.conf 是 ACME 常驻块（绝不能动）；其余
// guijia-*.conf 只有当其域名已进入新生成的 guijia-proxy.conf 时才删除（内容已迁移），
// 否则一律保留（它在服务面板不管的东西，删了会断服）。
//
// 多域名独立性：全量重写按规则生成，停用/删除一条只不出它的块，其余块字节不变；
// 同端口多域名（SNI）同理；单条规则生成失败（如证书匹配不到）只跳过那条、记红字
// 状态，绝不丢掉其他规则的块；只有 nginx -t 整体不通过时才全还原、不 reload。
//
// 安全：仅当面板跑 root 且本机有 nginx 二进制时才管理；否则跳过（状态回落上一轮
// 行为：绑定失败红字 / nginx -T 检测绿字），文件原样不动，绝不报错崩溃。
// manage 全程持有 proxyMu（apply 串行化，禁止并发 apply 交错写文件）；执行期间
// 快照/API 会短暂阻塞，规则保存是低频操作，可以接受。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// nginxProxyConf: 面板唯一 vhost 管理文件（测试可改；目录即 filepath.Dir 之值）。
var nginxProxyConf = "/etc/nginx/conf.d/guijia-proxy.conf"

// nginxProxyAcmeConf: ACME 常驻块，迁移时绝不能动（与 nginx_acme.go 的 nginxDefaultConf 同值）。
const nginxProxyAcmeConf = "/etc/nginx/conf.d/guijia-acme-default.conf"

// nginxProxyIsRoot / Test / Reload：可注入（单测注入，生产走真实环境）。
var nginxProxyIsRoot = func() bool { return os.Geteuid() == 0 }

var nginxProxyTestFunc = func() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, nginxBinary, "-t")
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nginx -t 超时")
		}
		return err
	}
	return nil
}

var nginxProxyReloadFunc = func() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "systemctl", "reload", "nginx").Run(); err == nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, nginxBinary, "-s", "reload")
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nginx reload 超时")
		}
		return err
	}
	return nil
}

// nginxProxyShouldManage: 管理门禁（可单测）：root 且本机有 nginx 二进制。
func nginxProxyShouldManage() bool {
	if !nginxProxyIsRoot() {
		return false
	}
	_, err := exec.LookPath(nginxBinary)
	return err == nil
}

// nginxProxyEntry: 一条待管理规则及其被占监听与证书路径。
type nginxProxyEntry struct {
	rule     *ProxyRule
	listens  []ProxyListen // 仅被占端口
	certPath string
	keyPath  string
}

// proxyCertKeyPath: 证书私钥路径（与证书下载同一口径：ACME 是 Dir/privkey.pem，
// 上传是 crt 同名 .key）。
func proxyCertKeyPath(meta ProxyCertMeta) string {
	if meta.Source == "acme" {
		return filepath.Join(meta.Dir, "privkey.pem")
	}
	return strings.TrimSuffix(meta.Path, ".crt") + ".key"
}

// resolveNginxProxyCert: 解析规则证书。needsTLS=false（纯 HTTP 被占监听）时不需证书。
// 返回 (crt, key, reason)，reason 非空表示跳过该规则（只跳过该条，不影响其他规则）。
func resolveNginxProxyCert(rule *ProxyRule, needsTLS bool, metas []ProxyCertMeta, serving map[string]*proxyCertEntry) (string, string, string) {
	if !needsTLS {
		return "", "", ""
	}
	certID := strings.TrimSpace(rule.Cert)
	if certID == "" || certID == "auto" {
		ent := selectCertForName(rule.Domain, serving)
		if ent == nil {
			return "", "", "无可用证书"
		}
		if !certCoversDomain(ent.meta, rule.Domain) {
			return "", "", "证书与域名不匹配"
		}
		return ent.meta.Path, proxyCertKeyPath(ent.meta), ""
	}
	if ent := serving[certID]; ent != nil {
		if !certCoversDomain(ent.meta, rule.Domain) {
			return "", "", "证书与域名不匹配"
		}
		return ent.meta.Path, proxyCertKeyPath(ent.meta), ""
	}
	for _, m := range metas {
		if m.ID == certID {
			if m.Expired {
				return "", "", "证书已过期"
			}
			return "", "", "证书不可用"
		}
	}
	return "", "", "证书不存在"
}

// buildNginxProxyContent: 全量生成 vhost 文件内容。规则按域名、监听按端口排序，
// 因此同一批规则输出恒定（停用/删除一条时其余块字节不变）。
func buildNginxProxyContent(entries []nginxProxyEntry) string {
	var b strings.Builder
	b.WriteString("# 由龟甲面板管理：下次反代 apply 时全量重写，手动改动会被覆盖。\n")
	b.WriteString("# 请勿在此目录手建 guijia-*.conf（面板按域名迁移清理该命名空间）。\n")
	sorted := append([]nginxProxyEntry{}, entries...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].rule.Domain != sorted[j].rule.Domain {
			return sorted[i].rule.Domain < sorted[j].rule.Domain
		}
		return sorted[i].rule.ID < sorted[j].rule.ID
	})
	for _, e := range sorted {
		listens := append([]ProxyListen{}, e.listens...)
		sort.Slice(listens, func(i, j int) bool { return listens[i].Port < listens[j].Port })
		for _, l := range listens {
			b.WriteString("server {\n")
			if l.Protocol == "https" {
				fmt.Fprintf(&b, "    listen %d ssl;\n", l.Port)
			} else {
				fmt.Fprintf(&b, "    listen %d;\n", l.Port)
			}
			fmt.Fprintf(&b, "    server_name %s;\n", e.rule.Domain)
			if l.Protocol == "https" {
				fmt.Fprintf(&b, "    ssl_certificate %s;\n", e.certPath)
				fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", e.keyPath)
			}
			b.WriteString("    location / {\n")
			fmt.Fprintf(&b, "        proxy_pass http://%s;\n", e.rule.Backend)
			b.WriteString("        proxy_set_header Host $host;\n")
			b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
			b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
			b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
			b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
			b.WriteString("    }\n")
			b.WriteString("}\n")
		}
	}
	return b.String()
}

// planNginxProxyMigration: 列出可删除的旧面板文件。仅 confDir 下 guijia-*.conf，
// 排除管理文件自身与 ACME 常驻块；仅当文件内全部 server_name 都已进入新管理集时
// 才删，否则保留（混有未迁移域名、读不到、无 server_name 的一律保留）。
func planNginxProxyMigration(confDir string, managedDomains map[string]bool) ([]string, error) {
	ents, err := os.ReadDir(confDir)
	if err != nil {
		return nil, err
	}
	var toDelete []string
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "guijia-") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		if name == "guijia-proxy.conf" || name == "guijia-acme-default.conf" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(confDir, name))
		if err != nil {
			continue
		}
		servers := parseNginxServers(string(data))
		seen := map[string]bool{}
		var names []string
		for _, s := range servers {
			for _, n := range s.names {
				ln := strings.ToLower(n)
				if !seen[ln] {
					seen[ln] = true
					names = append(names, ln)
				}
			}
		}
		if len(names) == 0 {
			continue
		}
		allMigrated := true
		for _, n := range names {
			if !managedDomains[n] {
				allMigrated = false
				break
			}
		}
		if allMigrated {
			toDelete = append(toDelete, filepath.Join(confDir, name))
		}
	}
	sort.Strings(toDelete)
	return toDelete, nil
}

// managedFromContent: 从 vhost 文件内容反推管理集（端口 → 域名），用于同步失败
// 回滚后：磁盘文件即还原后的旧文件，解析它得到真实管理集（与 running 配置一致）。
func managedFromContent(content string) map[int]map[string]bool {
	out := map[int]map[string]bool{}
	for _, s := range parseNginxServers(content) {
		for _, l := range s.listens {
			for _, n := range s.names {
				ln := strings.ToLower(n)
				if ln == "" || ln == "_" {
					continue
				}
				if out[l.port] == nil {
					out[l.port] = map[string]bool{}
				}
				out[l.port][ln] = true
			}
		}
	}
	return out
}

// nginxProxySync: 写新文件 + 删迁移旧文件 → -t → reload。任一步失败全部还原、
// 不 reload（-t 失败时 running 配置从未被触动，还原后无需 reload；reload 失败
// 同样还原，保证磁盘与 running 一致）。返回失败阶段（"" 表示成功）。
func nginxProxySync(confDir, newContent string, toDelete []string, testFunc, reloadFunc func() error) string {
	proxyPath := filepath.Join(confDir, "guijia-proxy.conf")
	type backup struct {
		path    string
		content *string // nil 表示原先不存在
	}
	var backups []backup
	readBackup := func(path string) *string {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		s := string(data)
		return &s
	}
	backups = append(backups, backup{path: proxyPath, content: readBackup(proxyPath)})
	for _, p := range toDelete {
		c := readBackup(p)
		if c == nil {
			continue // 计划时读到、同步时消失：视为已删，不再处理
		}
		backups = append(backups, backup{path: p, content: c})
	}
	restore := func() {
		for _, b := range backups {
			if b.content == nil {
				os.Remove(b.path)
			} else {
				os.WriteFile(b.path, []byte(*b.content), 0644)
			}
		}
	}
	if err := os.WriteFile(proxyPath, []byte(newContent), 0644); err != nil {
		restore()
		return "write"
	}
	for _, p := range toDelete {
		if err := os.Remove(p); err != nil {
			restore()
			return "write"
		}
	}
	if err := testFunc(); err != nil {
		restore()
		return "test"
	}
	if err := reloadFunc(); err != nil {
		restore()
		return "reload"
	}
	return ""
}

// nginxProxyNeedsSync: 是否需要写文件 + reload。内容与磁盘一致且无待删文件时
// 不动（避免每次 apply 都无意义 reload）。
func nginxProxyNeedsSync(confDir, newContent string, toDelete []string) bool {
	if len(toDelete) > 0 {
		return true
	}
	cur, err := os.ReadFile(filepath.Join(confDir, "guijia-proxy.conf"))
	if err != nil {
		return true
	}
	return string(cur) != newContent
}

// nginxProxyManage: proxyApply 末尾调用（frontApply 之后），全程持有 proxyMu。
// 收集候选 → 解析证书 → 生成内容 → 迁移规划 → 同步（-t 门 + reload）→ 更新状态。
// 成功/无变化时管理集 = 本次计算集；同步失败时管理集 = 还原后磁盘文件解析集；
// 门禁不通过时管理集与生成错误清零（回落上一轮行为），文件原样不动。
func nginxProxyManage() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if !nginxProxyShouldManage() {
		proxyManaged = map[int]map[string]bool{}
		proxyGenErr = map[string]string{}
		return
	}
	conflict443 := front443HasConflict()
	// 收集候选：已启用且至少一个监听在冲突端口（协议须与该端口胜出协议一致；
	// 443 仅 https，走 front443 冲突标志；80 规则无绑定失败，不在管理范围）。
	var candidates []*ProxyRule
	for _, r := range proxyCfg.Rules {
		if r == nil || !r.Enabled {
			continue
		}
		for _, l := range r.Listens {
			var ok bool
			if l.Port == 443 {
				ok = l.Protocol == "https" && conflict443
			} else {
				ok = proxyConflictPorts[l.Port] && proxyPortProto[l.Port] == l.Protocol
			}
			if ok {
				candidates = append(candidates, r)
				break
			}
		}
	}
	// 解析证书与生成条目：单条跳过只影响该条（记 genErr），绝不丢掉其他规则的块。
	genErr := map[string]string{}
	var entries []nginxProxyEntry
	for _, r := range candidates {
		var conflicted []ProxyListen
		needsTLS := false
		for _, l := range r.Listens {
			var ok bool
			if l.Port == 443 {
				ok = l.Protocol == "https" && conflict443
			} else {
				ok = proxyConflictPorts[l.Port] && proxyPortProto[l.Port] == l.Protocol
			}
			if ok {
				conflicted = append(conflicted, l)
				if l.Protocol == "https" {
					needsTLS = true
				}
			}
		}
		if len(conflicted) == 0 {
			continue
		}
		crt, key, reason := resolveNginxProxyCert(r, needsTLS, proxyCerts, proxyServing)
		if reason != "" {
			genErr[r.Domain] = reason
			continue
		}
		entries = append(entries, nginxProxyEntry{rule: r, listens: conflicted, certPath: crt, keyPath: key})
	}
	managedByPort := map[int]map[string]bool{}
	managedDomains := map[string]bool{}
	for _, e := range entries {
		managedDomains[strings.ToLower(e.rule.Domain)] = true
		for _, l := range e.listens {
			if managedByPort[l.Port] == nil {
				managedByPort[l.Port] = map[string]bool{}
			}
			managedByPort[l.Port][strings.ToLower(e.rule.Domain)] = true
		}
	}
	newContent := buildNginxProxyContent(entries)
	confDir := filepath.Dir(nginxProxyConf)
	toDelete, err := planNginxProxyMigration(confDir, managedDomains)
	if err != nil {
		// 迁移规划读目录失败：不写文件、不 reload；管理集以磁盘现况为准，
		// 未被管理的候选规则记红字原因。
		proxyManaged = managedFromDisk(confDir)
		for _, e := range entries {
			if !domainInManaged(proxyManaged, e.rule.Domain) {
				genErr[e.rule.Domain] = "读取 nginx 配置目录失败"
			}
		}
		proxyGenErr = genErr
		return
	}
	if !nginxProxyNeedsSync(confDir, newContent, toDelete) {
		proxyManaged = managedByPort
		proxyGenErr = genErr
		return
	}
	stage := nginxProxySync(confDir, newContent, toDelete, nginxProxyTestFunc, nginxProxyReloadFunc)
	if stage == "" {
		proxyManaged = managedByPort
		proxyGenErr = genErr
		return
	}
	// 同步失败：已全部还原，管理集以还原后磁盘文件为准；未被管理的候选规则记红字原因。
	proxyManaged = managedFromDisk(confDir)
	reason := "nginx 配置写入失败，已还原"
	if stage == "test" {
		reason = "nginx 配置校验失败，已还原"
	} else if stage == "reload" {
		reason = "nginx reload 失败，已还原"
	}
	for _, e := range entries {
		if !domainInManaged(proxyManaged, e.rule.Domain) {
			genErr[e.rule.Domain] = reason
		}
	}
	proxyGenErr = genErr
}

// managedFromDisk: 读管理文件并解析出管理集（文件不存在/读不到时为空集）。
func managedFromDisk(confDir string) map[int]map[string]bool {
	data, err := os.ReadFile(filepath.Join(confDir, "guijia-proxy.conf"))
	if err != nil {
		return map[int]map[string]bool{}
	}
	return managedFromContent(string(data))
}

// domainInManaged: 域名是否在任一端口的管理集中。
func domainInManaged(managed map[int]map[string]bool, domain string) bool {
	want := strings.ToLower(domain)
	for _, set := range managed {
		if set[want] {
			return true
		}
	}
	return false
}
