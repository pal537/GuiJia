package main

// nginx 接管检测（只读判断，不建 vhost、不改 vhost、不 reload）。
//
// 背景：规则端口被其他进程（常见为 nginx）占着绑不上时，规则行显示红字“监听失败”，
// 但当 nginx 里已有该域名的 vhost 在服务时（如 panel.example.com 经 nginx vhost 到面板），
// 流量实际是通的，启用 + 红字自相矛盾。本检测解决这个矛盾：命中接管时规则行显示
// “由 nginx 接管”（绿字，非错误），面板仍不绑该端口。
//
// 触发条件（调用方保证）：仅当某规则端口绑定失败且错误为 address already in use 时
// 才跑；成功绑定、无失败的 apply 不跑。检测失败（无 nginx 二进制、超时、解析不出）
// 一律视为未接管，保持现有红字失败行为不变。

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// nginxTTimeout: nginx -T 执行超时；超时即视为未接管（测试可调小）。
var nginxTTimeout = 5 * time.Second

// runNginxTDump: 真实执行 nginx -T 取配置全文（stdout）；失败或超时返回错误。
func runNginxTDump() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nginxTTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nginxBinary, "-T")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", errors.New("nginx -T 超时")
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return stdout.String(), nil
}

// nginxTDumpFunc: 可注入的 dump 入口（单测注入样本输出或错误，不调真实 nginx）。
var nginxTDumpFunc = runNginxTDump

// nginxListen: 一个 listen 指令解析结果。
type nginxListen struct {
	port int
	ssl  bool
}

// nginxServer: 一个 server 块解析结果（仅 server_name 与 listen，location 等内层不解析）。
type nginxServer struct {
	names   []string
	listens []nginxListen
}

// stripNginxComments: 按行去注释。# 只有行首或空白后才视为注释起止，
// 避免伤到值里的 #（如引号内或紧贴 token 的 #）。
func stripNginxComments(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if j := strings.Index(ln, "#"); j >= 0 {
			if j == 0 || ln[j-1] == ' ' || ln[j-1] == '\t' {
				lines[i] = ln[:j]
			}
		}
	}
	return strings.Join(lines, "\n")
}

func isNginxWordByte(c byte) bool {
	return c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// indexNginxServerBlock: 从 from 起找下一个 server 块左大括号下标；
// 要求 server 为独立单词且其后（跳过空白，含换行）紧跟 '{'。
// server_name、upstream 内的 server 指令等均不满足，不会误判。
func indexNginxServerBlock(s string, from int) int {
	for i := from; i+6 <= len(s); {
		idx := strings.Index(s[i:], "server")
		if idx < 0 {
			return -1
		}
		pos := i + idx
		beforeOK := pos == 0 || !isNginxWordByte(s[pos-1])
		afterOK := pos+6 >= len(s) || !isNginxWordByte(s[pos+6])
		if beforeOK && afterOK {
			j := pos + 6
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j < len(s) && s[j] == '{' {
				return j
			}
		}
		i = pos + 6
	}
	return -1
}

// parseNginxServers: 解析 nginx -T 全文，抽出全部 server 块（仅顶层 server_name 与 listen）。
// 大括号不配对时停在该处，不 panic、不误报。
func parseNginxServers(dump string) []nginxServer {
	s := stripNginxComments(dump)
	var servers []nginxServer
	i := 0
	for i < len(s) {
		open := indexNginxServerBlock(s, i)
		if open < 0 {
			break
		}
		depth := 0
		k := open
		for k < len(s) {
			if s[k] == '{' {
				depth++
			} else if s[k] == '}' {
				depth--
				if depth == 0 {
					break
				}
			}
			k++
		}
		if depth != 0 {
			break
		}
		servers = append(servers, parseNginxServerBody(s[open+1:k]))
		i = k + 1
	}
	return servers
}

// parseNginxServerBody: 解析单个 server 块体，只读顶层（大括号深度 0）的分号语句。
func parseNginxServerBody(body string) nginxServer {
	var srv nginxServer
	depth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ';':
			if depth == 0 {
				applyNginxServerStmt(&srv, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	return srv
}

func applyNginxServerStmt(srv *nginxServer, stmt string) {
	f := strings.Fields(stmt)
	if len(f) == 0 {
		return
	}
	switch f[0] {
	case "server_name":
		srv.names = append(srv.names, f[1:]...)
	case "listen":
		if l, ok := parseNginxListen(f[1:]); ok {
			srv.listens = append(srv.listens, l)
		}
	}
}

// parseNginxListen: 解析 listen 指令 token。地址形式：端口、IP:端口、[IPv6]:端口、*:端口；
// ssl 与否看任意位置有无 ssl token（default_server/http2 等顺序不限）。
func parseNginxListen(tokens []string) (nginxListen, bool) {
	if len(tokens) == 0 {
		return nginxListen{}, false
	}
	addr := tokens[0]
	var portStr string
	if strings.HasPrefix(addr, "[") {
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			portStr = addr[i+1:]
		} else {
			return nginxListen{}, false
		}
	} else if i := strings.LastIndex(addr, ":"); i >= 0 {
		portStr = addr[i+1:]
	} else {
		portStr = addr
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return nginxListen{}, false
	}
	ssl := false
	for _, t := range tokens[1:] {
		if t == "ssl" {
			ssl = true
		}
	}
	return nginxListen{port: p, ssl: ssl}, true
}

// nginxServes: 当且仅当某 server 块同时满足 server_name 精确包含域名
// （通配符规则接受通配符 token 本身；server_name _ 永不匹配）且 listen 包含该端口
// （https 规则要求 ssl，http 规则不要求）时返回 true。
func nginxServes(servers []nginxServer, domain string, port int, isTLS bool) bool {
	want := strings.ToLower(strings.TrimSpace(domain))
	if want == "" || want == "_" {
		return false
	}
	for _, s := range servers {
		okPort := false
		for _, l := range s.listens {
			if l.port == port && (!isTLS || l.ssl) {
				okPort = true
				break
			}
		}
		if !okPort {
			continue
		}
		for _, n := range s.names {
			if strings.ToLower(n) == want {
				return true
			}
		}
	}
	return false
}

// matchNginxTakeover: 在已解析的 server 列表里，返回被 nginx 接管的域名集合（纯函数，可单测）。
func matchNginxTakeover(servers []nginxServer, domains []string, port int, isTLS bool) map[string]bool {
	got := map[string]bool{}
	for _, d := range domains {
		if nginxServes(servers, d, port, isTLS) {
			got[d] = true
		}
	}
	return got
}

// detectNginxTakeover: 跑一次 nginx -T 并判定给定域名在该端口上是否被 nginx 接管；
// 任何失败（无二进制、超时、非零退出）都返回空集（视为未接管）。
func detectNginxTakeover(domains []string, port int, isTLS bool) map[string]bool {
	out, err := nginxTDumpFunc()
	if err != nil {
		return map[string]bool{}
	}
	return matchNginxTakeover(parseNginxServers(out), domains, port, isTLS)
}
