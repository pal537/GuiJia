package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var errTestSentinel = errors.New("injected nginx -T failure")

// nginx -T 样本输出：覆盖精确/通配/端口/ssl/注释/upstream/多域名/换行大括号等分支。
const takeoverSampleDump = `
# configuration file /etc/nginx/nginx.conf:
events {}
http {
    # configuration file /etc/nginx/conf.d/guijia-acme-default.conf:
    server {
        listen 80 default_server;
        server_name _;
        location ^~ /.well-known/acme-challenge/ { alias /var/lib/guijia/acme-challenge/; }
    }
    # configuration file /etc/nginx/sites-enabled/files.example.com:
    server {
        listen 443 ssl; # managed by Certbot
        server_name files.example.com;
        location / { proxy_pass http://127.0.0.1:8080; }
    }
    # configuration file /etc/nginx/conf.d/guijia-gui.conf:
    server {
        listen 443 ssl;
        server_name panel.example.com;
        location / { proxy_pass http://127.0.0.1:59188; }
    }
    # configuration file /etc/nginx/sites-enabled/plain.conf:
    server {
        listen 80;
        server_name plain.example.com;
    }
    # configuration file /etc/nginx/sites-enabled/wild.conf:
    server {
        listen [::]:443 ssl;
        server_name *.example.com;
    }
    # configuration file /etc/nginx/sites-enabled/nossl.conf:
    server {
        listen 8443;
        server_name nossl.example.com;
    }
    # configuration file /etc/nginx/sites-enabled/ip.conf:
    server {
        listen 127.0.0.1:8443 ssl;
        server_name ip.example.com;
    }
    # configuration file /etc/nginx/sites-enabled/multi.conf:
    server {
        listen 443 ssl http2;
        server_name multi1.com multi2.com;
    }
    # configuration file /etc/nginx/sites-enabled/noservername.conf:
    server {
        listen 443 ssl;
    }
    # configuration file /etc/nginx/sites-enabled/nextline.conf:
    server
    {
        listen 443 ssl;
        server_name nextline.example.com;
    }
    # configuration file /etc/nginx/sites-enabled/upstream.conf:
    upstream backend {
        server 127.0.0.1:8080;
    }
}
`

func TestParseNginxServers(t *testing.T) {
	servers := parseNginxServers(takeoverSampleDump)
	// 10 个 server 块（upstream 不算）；acme 默认块 server_name _ 也算一个。
	if len(servers) != 10 {
		t.Fatalf("应解析出 10 个 server 块，实际 %d", len(servers))
	}
	var gui *nginxServer
	for i := range servers {
		for _, n := range servers[i].names {
			if n == "panel.example.com" {
				gui = &servers[i]
			}
		}
	}
	if gui == nil {
		t.Fatal("未找到 panel.example.com 的 server 块")
	}
	if len(gui.listens) != 1 || gui.listens[0].port != 443 || !gui.listens[0].ssl {
		t.Fatalf("gui 块 listen 解析错误：%+v", gui.listens)
	}
}

func TestNginxServes(t *testing.T) {
	servers := parseNginxServers(takeoverSampleDump)
	cases := []struct {
		domain string
		port   int
		tls    bool
		want   bool
	}{
		{"panel.example.com", 443, true, true},    // 精确命中
		{"files.example.com", 443, true, true},    // listen 行尾注释不影响
		{"plain.example.com", 80, false, true},    // http 非 ssl 监听
		{"plain.example.com", 443, true, false},   // 端口不符
		{"panel.example.com", 80, false, false},   // 该域名无 80 监听
		{"*.example.com", 443, true, true},        // 通配符规则接受通配符 token 本身
		{"a.example.com", 443, true, false},       // 具体域名不匹配通配符 token
		{"_", 443, true, false},                   // server_name _ 永不匹配
		{"nossl.example.com", 8443, true, false},  // https 规则要求 ssl
		{"nossl.example.com", 8443, false, true},  // http 规则不要求 ssl
		{"ip.example.com", 8443, true, true},      // IP:端口形式
		{"multi2.com", 443, true, true},           // 多域名 server_name
		{"nextline.example.com", 443, true, true}, // 大括号换行
		{"missing.example.com", 443, true, false}, // 无匹配
		{"PANEL.EXAMPLE.COM", 443, true, true},    // 大小写不敏感
	}
	for _, c := range cases {
		if got := nginxServes(servers, c.domain, c.port, c.tls); got != c.want {
			t.Errorf("nginxServes(%q,%d,%v)=%v，想要 %v", c.domain, c.port, c.tls, got, c.want)
		}
	}
	if nginxServes(parseNginxServers(""), "panel.example.com", 443, true) {
		t.Error("空输出不应命中")
	}
	if nginxServes(parseNginxServers("server { listen 443 ssl; server_name a.com;"), "a.com", 443, true) {
		t.Error("大括号不配对应不命中、不 panic")
	}
}

func TestDetectNginxTakeoverInjected(t *testing.T) {
	old := nginxTDumpFunc
	defer func() { nginxTDumpFunc = old }()
	nginxTDumpFunc = func() (string, error) { return takeoverSampleDump, nil }
	got := detectNginxTakeover([]string{"panel.example.com", "missing.example.com"}, 443, true)
	if !got["panel.example.com"] {
		t.Error("应检测到 panel.example.com 被接管")
	}
	if got["missing.example.com"] {
		t.Error("不应检测到 missing.example.com 被接管")
	}
	nginxTDumpFunc = func() (string, error) { return "", errTestSentinel }
	if got := detectNginxTakeover([]string{"panel.example.com"}, 443, true); len(got) != 0 {
		t.Errorf("dump 失败应视为未接管，实际 %v", got)
	}
}

func TestRunNginxTDumpTimeout(t *testing.T) {
	dir := t.TempDir()
	script := dir + "/nginx"
	// 注意：必须用 exec sleep，让 sleep 成为被 kill 的直接子进程；否则 shell 被杀后
	// sleep 仍握着输出管道，cmd.Wait 会等满 10 秒（Go 的经典坑，与超时逻辑本身无关）。
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 10\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	old := nginxTTimeout
	nginxTTimeout = 50 * time.Millisecond
	defer func() { nginxTTimeout = old }()
	start := time.Now()
	if _, err := runNginxTDump(); err == nil {
		t.Fatal("假 nginx 睡眠应触发超时错误")
	} else if !strings.Contains(err.Error(), "超时") {
		t.Fatalf("应为超时错误，实际 %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("超时等待过久：%v", time.Since(start))
	}
}

func TestProxySnapshotTakeover(t *testing.T) {
	proxyMu.Lock()
	oldCfg, oldErr, oldTake := proxyCfg, proxyPortErr, proxyTakeover
	proxyCfg = defaultProxyConfig()
	proxyCfg.Rules = []*ProxyRule{{
		ID: "r1", Domain: "panel.example.com", Enabled: true,
		Listens: []ProxyListen{{Port: 443, Protocol: "https"}},
	}}
	proxyPortErr = map[int]string{}
	proxyTakeover = map[int]map[string]bool{}
	proxyMu.Unlock()
	defer func() {
		proxyMu.Lock()
		proxyCfg, proxyPortErr, proxyTakeover = oldCfg, oldErr, oldTake
		proxyMu.Unlock()
	}()

	front443Mu.Lock()
	oldOn, oldFerr, oldFtk := front443On, front443Err, front443Takeover
	front443On, front443Err = false, "端口 443 已被 nginx 占用，面板无法同时监听同一端口"
	front443Takeover = map[string]bool{"panel.example.com": true}
	front443Mu.Unlock()
	defer func() {
		front443Mu.Lock()
		front443On, front443Err, front443Takeover = oldOn, oldFerr, oldFtk
		front443Mu.Unlock()
	}()

	snap := proxySnapshot()
	st, ok := snap["status"].(map[string]any)
	if !ok {
		t.Fatal("快照无 status")
	}
	ports, ok := st["ports"].([]map[string]any)
	if !ok {
		t.Fatal("快照无 ports")
	}
	var entry map[string]any
	for _, p := range ports {
		if p["port"] == 443 {
			entry = p
		}
	}
	if entry == nil {
		t.Fatal("快照无 443 端口项")
	}
	if entry["error"] == "" {
		t.Error("443 应仍带绑定错误文本")
	}
	tk, _ := entry["takeover"].([]string)
	found := false
	for _, d := range tk {
		if d == "panel.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("443 takeover 应含 panel.example.com，实际 %v", tk)
	}

	// 未接管时 takeover 为空（UI 回落红字失败）。
	front443Mu.Lock()
	front443Takeover = map[string]bool{}
	front443Mu.Unlock()
	snap = proxySnapshot()
	st = snap["status"].(map[string]any)
	ports = st["ports"].([]map[string]any)
	for _, p := range ports {
		if p["port"] == 443 {
			if tk, _ := p["takeover"].([]string); len(tk) != 0 {
				t.Errorf("未接管时 takeover 应为空，实际 %v", tk)
			}
		}
	}
}
