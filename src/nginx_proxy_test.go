package main

import (
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- 测试辅助 ----------

func pxTestRule(id, domain string, enabled bool, listens []ProxyListen, cert, backend string) *ProxyRule {
	return &ProxyRule{ID: id, Domain: domain, Enabled: enabled, Listens: listens, Cert: cert, Backend: backend}
}

func pxTestServing(id, source, dir, path string, dns []string, notAfter time.Time) *proxyCertEntry {
	return &proxyCertEntry{
		meta: ProxyCertMeta{ID: id, Source: source, Dir: dir, Path: path, DNSNames: dns},
		leaf: &x509.Certificate{DNSNames: dns, NotAfter: notAfter},
	}
}

// pxExtractBlock: 从生成内容里按 server_name 抠出该域名的 server 块原文
// （生成器每块以 "server {" 起、顶层 "}" 止，便于断言“其余块字节不变”）。
func pxExtractBlock(content, domain string) string {
	marker := "server_name " + domain + ";"
	i := strings.Index(content, marker)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(content[:i], "server {")
	if start < 0 {
		return ""
	}
	rest := content[i:]
	j := strings.Index(rest, "\n}\n")
	if j < 0 {
		return ""
	}
	return content[start : i+j+3]
}

// pxManageSetup: 注入 nginxProxyManage 的全部可注入点（临时 confDir、假 root、
// 假 nginx 二进制、记录型 test/reload），返回恢复函数与 reload 调用计数指针。
// 注意：调用方在 setup 后设置 proxyCfg 等全局状态（不持锁），再调 nginxProxyManage。
func pxManageSetup(t *testing.T) (restore func(), reloadCalls *int) {
	t.Helper()
	dir := t.TempDir()
	oldConf, oldBin := nginxProxyConf, nginxBinary
	oldRoot := nginxProxyIsRoot
	oldTest, oldReload := nginxProxyTestFunc, nginxProxyReloadFunc
	oldCfg := proxyCfg
	oldConflict, oldProto := proxyConflictPorts, proxyPortProto
	oldCerts, oldServing := proxyCerts, proxyServing
	oldManaged, oldGenErr := proxyManaged, proxyGenErr
	front443Mu.Lock()
	oldConflict443 := front443Conflict
	front443Mu.Unlock()
	calls := 0
	nginxProxyConf = filepath.Join(dir, "guijia-proxy.conf")
	nginxBinary = "true" // PATH 里必有的真二进制，仅用于 LookPath 门禁；-t/reload 全走注入函数
	nginxProxyIsRoot = func() bool { return true }
	nginxProxyTestFunc = func() error { return nil }
	nginxProxyReloadFunc = func() error { calls++; return nil }
	proxyConflictPorts = map[int]bool{}
	proxyPortProto = map[int]string{}
	proxyCerts = nil
	proxyServing = map[string]*proxyCertEntry{}
	proxyManaged = map[int]map[string]bool{}
	proxyGenErr = map[string]string{}
	return func() {
		nginxProxyConf, nginxBinary = oldConf, oldBin
		nginxProxyIsRoot = oldRoot
		nginxProxyTestFunc, nginxProxyReloadFunc = oldTest, oldReload
		proxyCfg = oldCfg
		proxyConflictPorts, proxyPortProto = oldConflict, oldProto
		proxyCerts, proxyServing = oldCerts, oldServing
		proxyManaged, proxyGenErr = oldManaged, oldGenErr
		front443Mu.Lock()
		front443Conflict = oldConflict443
		front443Mu.Unlock()
	}, &calls
}

func pxSetFront443Conflict(v bool) {
	front443Mu.Lock()
	front443Conflict = v
	front443Mu.Unlock()
}

// ---------- vhost 生成 ----------

func TestNginxProxyBuild(t *testing.T) {
	entries := []nginxProxyEntry{
		{rule: pxTestRule("r2", "b.example.com", true, nil, "acme:b.example.com", "127.0.0.1:8080"),
			listens:  []ProxyListen{{Port: 8443, Protocol: "http"}},
			certPath: "", keyPath: ""},
		{rule: pxTestRule("r1", "a.example.com", true, nil, "acme:a.example.com", "127.0.0.1:59188"),
			listens:  []ProxyListen{{Port: 8443, Protocol: "https"}, {Port: 443, Protocol: "https"}},
			certPath: "/var/lib/guijia/certs/a.example.com/fullchain.pem",
			keyPath:  "/var/lib/guijia/certs/a.example.com/privkey.pem"},
	}
	out := buildNginxProxyContent(entries)
	if !strings.HasPrefix(out, "# 由龟甲面板管理") {
		t.Errorf("文件头应注明面板管理，实际:\n%s", out)
	}
	// 规则按域名排序：a 在 b 前；监听按端口排序：443 在 8443 前。
	ia := strings.Index(out, "server_name a.example.com;")
	ib := strings.Index(out, "server_name b.example.com;")
	if ia < 0 || ib < 0 || ia > ib {
		t.Errorf("规则应按域名排序，a=%d b=%d", ia, ib)
	}
	a443 := pxExtractBlock(out, "a.example.com")
	if !strings.Contains(a443, "listen 443 ssl;") || !strings.Contains(a443, "ssl_certificate /var/lib/guijia/certs/a.example.com/fullchain.pem;") ||
		!strings.Contains(a443, "ssl_certificate_key /var/lib/guijia/certs/a.example.com/privkey.pem;") ||
		!strings.Contains(a443, "proxy_pass http://127.0.0.1:59188;") {
		t.Errorf("a 的 443 块应含 ssl 与后端，实际:\n%s", a443)
	}
	for _, h := range []string{"proxy_set_header Host $host;", "proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;", "proxy_set_header X-Forwarded-Proto $scheme;",
		"proxy_http_version 1.1;", "proxy_set_header Upgrade $http_upgrade;"} {
		if !strings.Contains(out, h) {
			t.Errorf("应含标准头 %s", h)
		}
	}
	// b 只有 http 监听：块内绝不能有 ssl 行。
	bBlock := pxExtractBlock(out, "b.example.com")
	if strings.Contains(bBlock, "ssl_certificate") || !strings.Contains(bBlock, "listen 8443;") {
		t.Errorf("b 的 http 块不应含 ssl 行，实际:\n%s", bBlock)
	}
	// 无管理规则时文件只留注释行，不删文件。
	empty := buildNginxProxyContent(nil)
	if strings.Contains(empty, "server {") {
		t.Errorf("无管理规则时不应有 server 块，实际:\n%s", empty)
	}
}

// ---------- 证书解析 ----------

func TestResolveNginxProxyCert(t *testing.T) {
	now := time.Now()
	serving := map[string]*proxyCertEntry{
		"acme:a.example.com": pxTestServing("acme:a.example.com", "acme", "/var/lib/guijia/certs/a.example.com", "/var/lib/guijia/certs/a.example.com/fullchain.pem", []string{"a.example.com"}, now.Add(24*time.Hour)),
		"upload:up":          pxTestServing("upload:up", "upload", "/var/lib/guijia/certs/up", "/var/lib/guijia/certs/up.crt", []string{"up.example.com"}, now.Add(24*time.Hour)),
		"acme:wild":          pxTestServing("acme:wild", "acme", "/var/lib/guijia/certs/wild", "/var/lib/guijia/certs/wild/fullchain.pem", []string{"*.example.com"}, now.Add(24*time.Hour)),
	}
	metas := []ProxyCertMeta{
		serving["acme:a.example.com"].meta,
		serving["upload:up"].meta,
		{ID: "acme:old.example.com", Source: "acme", Dir: "/var/lib/guijia/certs/old.example.com", Path: "/var/lib/guijia/certs/old.example.com/fullchain.pem", DNSNames: []string{"old.example.com"}, Expired: true},
	}
	cases := []struct {
		name     string
		rule     *ProxyRule
		needsTLS bool
		wantCrt  string
		wantKey  string
		wantErr  string
	}{
		{"纯 HTTP 不需证书", pxTestRule("r", "h.example.com", true, nil, "", "127.0.0.1:80"), false, "", "", ""},
		{"auto 精确匹配", pxTestRule("r", "a.example.com", true, nil, "auto", "127.0.0.1:80"), true, "/var/lib/guijia/certs/a.example.com/fullchain.pem", "/var/lib/guijia/certs/a.example.com/privkey.pem", ""},
		{"auto 通配符匹配", pxTestRule("r", "x.example.com", true, nil, "auto", "127.0.0.1:80"), true, "/var/lib/guijia/certs/wild/fullchain.pem", "/var/lib/guijia/certs/wild/privkey.pem", ""},
		{"auto 无证书跳过", pxTestRule("r", "none.example.org", true, nil, "auto", "127.0.0.1:80"), true, "", "", "无可用证书"},
		{"显式上传证书 key 同名", pxTestRule("r", "up.example.com", true, nil, "upload:up", "127.0.0.1:80"), true, "/var/lib/guijia/certs/up.crt", "/var/lib/guijia/certs/up.key", ""},
		{"显式证书已过期", pxTestRule("r", "old.example.com", true, nil, "acme:old.example.com", "127.0.0.1:80"), true, "", "", "证书已过期"},
		{"显式证书不存在", pxTestRule("r", "a.example.com", true, nil, "acme:ghost.example.com", "127.0.0.1:80"), true, "", "", "证书不存在"},
		{"显式证书与域名不匹配", pxTestRule("r", "other.example.com", true, nil, "upload:up", "127.0.0.1:80"), true, "", "", "证书与域名不匹配"},
	}
	for _, c := range cases {
		crt, key, reason := resolveNginxProxyCert(c.rule, c.needsTLS, metas, serving)
		if crt != c.wantCrt || key != c.wantKey || reason != c.wantErr {
			t.Errorf("%s: 得 crt=%q key=%q reason=%q,  want crt=%q key=%q reason=%q",
				c.name, crt, key, reason, c.wantCrt, c.wantKey, c.wantErr)
		}
	}
}

// ---------- 迁移清理 ----------

func TestPlanNginxProxyMigration(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("guijia-proxy.conf", "# managed\nserver { listen 443 ssl; server_name migrated.example.com; }\n")
	write("guijia-old.conf", "server { listen 443 ssl; server_name migrated.example.com; }\n")
	write("guijia-mixed.conf", "server { listen 443 ssl; server_name migrated.example.com; }\nserver { listen 443 ssl; server_name kept.example.com; }\n")
	write("guijia-keep.conf", "server { listen 443 ssl; server_name kept.example.com; }\n")
	write("guijia-acme-default.conf", "server { listen 80 default_server; server_name _; }\n")
	write("other.conf", "server { listen 443 ssl; server_name migrated.example.com; }\n")
	write("guijia-broken.conf", "server { listen 443 ssl; }\n") // 无 server_name：保留
	toDelete, err := planNginxProxyMigration(dir, map[string]bool{"migrated.example.com": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(toDelete) != 1 || toDelete[0] != filepath.Join(dir, "guijia-old.conf") {
		t.Errorf("只应删域名已迁移的旧文件，得 %v", toDelete)
	}
	// 域名未进入管理集时，旧文件一个都不删。
	toDelete2, err := planNginxProxyMigration(dir, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(toDelete2) != 0 {
		t.Errorf("无管理域名时不应删任何文件，得 %v", toDelete2)
	}
}

// ---------- 同步与 -t 门 ----------

func TestNginxProxySync(t *testing.T) {
	dir := t.TempDir()
	proxyPath := filepath.Join(dir, "guijia-proxy.conf")
	oldPath := filepath.Join(dir, "guijia-old.conf")
	oldContent := "server { listen 443 ssl; server_name a.example.com; }\n"
	if err := os.WriteFile(oldPath, []byte(oldContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyPath, []byte("# old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ok := func() error { return nil }
	fail := func() error { return errTestSentinel }
	// 成功：新文件写上、旧文件删除、reload 调用一次。
	reloads := 0
	if stage := nginxProxySync(dir, "# new\n", []string{oldPath}, ok, func() error { reloads++; return nil }); stage != "" {
		t.Fatalf("成功同步不应有失败阶段，得 %q", stage)
	}
	if got, _ := os.ReadFile(proxyPath); string(got) != "# new\n" {
		t.Errorf("新文件应为新内容，得 %q", got)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("迁移旧文件应已删除")
	}
	if reloads != 1 {
		t.Errorf("成功时 reload 应调用 1 次，得 %d", reloads)
	}
	// -t 失败：新文件与旧文件都恢复原样、不 reload。
	if err := os.WriteFile(oldPath, []byte(oldContent), 0644); err != nil {
		t.Fatal(err)
	}
	if stage := nginxProxySync(dir, "# bad\n", []string{oldPath}, fail, func() error { reloads++; return nil }); stage != "test" {
		t.Errorf("-t 失败阶段应为 test，得 %q", stage)
	}
	if got, _ := os.ReadFile(proxyPath); string(got) != "# new\n" {
		t.Errorf("-t 失败后管理文件应还原，得 %q", got)
	}
	if got, _ := os.ReadFile(oldPath); string(got) != oldContent {
		t.Errorf("-t 失败后旧文件应还原，得 %q", got)
	}
	if reloads != 1 {
		t.Errorf("-t 失败时不应 reload，调用次数 %d", reloads)
	}
	// reload 失败：同样全部还原。
	if stage := nginxProxySync(dir, "# bad2\n", []string{oldPath}, ok, fail); stage != "reload" {
		t.Errorf("reload 失败阶段应为 reload，得 %q", stage)
	}
	if got, _ := os.ReadFile(proxyPath); string(got) != "# new\n" {
		t.Errorf("reload 失败后管理文件应还原，得 %q", got)
	}
	if got, _ := os.ReadFile(oldPath); string(got) != oldContent {
		t.Errorf("reload 失败后旧文件应还原，得 %q", got)
	}
}

func TestNginxProxyNeedsSync(t *testing.T) {
	dir := t.TempDir()
	proxyPath := filepath.Join(dir, "guijia-proxy.conf")
	if nginxProxyNeedsSync(dir, "# x\n", nil) != true {
		t.Errorf("文件不存在时应需要同步")
	}
	if err := os.WriteFile(proxyPath, []byte("# x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if nginxProxyNeedsSync(dir, "# x\n", nil) != false {
		t.Errorf("内容一致且无待删文件时应跳过同步（避免无意义 reload）")
	}
	if nginxProxyNeedsSync(dir, "# y\n", nil) != true {
		t.Errorf("内容不一致时应同步")
	}
	if nginxProxyNeedsSync(dir, "# x\n", []string{filepath.Join(dir, "guijia-old.conf")}) != true {
		t.Errorf("有待删文件时即使内容一致也应同步（删旧文件后必须 reload）")
	}
}

func TestManagedFromContent(t *testing.T) {
	m := managedFromContent("server { listen 443 ssl; server_name a.example.com; }\nserver { listen 8443; server_name b.example.com a.example.com; }\n")
	if !m[443]["a.example.com"] || !m[8443]["b.example.com"] || !m[8443]["a.example.com"] {
		t.Errorf("应解析出端口→域名集，得 %v", m)
	}
	if len(managedFromContent("server { listen 80 default_server; server_name _; }")) != 0 {
		t.Errorf("server_name _ 不应进入管理集")
	}
}

// ---------- manage 钩子：开关语义与多域名独立性 ----------

func TestNginxProxyManageToggleAndIndependence(t *testing.T) {
	restore, reloadCalls := pxManageSetup(t)
	defer restore()
	now := time.Now()
	proxyServing = map[string]*proxyCertEntry{
		"acme:a.example.com": pxTestServing("acme:a.example.com", "acme", "/var/lib/guijia/certs/a.example.com", "/var/lib/guijia/certs/a.example.com/fullchain.pem", []string{"a.example.com"}, now.Add(24*time.Hour)),
		"acme:b.example.com": pxTestServing("acme:b.example.com", "acme", "/var/lib/guijia/certs/b.example.com", "/var/lib/guijia/certs/b.example.com/fullchain.pem", []string{"b.example.com"}, now.Add(24*time.Hour)),
	}
	proxyCerts = []ProxyCertMeta{proxyServing["acme:a.example.com"].meta, proxyServing["acme:b.example.com"].meta}
	ruleA := pxTestRule("ra", "a.example.com", true, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:8080")
	ruleB := pxTestRule("rb", "b.example.com", true, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:8081")
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{ruleA, ruleB}}
	pxSetFront443Conflict(true)

	// 两条同端口 SNI 规则启用 → 文件含两块。
	nginxProxyManage()
	content, err := os.ReadFile(nginxProxyConf)
	if err != nil {
		t.Fatal(err)
	}
	blockA1 := pxExtractBlock(string(content), "a.example.com")
	blockB1 := pxExtractBlock(string(content), "b.example.com")
	if blockA1 == "" || blockB1 == "" {
		t.Fatalf("启用后两块都应存在，实际:\n%s", content)
	}
	if *reloadCalls != 1 {
		t.Errorf("首次生成应 reload 1 次，得 %d", *reloadCalls)
	}
	if !proxyManaged[443]["a.example.com"] || !proxyManaged[443]["b.example.com"] {
		t.Errorf("管理集应含两域名，得 %v", proxyManaged)
	}

	// 停用 b → b 的块消失，a 的块字节不变，reload 再跑一次。
	ruleB.Enabled = false
	nginxProxyManage()
	content, err = os.ReadFile(nginxProxyConf)
	if err != nil {
		t.Fatal(err)
	}
	if pxExtractBlock(string(content), "b.example.com") != "" {
		t.Errorf("停用 b 后 b 的块应消失，实际:\n%s", content)
	}
	if got := pxExtractBlock(string(content), "a.example.com"); got != blockA1 {
		t.Errorf("停用 b 后 a 的块应字节不变，旧:\n%s\n新:\n%s", blockA1, got)
	}
	if *reloadCalls != 2 {
		t.Errorf("停用后应再 reload 1 次，得 %d", *reloadCalls)
	}

	// 删除 a（规则出配置）→ a 的块消失，b 恢复启用后 b 的块与首次字节一致。
	ruleB.Enabled = true
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{ruleB}}
	nginxProxyManage()
	content, err = os.ReadFile(nginxProxyConf)
	if err != nil {
		t.Fatal(err)
	}
	if pxExtractBlock(string(content), "a.example.com") != "" {
		t.Errorf("删除 a 后 a 的块应消失，实际:\n%s", content)
	}
	if got := pxExtractBlock(string(content), "b.example.com"); got != blockB1 {
		t.Errorf("删除 a 后 b 的块应与首次字节一致，旧:\n%s\n新:\n%s", blockB1, got)
	}
}

// 单条规则生成失败只跳过该条、记红字，其余照常生成；且多监听规则只含被占端口。
func TestNginxProxyManageOneFailureKeepsOthers(t *testing.T) {
	restore, _ := pxManageSetup(t)
	defer restore()
	now := time.Now()
	proxyServing = map[string]*proxyCertEntry{
		"acme:a.example.com": pxTestServing("acme:a.example.com", "acme", "/var/lib/guijia/certs/a.example.com", "/var/lib/guijia/certs/a.example.com/fullchain.pem", []string{"a.example.com"}, now.Add(24*time.Hour)),
	}
	proxyCerts = []ProxyCertMeta{proxyServing["acme:a.example.com"].meta}
	ruleA := pxTestRule("ra", "a.example.com", true,
		[]ProxyListen{{Port: 443, Protocol: "https"}, {Port: 8443, Protocol: "https"}}, "auto", "127.0.0.1:8080")
	ruleC := pxTestRule("rc", "c.example.com", true, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:8082")
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{ruleA, ruleC}}
	pxSetFront443Conflict(true)
	// 8443 空闲（不在冲突集里），只应生成 a 的 443 块；c 无证书被跳过。
	nginxProxyManage()
	content, err := os.ReadFile(nginxProxyConf)
	if err != nil {
		t.Fatal(err)
	}
	aBlock := pxExtractBlock(string(content), "a.example.com")
	if aBlock == "" || !strings.Contains(aBlock, "listen 443 ssl;") || strings.Contains(aBlock, "listen 8443") {
		t.Errorf("a 只应含被占的 443 块，实际:\n%s", aBlock)
	}
	if pxExtractBlock(string(content), "c.example.com") != "" {
		t.Errorf("c 无证书应被跳过，实际:\n%s", content)
	}
	if proxyGenErr["c.example.com"] != "无可用证书" {
		t.Errorf("c 应记红字“无可用证书”，得 %v", proxyGenErr)
	}
	if !proxyManaged[443]["a.example.com"] || proxyManaged[443]["c.example.com"] {
		t.Errorf("管理集应只含 a，得 %v", proxyManaged)
	}
	// 给 c 补上证书 → c 进文件，a 的块字节不变。
	proxyServing["acme:c.example.com"] = pxTestServing("acme:c.example.com", "acme", "/var/lib/guijia/certs/c.example.com", "/var/lib/guijia/certs/c.example.com/fullchain.pem", []string{"c.example.com"}, now.Add(24*time.Hour))
	proxyCerts = append(proxyCerts, proxyServing["acme:c.example.com"].meta)
	nginxProxyManage()
	content, err = os.ReadFile(nginxProxyConf)
	if err != nil {
		t.Fatal(err)
	}
	if got := pxExtractBlock(string(content), "a.example.com"); got != aBlock {
		t.Errorf("c 补证书后 a 的块应字节不变，旧:\n%s\n新:\n%s", aBlock, got)
	}
	if pxExtractBlock(string(content), "c.example.com") == "" {
		t.Errorf("c 补证书后应进文件，实际:\n%s", content)
	}
	if proxyGenErr["c.example.com"] != "" {
		t.Errorf("c 进文件后不应再有生成错误，得 %v", proxyGenErr)
	}
}

// 停用全部规则后文件只留注释（不删文件），且手建旧文件（域名未迁移）保留不断服。
func TestNginxProxyManageDisableAllKeepsHandBuilt(t *testing.T) {
	restore, _ := pxManageSetup(t)
	defer restore()
	now := time.Now()
	proxyServing = map[string]*proxyCertEntry{
		"acme:panel.example.com": pxTestServing("acme:panel.example.com", "acme", "/var/lib/guijia/certs/panel.example.com", "/var/lib/guijia/certs/panel.example.com/fullchain.pem", []string{"panel.example.com"}, now.Add(24*time.Hour)),
	}
	proxyCerts = []ProxyCertMeta{proxyServing["acme:panel.example.com"].meta}
	confDir := filepath.Dir(nginxProxyConf)
	handBuilt := filepath.Join(confDir, "guijia-gui.conf")
	if err := os.WriteFile(handBuilt, []byte("server { listen 443 ssl; server_name panel.example.com; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rule := pxTestRule("rg", "panel.example.com", false, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:59188")
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{rule}}
	pxSetFront443Conflict(true)
	nginxProxyManage()
	content, err := os.ReadFile(nginxProxyConf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "server {") {
		t.Errorf("规则停用时管理文件应只留注释，得:\n%s", content)
	}
	if _, err := os.Stat(handBuilt); err != nil {
		t.Errorf("域名未进入管理集的手建文件必须保留，stat 失败: %v", err)
	}
}

// 同步失败时管理集以还原后磁盘文件为准，未被管理的候选规则记红字原因。
func TestNginxProxyManageSyncFailureRestores(t *testing.T) {
	restore, reloadCalls := pxManageSetup(t)
	defer restore()
	now := time.Now()
	proxyServing = map[string]*proxyCertEntry{
		"acme:a.example.com": pxTestServing("acme:a.example.com", "acme", "/var/lib/guijia/certs/a.example.com", "/var/lib/guijia/certs/a.example.com/fullchain.pem", []string{"a.example.com"}, now.Add(24*time.Hour)),
	}
	proxyCerts = []ProxyCertMeta{proxyServing["acme:a.example.com"].meta}
	ruleA := pxTestRule("ra", "a.example.com", true, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:8080")
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{ruleA}}
	pxSetFront443Conflict(true)
	nginxProxyManage() // 先成功一次：文件含 a
	good, _ := os.ReadFile(nginxProxyConf)
	if *reloadCalls != 1 {
		t.Fatalf("前置成功应 reload 1 次，得 %d", *reloadCalls)
	}
	// 改后端并让 -t 失败：新内容写不上，旧文件还原，a 仍在管理集（磁盘现况），
	// reload 不应再跑。
	ruleA.Backend = "127.0.0.1:9090"
	nginxProxyTestFunc = func() error { return errTestSentinel }
	nginxProxyManage()
	after, _ := os.ReadFile(nginxProxyConf)
	if string(after) != string(good) {
		t.Errorf("-t 失败后文件应还原为旧内容，旧:\n%s\n新:\n%s", good, after)
	}
	if !proxyManaged[443]["a.example.com"] {
		t.Errorf("-t 失败后 a 仍在磁盘文件里，管理集应保留它，得 %v", proxyManaged)
	}
	if proxyGenErr["a.example.com"] != "" {
		t.Errorf("-t 失败后 a 已在管理集内，不应记生成错误，得 %v", proxyGenErr)
	}
	if *reloadCalls != 1 {
		t.Errorf("-t 失败时不应 reload，调用次数 %d", *reloadCalls)
	}
	// 再加一条无证书规则 b：同步失败时 b 记红字原因，a 仍绿。
	ruleB := pxTestRule("rb", "b.example.com", true, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:8081")
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{ruleA, ruleB}}
	nginxProxyManage()
	if proxyGenErr["b.example.com"] != "无可用证书" {
		t.Errorf("b 无证书应记“无可用证书”（跳过在同步前），得 %v", proxyGenErr)
	}
}

// 门禁：非 root 或无 nginx 二进制时跳过管理，状态清零、文件不动。
func TestNginxProxyManageGuard(t *testing.T) {
	restore, reloadCalls := pxManageSetup(t)
	defer restore()
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{
		pxTestRule("ra", "a.example.com", true, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:8080"),
	}}
	pxSetFront443Conflict(true)
	nginxProxyIsRoot = func() bool { return false }
	nginxProxyManage()
	if _, err := os.Stat(nginxProxyConf); !os.IsNotExist(err) {
		t.Errorf("非 root 时不应写管理文件")
	}
	if *reloadCalls != 0 {
		t.Errorf("非 root 时不应 reload")
	}
	nginxProxyIsRoot = func() bool { return true }
	nginxBinary = "definitely-not-a-real-binary-xyz"
	nginxProxyManage()
	if _, err := os.Stat(nginxProxyConf); !os.IsNotExist(err) {
		t.Errorf("无 nginx 二进制时不应写管理文件")
	}
}

// ---------- 快照字段 ----------

func TestProxySnapshotManagedGenErr(t *testing.T) {
	oldCfg, oldErr, oldManaged, oldGenErr := proxyCfg, proxyPortErr, proxyManaged, proxyGenErr
	defer func() { proxyCfg, proxyPortErr, proxyManaged, proxyGenErr = oldCfg, oldErr, oldManaged, oldGenErr }()
	proxyCfg = ProxyConfig{Rules: []*ProxyRule{
		pxTestRule("rg", "panel.example.com", true, []ProxyListen{{Port: 443, Protocol: "https"}}, "auto", "127.0.0.1:59188"),
	}}
	proxyPortErr = map[int]string{443: "监听失败: address already in use"}
	proxyManaged = map[int]map[string]bool{443: {"panel.example.com": true}}
	proxyGenErr = map[string]string{"bad.example.com": "无可用证书"}
	snap := proxySnapshot()
	status, _ := snap["status"].(map[string]any)
	ports, _ := status["ports"].([]map[string]any)
	found := false
	for _, p := range ports {
		if p["port"] == 443 {
			found = true
			managed, _ := p["managed"].([]string)
			if len(managed) != 1 || managed[0] != "panel.example.com" {
				t.Errorf("443 端口 managed 应为 [panel.example.com]，得 %v", managed)
			}
		}
	}
	if !found {
		t.Errorf("快照应含 443 端口，ports=%v", ports)
	}
	genErr, _ := status["genErr"].(map[string]string)
	if genErr["bad.example.com"] != "无可用证书" {
		t.Errorf("快照 genErr 应透传，得 %v", genErr)
	}
}

// ---------- UI 徽标行为（抽取 index.html 内函数跑 node） ----------

func TestPxStatusBadgeBehavior(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("本机无 node，跳过徽标行为单测")
	}
	html := string(indexHTML)
	extract := func(start, end string) string {
		s := strings.Index(html, start)
		if s < 0 {
			t.Fatalf("index.html 缺少标记 %q", start)
		}
		e := strings.Index(html[s:], end)
		if e < 0 {
			t.Fatalf("index.html 缺少结束标记 %q", end)
		}
		return html[s : s+e]
	}
	// esc 是一行函数，单独按行取。
	escLine := ""
	for _, line := range strings.Split(html, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "function esc(") {
			escLine = strings.TrimSpace(line)
			break
		}
	}
	if escLine == "" {
		t.Fatal("index.html 缺少 function esc(")
	}
	js := escLine + "\n" + extract("function pxRuleListens(", "function pxStatusBadge(") +
		extract("function pxStatusBadge(", "function renderProxy()") + `
const R=(id,domain,enabled,listens)=>({id,domain,enabled,listens});
const out=[];
out.push(pxStatusBadge(R('r','a.com',false,[{port:443,protocol:'https'}]),{}, {443:'x'}, {}, {}, {}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:443,protocol:'https'}]),{}, {443:'x'}, {}, {443:['a.com']}, {}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:443,protocol:'https'}]),{}, {443:'x'}, {443:['a.com']}, {}, {}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:443,protocol:'https'}]),{}, {443:'x'}, {}, {}, {'a.com':'无可用证书'}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:443,protocol:'https'}]),{}, {443:'监听失败: 占用'}, {}, {}, {}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:443,protocol:'https'}]),{'r':{ok:true}}, {}, {}, {}, {}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:443,protocol:'https'}]),{'r':{ok:false}}, {}, {}, {}, {}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:443,protocol:'https'}]),{}, {}, {}, {}, {}));
out.push(pxStatusBadge(R('r','a.com',true,[{port:8443,protocol:'https'},{port:443,protocol:'https'}]),{}, {8443:'x',443:'y'}, {}, {443:['a.com']}, {'a.com':'无可用证书'}));
console.log(out.join('\n---\n'));
`
	dir := t.TempDir()
	jsPath := filepath.Join(dir, "badge.js")
	if err := os.WriteFile(jsPath, []byte(js), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("node", jsPath).Output()
	if err != nil {
		t.Fatalf("node 执行徽标单测失败: %v\n%s", err, js)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n---\n")
	if len(got) != 9 {
		t.Fatalf("徽标单测应输出 9 行，得 %d 行:\n%s", len(got), out)
	}
	check := func(i int, want string, notWant ...string) {
		if !strings.Contains(got[i], want) {
			t.Errorf("第 %d 组应含 %q，得 %q", i, want, got[i])
		}
		for _, nw := range notWant {
			if strings.Contains(got[i], nw) {
				t.Errorf("第 %d 组不应含 %q，得 %q", i, nw, got[i])
			}
		}
	}
	check(0, "未启用", "由 nginx 接管")
	check(1, "由 nginx 接管")         // 管理内绿字
	check(2, "由 nginx 接管")         // 检测命中绿字
	check(3, "无可用证书", "监听失败")      // 生成失败红字原因
	check(4, "监听失败", "由 nginx 接管") // 普通失败红字
	check(5, "正常")
	check(6, "后端不可达")
	check(7, "未检测")
	check(8, "无可用证书") // 多监听：首个错误监听（8443，genErr）决定颜色，不因 443 被管理而变绿
}
