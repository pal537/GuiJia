package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- 常驻块与解析 ---

func TestDefaultConfContent(t *testing.T) {
	old := dataDir
	dataDir = "/tmp/gj-test-data"
	t.Cleanup(func() { dataDir = old })
	s := nginxDefaultConfContent()
	if !strings.Contains(s, "listen 80 default_server;") {
		t.Errorf("常驻块必须是 80 default_server，得到:\n%s", s)
	}
	if !strings.Contains(s, "server_name _;") {
		t.Errorf("常驻块 server_name 应为 _，得到:\n%s", s)
	}
	if !strings.Contains(s, "location ^~ /.well-known/acme-challenge/") {
		t.Errorf("常驻块应为 ^~ location，得到:\n%s", s)
	}
	if !strings.Contains(s, "alias /tmp/gj-test-data/acme-challenge/;") {
		t.Errorf("常驻块 alias 应随 dataDir 变化，得到:\n%s", s)
	}
	if !strings.Contains(s, "    location / {\n        return 404;\n    }") {
		t.Errorf("常驻块其余路径的 return 404 必须在 location / 内（server 层 return 会压过验证 location），得到:\n%s", s)
	}
}

const nginxTestDump = `# configuration file /etc/nginx/nginx.conf:
user www-data;
http {
    include /etc/nginx/conf.d/*.conf;
}
# configuration file /etc/nginx/sites-enabled/a.conf:
server {
    listen 80;
    listen [::]:80;
    server_name a.example.com www.a.example.com;
}
# configuration file /etc/nginx/sites-enabled/b.conf:
server {
    listen 443 ssl;
    # listen 80;（注释里的 80 不能算）
    server_name b.example.com;
}
# configuration file /etc/nginx/sites-enabled/c.conf:
server {
    listen 80 default_server;
    server_name c.example.com;
}
# configuration file /etc/nginx/sites-enabled/d.conf:
server {
    listen 127.0.0.1:80;
    server_name d.example.com;
}
# configuration file /etc/nginx/sites-enabled/e.conf:
server {
    listen *:80;
    server_name e.example.com;
}
# configuration file /etc/nginx/sites-enabled/f.conf:
server {
    listen 80;
    server_name f.example.com;
    return 404; # managed by Certbot
}
# configuration file /etc/nginx/sites-enabled/g.conf:
server {
    listen 80;
    server_name g.example.com;
    location / {
        return 301 https://$host$request_uri;
    }
}
`

func TestParseNginxDump(t *testing.T) {
	files := parseNginxDump(nginxTestDump)
	if len(files) != 8 {
		t.Fatalf("应切出 8 个文件，得到 %d", len(files))
	}
	byName := map[string]string{}
	for _, f := range files {
		byName[filepath.Base(f.Path)] = f.Content
	}
	a := analyzeNginxBlocks(byName["a.conf"])
	if len(a) != 1 || !a[0].Listens80 || a[0].ServerName != "a.example.com" || len(a[0].ServerNames) != 2 {
		t.Errorf("a.conf 应为 80 监听、多域名，得到 %+v", a)
	}
	b := analyzeNginxBlocks(byName["b.conf"])
	if len(b) != 1 || b[0].Listens80 {
		t.Errorf("b.conf 只有 443（注释里的 80 不算），得到 %+v", b)
	}
	c := analyzeNginxBlocks(byName["c.conf"])
	if len(c) != 1 || !c[0].Listens80 || !c[0].HasDefaultServer {
		t.Errorf("c.conf 应为 80 default_server，得到 %+v", c)
	}
	d := analyzeNginxBlocks(byName["d.conf"])
	if len(d) != 1 || !d[0].Listens80 {
		t.Errorf("d.conf 127.0.0.1:80 应算 80 监听，得到 %+v", d)
	}
	e := analyzeNginxBlocks(byName["e.conf"])
	if len(e) != 1 || !e[0].Listens80 {
		t.Errorf("e.conf *:80 应算 80 监听，得到 %+v", e)
	}
	f := analyzeNginxBlocks(byName["f.conf"])
	if len(f) != 1 || !f[0].Listens80 || f[0].ReturnLine < 0 {
		t.Errorf("f.conf 应为 80 且有 server 层 return，得到 %+v", f)
	}
	g := analyzeNginxBlocks(byName["g.conf"])
	if len(g) != 1 || !g[0].Listens80 || g[0].ReturnLine >= 0 {
		t.Errorf("g.conf 的 return 在 location 内，不算 server 层 return，得到 %+v", g)
	}
}

func TestServerNameMatches(t *testing.T) {
	if !serverNameMatches("a.example.com", []string{"a.example.com", "www.a.example.com"}) {
		t.Error("精确域名应命中")
	}
	if !serverNameMatches("x.example.com", []string{"*.example.com"}) {
		t.Error("单层通配符应命中")
	}
	if serverNameMatches("a.b.example.com", []string{"*.example.com"}) {
		t.Error("多层子域名不应被单层通配符命中")
	}
	if serverNameMatches("other.com", []string{"a.example.com"}) {
		t.Error("不相关域名不应命中")
	}
}

// TestChallengePlanRegression: v1 回归证据——Certbot 式 return 块只加 location
// 在 Oracle 实测中送不到验证文件，因此方案必须是临时改写（注释 return + 加 location），
// 而不是 v1 的 include 路线；已有验证 location 的块不重复加 location，但有 server 层
// return 的仍需注释 return（否则 return 照样压过 location）。
func TestChallengePlanRegression(t *testing.T) {
	ret := "server {\n    listen 80;\n    server_name r.example.com;\n    return 404; # managed by Certbot\n}\n"
	b := analyzeNginxBlocks(ret)[0]
	need, comment, addLoc := blockChallengePlan(b)
	if !need || !comment || !addLoc {
		t.Errorf("return 块应临时改写且注释 return 并加 location，得到 need=%v comment=%v addLoc=%v", need, comment, addLoc)
	}
	proxy := "server {\n    listen 80;\n    server_name p.example.com;\n    location / {\n        proxy_pass http://127.0.0.1:5000;\n    }\n}\n"
	b = analyzeNginxBlocks(proxy)[0]
	need, comment, addLoc = blockChallengePlan(b)
	if !need || comment || !addLoc {
		t.Errorf("普通代理块应临时改写但无需注释 return，得到 need=%v comment=%v addLoc=%v", need, comment, addLoc)
	}
	hasLoc := "server {\n    listen 80;\n    server_name h.example.com;\n    location ^~ /.well-known/acme-challenge/ {\n        alias /var/lib/guijia/acme-challenge/;\n    }\n}\n"
	b = analyzeNginxBlocks(hasLoc)[0]
	need, _, _ = blockChallengePlan(b)
	if need {
		t.Error("已有验证 location 且无 return 的块不应再改写")
	}
	hasLocRet := "server {\n    listen 80;\n    server_name hr.example.com;\n    return 404;\n    location ^~ /.well-known/acme-challenge/ {\n        alias /var/lib/guijia/acme-challenge/;\n    }\n}\n"
	b = analyzeNginxBlocks(hasLocRet)[0]
	need, comment, addLoc = blockChallengePlan(b)
	if !need || !comment || addLoc {
		t.Errorf("已有 location 但有 server 层 return 的块应只注释 return、不重复加 location，得到 need=%v comment=%v addLoc=%v", need, comment, addLoc)
	}
	ssl := "server {\n    listen 443 ssl;\n    server_name s.example.com;\n}\n"
	b = analyzeNginxBlocks(ssl)[0]
	need, _, _ = blockChallengePlan(b)
	if need {
		t.Error("非 80 块不应改写")
	}
}

// --- 假 nginx 与常驻块 / 临时改写 ---

// writeFakeNginx: 在临时目录放一个假 nginx 脚本（-T 吐配置、-t 可控失败、-s reload 记日志）。
func writeFakeNginx(t *testing.T, dir string) (script, log string) {
	t.Helper()
	script = filepath.Join(dir, "nginx")
	log = filepath.Join(dir, "calls.log")
	body := "#!/bin/bash\n" +
		"echo \"$*\" >> \"" + log + "\"\n" +
		"case \"$1\" in\n" +
		"  -T)\n" +
		"    for f in \"" + dir + "\"/*.conf; do echo \"# configuration file $f:\"; cat \"$f\"; done\n" +
		"    ;;\n" +
		"  -t)\n" +
		"    if [ -f \"" + dir + "/fail-t\" ]; then rm \"" + dir + "/fail-t\"; echo test-failed >&2; exit 1; fi\n" +
		"    echo test-ok >&2\n" +
		"    ;;\n" +
		"  -s)\n" +
		"    echo reloaded >> \"" + log + "\"\n" +
		"    ;;\n" +
		"esac\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return script, log
}

func countLog(log, want string) int {
	b, _ := os.ReadFile(log)
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) == want {
			n++
		}
	}
	return n
}

func setupNginxTestEnv(t *testing.T) (vhostDir, log string) {
	t.Helper()
	root := t.TempDir()
	vhostDir = filepath.Join(root, "vhosts")
	if err := os.MkdirAll(vhostDir, 0755); err != nil {
		t.Fatal(err)
	}
	oldBin, oldConf, oldDir := nginxBinary, nginxDefaultConf, dataDir
	dataDir = filepath.Join(root, "data")
	nginxDefaultConf = filepath.Join(root, "guijia-acme-default.conf")
	script, log := writeFakeNginx(t, vhostDir)
	nginxBinary = script
	t.Cleanup(func() { nginxBinary, nginxDefaultConf, dataDir = oldBin, oldConf, oldDir })
	return vhostDir, log
}

func TestInstallDefaultIdempotent(t *testing.T) {
	vhostDir, log := setupNginxTestEnv(t)
	if err := os.WriteFile(filepath.Join(vhostDir, "site.conf"), []byte("server {\n    listen 80;\n    server_name idem.example.com;\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := nginxInstallDefault()
	if err != nil || !changed {
		t.Fatalf("首次安装应改动，changed=%v err=%v", changed, err)
	}
	if countLog(log, "reloaded") != 1 {
		t.Errorf("首次安装应 reload 恰好 1 次")
	}
	if b, _ := os.ReadFile(nginxDefaultConf); string(b) != nginxDefaultConfContent() {
		t.Errorf("常驻块内容应与生成一致，得到:\n%s", b)
	}
	changed2, err := nginxInstallDefault()
	if err != nil || changed2 {
		t.Fatalf("二次安装应幂等无改动，changed=%v err=%v", changed2, err)
	}
	if countLog(log, "reloaded") != 1 {
		t.Errorf("二次安装不应再 reload")
	}
	st, err := getNginxAcmeStatus()
	if err != nil || !st.OK || !st.DefaultInstalled || !st.DefaultCurrent {
		t.Errorf("status 应正常，得到 %+v err=%v", st, err)
	}
}

func TestInstallDefaultForeignConflict(t *testing.T) {
	vhostDir, log := setupNginxTestEnv(t)
	if err := os.WriteFile(filepath.Join(vhostDir, "site.conf"), []byte("server {\n    listen 80 default_server;\n    server_name _;\n    return 404;\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := nginxInstallDefault(); err == nil || !strings.Contains(err.Error(), "default_server") {
		t.Errorf("已有其他 default_server 时应报错拒绝，得到 err=%v", err)
	}
	if _, serr := os.Stat(nginxDefaultConf); serr == nil {
		t.Error("冲突时不应新建常驻块文件")
	}
	if countLog(log, "reloaded") != 0 {
		t.Error("冲突时不应 reload")
	}
}

const tempEditVhost = `server {
    listen 443 ssl;
    server_name a.example.com;
    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
server {
    listen 80;
    server_name a.example.com;
    return 404; # managed by Certbot
}
server {
    listen 80;
    server_name b.example.com;
    return 301 https://$host$request_uri;
}
`

func TestTempEditRestoreByteIdentical(t *testing.T) {
	vhostDir, log := setupNginxTestEnv(t)
	vhostPath := filepath.Join(vhostDir, "site.conf")
	if err := os.WriteFile(vhostPath, []byte(tempEditVhost), 0644); err != nil {
		t.Fatal(err)
	}
	restore, err := nginxTempEdit([]string{"a.example.com"})
	if err != nil || restore == nil {
		t.Fatalf("临时改写应成功，err=%v", err)
	}
	edited, _ := os.ReadFile(vhostPath)
	es := string(edited)
	if !strings.Contains(es, "# guijia-temp     return 404;") {
		t.Errorf("命中块的 server 层 return 应被注释，得到:\n%s", es)
	}
	if !strings.Contains(es, "location ^~ /.well-known/acme-challenge/") {
		t.Errorf("命中块应加入验证 location，得到:\n%s", es)
	}
	// b.example.com 的 301 块未命中：return 必须原样保留。
	if strings.Contains(es, "# guijia-temp     return 301") {
		t.Errorf("未命中块不应被改写，得到:\n%s", es)
	}
	if countLog(log, "reloaded") != 1 {
		t.Errorf("改写后应 reload 恰好 1 次")
	}
	// 备份必须在数据目录下，绝不进 /etc/nginx（v1 教训）。
	mb, err := os.ReadFile(nginxTempEditMarkerPath())
	if err != nil {
		t.Fatalf("改写后应有标记文件，err=%v", err)
	}
	var m nginxTempEditMarker
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 1 {
		t.Fatalf("应恰好备份 1 个文件，得到 %+v", m.Files)
	}
	if !strings.HasPrefix(m.BackupDir, filepath.Join(dataDir, "nginx-backups")) {
		t.Errorf("备份目录应在数据目录下，得到 %s", m.BackupDir)
	}
	if strings.Contains(m.BackupDir, "/etc/nginx") || strings.Contains(m.Files[0].Backup, "/etc/nginx") {
		t.Errorf("备份绝不能进 /etc/nginx，得到 %+v", m)
	}
	if err := restore(); err != nil {
		t.Fatalf("还原应成功，err=%v", err)
	}
	after, _ := os.ReadFile(vhostPath)
	if string(after) != tempEditVhost {
		t.Errorf("还原后应字节一致，得到:\n%s", after)
	}
	if countLog(log, "reloaded") != 2 {
		t.Errorf("还原后应再 reload 1 次（共 2 次）")
	}
	if _, serr := os.Stat(nginxTempEditMarkerPath()); serr == nil {
		t.Error("还原成功后标记应清除")
	}
}

func TestTempEditTestFailureRestores(t *testing.T) {
	vhostDir, log := setupNginxTestEnv(t)
	vhostPath := filepath.Join(vhostDir, "site.conf")
	if err := os.WriteFile(vhostPath, []byte(tempEditVhost), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vhostDir, "fail-t"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := nginxTempEdit([]string{"a.example.com"}); err == nil {
		t.Fatal("nginx -t 失败时临时改写应报错")
	}
	after, _ := os.ReadFile(vhostPath)
	if string(after) != tempEditVhost {
		t.Errorf("失败后 vhost 应还原，得到:\n%s", after)
	}
	if _, serr := os.Stat(nginxTempEditMarkerPath()); serr == nil {
		t.Error("失败后标记应清除（已还原）")
	}
	// 还原本身会 reload 一次（让磁盘与运行中配置收敛；编辑失败时 nginx 从未载入过改写配置，
	// 这次 reload 只是无害收敛，不是“失败后又推了坏配置”）。
	if countLog(log, "reloaded") != 1 {
		t.Errorf("失败后还原应 reload 恰好 1 次，实际 %d 次", countLog(log, "reloaded"))
	}
}

func TestTempEditNoHitNoop(t *testing.T) {
	vhostDir, log := setupNginxTestEnv(t)
	vhostPath := filepath.Join(vhostDir, "site.conf")
	if err := os.WriteFile(vhostPath, []byte(tempEditVhost), 0644); err != nil {
		t.Fatal(err)
	}
	restore, err := nginxTempEdit([]string{"new.example.com"})
	if err != nil || restore == nil {
		t.Fatalf("无命中块时应静默无操作，err=%v", err)
	}
	after, _ := os.ReadFile(vhostPath)
	if string(after) != tempEditVhost {
		t.Error("无命中块时不应改动文件")
	}
	if countLog(log, "reloaded") != 0 {
		t.Error("无命中块时不应 reload")
	}
	if err := restore(); err != nil {
		t.Errorf("无操作还原应成功，err=%v", err)
	}
}

func TestHealTempEdits(t *testing.T) {
	vhostDir, log := setupNginxTestEnv(t)
	vhostPath := filepath.Join(vhostDir, "site.conf")
	if err := os.WriteFile(vhostPath, []byte(tempEditVhost), 0644); err != nil {
		t.Fatal(err)
	}
	// 模拟崩溃残留：文件已被改写、标记与备份都在。
	backupDir := filepath.Join(dataDir, "nginx-backups", "crash")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatal(err)
	}
	bak := nginxBackupPath(backupDir, vhostPath)
	if err := os.WriteFile(bak, []byte(tempEditVhost), 0644); err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(tempEditVhost, "    return 404; # managed by Certbot", "    # guijia-temp     return 404; # managed by Certbot", 1)
	if err := os.WriteFile(vhostPath, []byte(edited), 0644); err != nil {
		t.Fatal(err)
	}
	marker := nginxTempEditMarker{BackupDir: backupDir, Files: []nginxTempEditFile{{Path: vhostPath, Backup: bak}}}
	mb, _ := json.Marshal(marker)
	if err := os.WriteFile(nginxTempEditMarkerPath(), mb, 0644); err != nil {
		t.Fatal(err)
	}
	nginxHealTempEdits()
	after, _ := os.ReadFile(vhostPath)
	if string(after) != tempEditVhost {
		t.Errorf("自愈后应还原，得到:\n%s", after)
	}
	if _, serr := os.Stat(nginxTempEditMarkerPath()); serr == nil {
		t.Error("自愈成功后标记应清除")
	}
	if countLog(log, "reloaded") != 1 {
		t.Errorf("自愈后应 reload 1 次")
	}
}

// --- 探针（两路） ---

func TestNginxProbeTwoHosts(t *testing.T) {
	oldDir, oldBase := dataDir, nginxProbeBase
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDir; nginxProbeBase = oldBase })
	var hosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.Host)
		name := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		b, err := os.ReadFile(filepath.Join(nginxChallengeDir(), name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	nginxProbeBase = srv.URL
	if err := nginxProbeAll(); err != nil {
		t.Fatalf("两路探针应通过: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("应恰好请求 2 次，得到 %v", hosts)
	}
	unmatched := false
	for _, h := range hosts {
		if strings.HasSuffix(h, ".invalid") {
			unmatched = true
		}
	}
	if !unmatched {
		t.Errorf("第二路应用无匹配 Host（.invalid），得到 %v", hosts)
	}
	ents, _ := os.ReadDir(nginxChallengeDir())
	if len(ents) != 0 {
		t.Errorf("探针后文件应清理，残留 %d 个", len(ents))
	}
	// 失败：404 服务。
	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	t.Cleanup(srv404.Close)
	nginxProbeBase = srv404.URL
	if err := nginxProbeAll(); err == nil {
		t.Error("404 时探针应失败")
	}
	ents, _ = os.ReadDir(nginxChallengeDir())
	if len(ents) != 0 {
		t.Errorf("失败后探针文件也应清理，残留 %d 个", len(ents))
	}
}

// TestNginxProbeRetryAfterReloadDrain: reload 后旧 worker 短暂接新连接时
// 前两次探针 404，探针重试应最终通过（Oracle 实测：ensure 内探针曾因此失败，
// 手动再 reload 后才通过）。
func TestNginxProbeRetryAfterReloadDrain(t *testing.T) {
	oldDir, oldBase, oldDelay := dataDir, nginxProbeBase, nginxProbeRetryDelay
	dataDir = t.TempDir()
	nginxProbeRetryDelay = time.Millisecond
	t.Cleanup(func() { dataDir = oldDir; nginxProbeBase = oldBase; nginxProbeRetryDelay = oldDelay })
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if count <= 2 {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		b, err := os.ReadFile(filepath.Join(nginxChallengeDir(), name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	nginxProbeBase = srv.URL
	if err := nginxProbeAll(); err != nil {
		t.Fatalf("前两次 404 后探针重试应通过: %v", err)
	}
	if count < 3 {
		t.Errorf("应至少重试到第 3 次请求，实际 %d 次", count)
	}
}

// --- nginx 方式端到端与解析 ---

func TestOrderCertNginx(t *testing.T) {
	m := newMockAcme(t, "example.com", false)
	acmeTestSetup(t, m)
	m.nginxChallengeDir = dataDir
	client, err := newAcmeClient()
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := client.thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	m.expectedKeyAuth = "tok-123." + thumb
	chain, priv, err := client.orderCert([]string{"example.com"}, "nginx", "")
	if err != nil {
		t.Fatalf("nginx orderCert: %v", err)
	}
	if !strings.Contains(string(chain), "CERTIFICATE") || !strings.Contains(string(priv), "PRIVATE KEY") {
		t.Error("应返回证书链与私钥 PEM")
	}
	ents, _ := os.ReadDir(nginxChallengeDir())
	if len(ents) != 0 {
		t.Errorf("签发后验证文件应清理，残留 %d 个", len(ents))
	}
}

func TestResolveAcmeApplyNginx(t *testing.T) {
	d, m, tok, err := resolveAcmeApply(acmeApplyInput{Domains: []string{"example.com"}, Method: "nginx"}, false, "")
	if err != nil || m != "nginx" || tok != "" || len(d) != 1 {
		t.Errorf("nginx 应无需 80、无需 Token，得到 %v %q %q %v", d, m, tok, err)
	}
	if _, _, _, err := resolveAcmeApply(acmeApplyInput{Domains: []string{"*.example.com"}, Method: "nginx"}, true, ""); err == nil {
		t.Error("通配符 + nginx 应报错（只能 DNS-01）")
	}
	if _, _, _, err := resolveAcmeApply(acmeApplyInput{Domains: []string{"*.example.com"}, Method: "http-01"}, true, ""); err == nil {
		t.Error("通配符 + HTTP-01 应报错")
	}
	if _, m2, _, err := resolveAcmeApply(acmeApplyInput{Domains: []string{"*.example.com"}, Method: "auto"}, true, "tok"); err != nil || m2 != "dns-01" {
		t.Errorf("通配符 + 自动应落到 DNS-01，得到 %q %v", m2, err)
	}
	// 自动保持原样：80 空闲 http-01，80 被占 + Token 走 dns-01，无 Token 报错。
	if _, m3, _, err := resolveAcmeApply(acmeApplyInput{Domains: []string{"example.com"}, Method: "auto"}, true, ""); err != nil || m3 != "http-01" {
		t.Errorf("自动 + 80 空闲应为 http-01，得到 %q %v", m3, err)
	}
	if _, m4, _, err := resolveAcmeApply(acmeApplyInput{Domains: []string{"example.com"}, Method: "auto"}, false, "tok"); err != nil || m4 != "dns-01" {
		t.Errorf("自动 + 80 被占应为 dns-01，得到 %q %v", m4, err)
	}
	if _, _, _, err := resolveAcmeApply(acmeApplyInput{Domains: []string{"example.com"}, Method: "auto"}, false, ""); err == nil {
		t.Error("自动 + 80 被占 + 无 Token 应报错")
	}
}

func TestReadAcmeMetaNginx(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = old })
	if err := writeAcmeMetaGuarded("example.com", acmeCertMeta{Domains: []string{"example.com", "www.example.com"}, Method: "nginx"}); err != nil {
		t.Fatal(err)
	}
	d, m := acmeRenewalPlan("example.com")
	if m != "nginx" || len(d) != 2 {
		t.Errorf("续期应原样沿用 nginx 与域名组，得到 %v %q", d, m)
	}
}

// --- CLI ---

func TestCliNginxStatusEnsure(t *testing.T) {
	vhostDir, _ := setupNginxTestEnv(t)
	vhostPath := filepath.Join(vhostDir, "site.conf")
	if err := os.WriteFile(vhostPath, []byte("server {\n    listen 80;\n    server_name cli.example.com;\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// 未配置时 status 应返回 1。
	if code := cliNginxStatus(); code != 1 {
		t.Errorf("未配置时 nginx-status 应返回 1，得到 %d", code)
	}
	// ensure 本体（不含探针）：改动应发生且幂等。
	changed, err := nginxInstallDefault()
	if err != nil || !changed {
		t.Fatalf("安装应改动，changed=%v err=%v", changed, err)
	}
	if code := cliNginxStatus(); code != 0 {
		t.Errorf("配置后 nginx-status 应返回 0，得到 %d", code)
	}
	// cliMain 路由。
	if code := cliMain([]string{"nginx-status"}); code != 0 {
		t.Errorf("cliMain nginx-status 应返回 0，得到 %d", code)
	}
	// ensure 全套（含探针）：探针基址换成 httptest 冒充 nginx。
	oldBase := nginxProbeBase
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		b, err := os.ReadFile(filepath.Join(nginxChallengeDir(), name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(func() { nginxProbeBase = oldBase; srv.Close() })
	nginxProbeBase = srv.URL
	if code := cliNginxEnsure(); code != 0 {
		t.Errorf("cliNginxEnsure 应返回 0，得到 %d", code)
	}
}
