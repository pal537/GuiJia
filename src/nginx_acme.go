package main

// nginx 代答 HTTP-01 v2（v1 已推翻，见下）。
//
// v1 失败的实测教训（Oracle 真机，nginx 1.22.1）：
//   - 80 站点全是 Certbot 式 server 层 return 404/301 块；v1 只往各文件补 include，
//     验证文件送不到（v1 还把 include 加进了每文件的首个 server 块而非 80 块）；
//   - v1 把备份写进 sites-enabled/，nginx 的 sites-enabled/* 把 .bak 当配置加载出重块。
//   v1 代码已全部删掉，不要往回加 include 路线。
//
// v2 打法（两层，缺一不可）：
//   a. 常驻：新建 /etc/nginx/conf.d/guijia-acme-default.conf，唯一内容是一个
//      listen 80 default_server 块，内含验证 location + 其余 return 404。
//      不碰任何现有 vhost；无匹配域名的请求（新域名、IP 探针）都落到它上面。
//      已有其他 default_server 时不建第二个，直接报错说明。
//   b. 临时改写（Certbot 套路）：申请的域名若命中现有 80 块，申请期间临时改写
//      该块——注释掉 server 层 return、加入验证 location，验证完无论成败都还原
//      （defer + 面板启动自愈标记），备份只写数据目录，绝不进 nginx include 目录。
//   探针是最终裁判：安装后必须 127.0.0.1 与无匹配 Host 两路都取到探针文件才算通过。

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// 可测试变量：测试可注入假 nginx 与临时路径。
	nginxBinary      = "nginx"
	nginxProbeBase   = "http://127.0.0.1"
	nginxProbeTimout = 10 * time.Second
	// 探针重试：覆盖 reload 后旧 worker 退出前的短暂窗口。
	nginxProbeRetryAttempts = 6
	nginxProbeRetryDelay    = 500 * time.Millisecond
	nginxDefaultConf        = "/etc/nginx/conf.d/guijia-acme-default.conf"
	nginxEnsureMu           sync.Mutex
)

// nginxChallengeDir: 验证文件目录（nginx worker 须可读：目录 0755、文件 0644）。
func nginxChallengeDir() string {
	return filepath.Join(dataDir, "acme-challenge")
}

// nginxWriteChallenge: 写一个验证文件（nginx 方式与自测探针共用）。
func nginxWriteChallenge(token, keyAuth string) error {
	if err := os.MkdirAll(nginxChallengeDir(), 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(nginxChallengeDir(), token), []byte(keyAuth), 0644)
}

// nginxRemoveChallenge: 删验证文件（不存在不报错）。
func nginxRemoveChallenge(token string) {
	os.Remove(filepath.Join(nginxChallengeDir(), token))
}

// nginxChallengeLocation: 验证 location（常驻块与临时改写共用同一段）。
func nginxChallengeLocation() string {
	return "    location ^~ /.well-known/acme-challenge/ {\n" +
		"        alias " + nginxChallengeDir() + "/;\n" +
		"        default_type text/plain;\n" +
		"    }\n"
}

// nginxDefaultConfContent: 常驻代答块内容（由 dataDir 生成，不写死路径）。
func nginxDefaultConfContent() string {
	return "# guijia ACME nginx 代答（面板自动管理；删此文件即停用代答）\n" +
		"server {\n" +
		"    listen 80 default_server;\n" +
		"    server_name _;\n" +
		nginxChallengeLocation() +
		"    location / {\n" +
		"        return 404;\n" +
		"    }\n" +
		"}\n"
}

// ---------- nginx -T 解析（纯函数，可单测） ----------

type nginxDumpFile struct {
	Path    string
	Content string
}

// parseNginxDump: 按 "# configuration file <路径>:" 切分 nginx -T 输出。
func parseNginxDump(dump string) []nginxDumpFile {
	var files []nginxDumpFile
	seen := map[string]bool{}
	var cur *nginxDumpFile
	flush := func() {
		if cur != nil && !seen[cur.Path] {
			seen[cur.Path] = true
			files = append(files, *cur)
		}
		cur = nil
	}
	// Split 末尾的空元素是 dump 结尾换行切出来的，不是文件内容；
	// 不去掉它，每个文件解析后都会多一个换行，还原就做不到字节一致。
	lines := strings.Split(dump, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "# configuration file ") {
			flush()
			p := strings.TrimSpace(strings.TrimPrefix(line, "# configuration file "))
			p = strings.TrimSuffix(p, ":")
			cur = &nginxDumpFile{Path: p}
			continue
		}
		if cur != nil {
			cur.Content += line + "\n"
		}
	}
	flush()
	return files
}

// stripNginxComment: 去掉行内注释（# 在引号外才算注释起头）。
func stripNginxComment(line string) string {
	var inSingle, inDouble bool
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		} else if c == '#' && !inSingle && !inDouble {
			return line[:i]
		}
	}
	return line
}

type nginxBlock struct {
	Start            int // server { 所在行（0 起）
	End              int // 配对 } 所在行
	ServerName       string
	ServerNames      []string
	Listens80        bool
	HasDefaultServer bool
	HasChallengeLoc  bool // 块内已有验证 location（临时改写时跳过，避免重复 location 导致 -t 失败）
	ReturnLine       int  // server 层 return 所在行（块的直接子级，不在 location 内）；无则 -1
}

var (
	nginxServerRe = regexp.MustCompile(`^\s*server\s*\{`)
	nginxListenRe = regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	nginxNameRe   = regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	nginxReturnRe = regexp.MustCompile(`^\s*return\s+`)
	nginxChalRe   = regexp.MustCompile(`location\s+[^;{]*\.well-known/acme-challenge`)
)

// listenIs80: listen 参数是否落在 80 端口（80、*:80、IP:80、[::]:80 及带后缀的都算）。
func listenIs80(params string) bool {
	f := strings.Fields(params)
	if len(f) == 0 {
		return false
	}
	addr := f[0]
	if strings.HasPrefix(addr, "[") {
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			return addr[i+1:] == "80"
		}
		return false
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:] == "80"
	}
	return addr == "80"
}

// listenHasDefault: listen 参数是否带 default_server。
func listenHasDefault(params string) bool {
	for _, f := range strings.Fields(params) {
		if f == "default_server" {
			return true
		}
	}
	return false
}

// analyzeNginxBlocks: 找文件里全部 server 块（花括号配对），并算 80 监听、
// default_server、验证 location 与 server 层 return 情况。
// server 层 return 的判定靠花括号深度：块内深度为 1 的行才是块的直接子级，
// location 内的 return 深度 >= 2，不算。
func analyzeNginxBlocks(content string) []nginxBlock {
	raw := strings.Split(content, "\n")
	stripped := make([]string, len(raw))
	for i, l := range raw {
		stripped[i] = stripNginxComment(l)
	}
	var blocks []nginxBlock
	for i := 0; i < len(stripped); i++ {
		line := stripped[i]
		start := -1
		if nginxServerRe.MatchString(line) {
			start = i
		} else if strings.TrimSpace(line) == "server" && i+1 < len(stripped) && strings.HasPrefix(strings.TrimSpace(stripped[i+1]), "{") {
			start = i + 1
		}
		if start < 0 {
			continue
		}
		// 从 start 行的 { 起数花括号（引号内不算），同时记每行起始深度。
		depth := 0
		end := -1
		lineDepth := make([]int, len(stripped))
		for j := start; j < len(stripped); j++ {
			lineDepth[j] = depth
			var inSingle, inDouble bool
			for k := 0; k < len(stripped[j]); k++ {
				c := stripped[j][k]
				if c == '\'' && !inDouble {
					inSingle = !inSingle
				} else if c == '"' && !inSingle {
					inDouble = !inDouble
				} else if !inSingle && !inDouble {
					if c == '{' {
						depth++
					} else if c == '}' {
						depth--
						if depth == 0 {
							end = j
							break
						}
					}
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			continue // 未闭合的块不碰
		}
		b := nginxBlock{Start: start, End: end, ReturnLine: -1}
		for j := start; j <= end; j++ {
			if m := nginxListenRe.FindStringSubmatch(stripped[j]); m != nil {
				if listenIs80(m[1]) {
					b.Listens80 = true
				}
				if listenHasDefault(m[1]) {
					b.HasDefaultServer = true
				}
			}
			if m := nginxNameRe.FindStringSubmatch(stripped[j]); m != nil {
				for _, n := range strings.Fields(m[1]) {
					b.ServerNames = append(b.ServerNames, n)
					if b.ServerName == "" {
						b.ServerName = n
					}
				}
			}
			if nginxChalRe.MatchString(stripped[j]) {
				b.HasChallengeLoc = true
			}
			if lineDepth[j] == 1 && nginxReturnRe.MatchString(stripped[j]) && b.ReturnLine < 0 {
				b.ReturnLine = j
			}
		}
		blocks = append(blocks, b)
		i = end // 块内不再找 server
	}
	return blocks
}

// serverNameMatches: server_name 是否命中域名（精确匹配，或单层通配符 *.example.com）。
func serverNameMatches(domain string, names []string) bool {
	for _, n := range names {
		if n == domain {
			return true
		}
		if strings.HasPrefix(n, "*.") {
			suf := n[1:] // .example.com
			if strings.HasSuffix(domain, suf) {
				rest := domain[:len(domain)-len(suf)]
				if rest != "" && !strings.Contains(rest, ".") {
					return true
				}
			}
		}
	}
	return false
}

// blockChallengePlan: 80 块的代答方案（回归证据，见 TestChallengePlanRegression）。
//   - 已有验证 location：不重复加 location，但 server 层 return 仍会压过它，
//     所以有 return 的仍需改写（只注释 return，不加 location）；
//   - 无验证 location：必须临时改写——只加 location 在 Certbot 式 return 块上
//     实测送不到（v1 教训），所以 return 块还要同时注释掉 server 层 return。
//
// 返回 (需改写, 需注释 return, 需加 location)。
func blockChallengePlan(b nginxBlock) (needEdit, commentReturn, addLoc bool) {
	if !b.Listens80 {
		return false, false, false
	}
	if b.HasChallengeLoc {
		return b.ReturnLine >= 0, b.ReturnLine >= 0, false
	}
	return true, b.ReturnLine >= 0, true
}

// ---------- 系统交互 ----------

// runNginx: 跑 nginx 子命令；-T 取 stdout，失败时错误里带 stderr。
func runNginx(args ...string) (string, error) {
	cmd := exec.Command(nginxBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("nginx %s 失败: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}

func nginxDump() (string, error) {
	out, err := runNginx("-T")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "executable file not found") {
			return "", errors.New("未找到 nginx 可执行文件")
		}
		return "", err
	}
	return out, nil
}

// nginxBackupRoot: 备份根目录（数据目录下，绝不进任何 nginx include 目录——v1 教训）。
func nginxBackupRoot() string {
	return filepath.Join(dataDir, "nginx-backups")
}

// nginxBackupPath: 某 nginx 配置文件在某次备份目录下的备份路径（/ 展平成 _）。
func nginxBackupPath(backupDir, nginxPath string) string {
	rel := strings.TrimPrefix(nginxPath, "/")
	return filepath.Join(backupDir, strings.ReplaceAll(rel, "/", "_"))
}

// nginxTempEditMarkerPath: 临时改写标记（面板启动自愈的依据）。
func nginxTempEditMarkerPath() string {
	return filepath.Join(dataDir, "nginx-temp-edit.json")
}

type nginxTempEditFile struct {
	Path   string `json:"path"`
	Backup string `json:"backup"`
}

type nginxTempEditMarker struct {
	BackupDir string              `json:"backupDir"`
	Files     []nginxTempEditFile `json:"files"`
}

// ---------- 常驻代答块 ----------

// nginxAcmeStatusInfo: 代答配置检测结果（只读，不改动、不 reload、不探活）。
type nginxAcmeStatusInfo struct {
	OK               bool   `json:"ok"`
	Detail           string `json:"detail"`
	DefaultInstalled bool   `json:"defaultInstalled"`
	DefaultCurrent   bool   `json:"defaultCurrent"`
	ForeignDefault   string `json:"foreignDefault"`
	Servers80        int    `json:"servers80"`
}

// getNginxAcmeStatus: 纯文件/配置检查。
func getNginxAcmeStatus() (nginxAcmeStatusInfo, error) {
	dump, err := nginxDump()
	if err != nil {
		return nginxAcmeStatusInfo{}, err
	}
	st := nginxAcmeStatusInfo{}
	want := nginxDefaultConfContent()
	if b, rerr := os.ReadFile(nginxDefaultConf); rerr == nil {
		st.DefaultInstalled = true
		st.DefaultCurrent = string(b) == want
	}
	for _, f := range parseNginxDump(dump) {
		for _, b := range analyzeNginxBlocks(f.Content) {
			if !b.Listens80 {
				continue
			}
			st.Servers80++
			if b.HasDefaultServer && f.Path != nginxDefaultConf {
				st.ForeignDefault = fmt.Sprintf("%s（%s）", b.ServerName, f.Path)
			}
		}
	}
	switch {
	case st.ForeignDefault != "":
		st.Detail = "nginx 已有 default_server（" + st.ForeignDefault + "），面板不再新建第二个，请手动处理"
	case !st.DefaultInstalled || !st.DefaultCurrent:
		st.Detail = "常驻代答块未安装或内容过期，需安装"
	default:
		st.OK = true
		st.Detail = fmt.Sprintf("常驻代答块正常：%d 个 80 站点，无匹配域名时由代答块接管", st.Servers80)
	}
	return st, nil
}

// nginxInstallDefault: 安装常驻代答块。已是最新则无改动（不 -t 不 reload，幂等）；
// 改动过才 -t + 平滑 reload；-t 失败还原并报错；已有其他 default_server 时拒绝。
func nginxInstallDefault() (bool, error) {
	nginxEnsureMu.Lock()
	defer nginxEnsureMu.Unlock()
	want := nginxDefaultConfContent()
	if cur, rerr := os.ReadFile(nginxDefaultConf); rerr == nil && string(cur) == want {
		return false, nil
	}
	dump, err := nginxDump()
	if err != nil {
		return false, err
	}
	for _, f := range parseNginxDump(dump) {
		for _, b := range analyzeNginxBlocks(f.Content) {
			if b.Listens80 && b.HasDefaultServer && f.Path != nginxDefaultConf {
				return false, fmt.Errorf("nginx 已有 default_server（%s，%s），面板不再新建第二个，请手动处理", b.ServerName, f.Path)
			}
		}
	}
	// 备份旧的常驻块（只备份面板自己的文件，进数据目录）。
	backupDir := filepath.Join(nginxBackupRoot(), time.Now().Format("20060102-150405"))
	if cur, rerr := os.ReadFile(nginxDefaultConf); rerr == nil {
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			return false, err
		}
		if err := os.WriteFile(nginxBackupPath(backupDir, nginxDefaultConf), cur, 0644); err != nil {
			return false, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(nginxDefaultConf), 0755); err != nil {
		return false, err
	}
	if err := os.WriteFile(nginxDefaultConf, []byte(want), 0644); err != nil {
		return false, err
	}
	if _, err := runNginx("-t"); err != nil {
		// 还原：有旧备份则拷回，否则删新建文件。
		bak := nginxBackupPath(backupDir, nginxDefaultConf)
		if b, rerr := os.ReadFile(bak); rerr == nil {
			os.WriteFile(nginxDefaultConf, b, 0644)
		} else {
			os.Remove(nginxDefaultConf)
		}
		return false, fmt.Errorf("nginx -t 未通过，已还原: %w", err)
	}
	if _, err := runNginx("-s", "reload"); err != nil {
		return true, fmt.Errorf("配置已更新并通过 -t，但 reload 失败，请手动执行 nginx -s reload: %w", err)
	}
	return true, nil
}

// ---------- 探针（两路） ----------

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 极小概率回退到时间戳（探针内容随机性要求不高，失败即报错即可）。
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// nginxProbeOnce: 对一个 Host 取一次探针文件，要求 200 且内容一致。
func nginxProbeOnce(name, want, host string) error {
	url := strings.TrimSuffix(nginxProbeBase, "/") + "/.well-known/acme-challenge/" + name
	var resp *http.Response
	var err error
	client := &http.Client{Timeout: nginxProbeTimout}
	if host == "" {
		resp, err = client.Get(url)
	} else {
		var req *http.Request
		req, err = http.NewRequest("GET", url, nil)
		if err == nil {
			req.Host = host
			resp, err = client.Do(req)
		}
	}
	if err != nil {
		return fmt.Errorf("探针请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != want {
		return fmt.Errorf("探针未通过：HTTP %d", resp.StatusCode)
	}
	return nil
}

// nginxProbeRetry: 带重试的单路探针。nginx 平滑 reload 后旧 worker 退出前
// 仍可能接新连接（旧配置、无代答块），立即探针会吃到一次 404；重试几次
// 等旧 worker 退完即可通过，避免 reload 后误判失败。
func nginxProbeRetry(name, want, host string) error {
	var err error
	for i := 0; i < nginxProbeRetryAttempts; i++ {
		if i > 0 {
			time.Sleep(nginxProbeRetryDelay)
		}
		if err = nginxProbeOnce(name, want, host); err == nil {
			return nil
		}
	}
	return err
}

// nginxProbeAll: 写一个探针文件，两路验证（127.0.0.1 直连 + 无匹配 Host，
// 后者模拟尚无 nginx 站点的新域名），两路都过才算通过；事后删文件。
func nginxProbeAll() error {
	name := randHex(16)
	want := randHex(16)
	if err := nginxWriteChallenge(name, want); err != nil {
		return fmt.Errorf("写探针文件失败: %w", err)
	}
	defer nginxRemoveChallenge(name)
	if err := nginxProbeRetry(name, want, ""); err != nil {
		return fmt.Errorf("127.0.0.1 探针失败（请确认 nginx 已 reload 且常驻代答块已生效）: %w", err)
	}
	unmatched := "guijia-probe-" + randHex(8) + ".invalid"
	if err := nginxProbeRetry(name, want, unmatched); err != nil {
		return fmt.Errorf("无匹配域名探针失败（Host %s，请确认常驻代答块是 default_server）: %w", unmatched, err)
	}
	return nil
}

// nginxInstallDefaultAndProbe: 安装常驻块 + 两路自测（申请入口与检查按钮共用）。
func nginxInstallDefaultAndProbe() (bool, error) {
	changed, err := nginxInstallDefault()
	if err != nil {
		return changed, err
	}
	if err := nginxProbeAll(); err != nil {
		return changed, err
	}
	return changed, nil
}

// ---------- 临时改写（命中块，Certbot 套路） ----------

// nginxTempEdit: 对命中域名的 80 块做临时改写，返回还原函数。
// 流程：找命中块 → 备份到数据目录 → 写标记 → 改写（注释 return + 加 location）
// → -t（失败立即还原）→ reload。还原函数：拷回备份 → -t → reload → 清标记；
// 还原失败时保留标记（下次启动自愈重试），并返回错误。
func nginxTempEdit(domains []string) (func() error, error) {
	nginxEnsureMu.Lock()
	defer nginxEnsureMu.Unlock()
	dump, err := nginxDump()
	if err != nil {
		return nil, err
	}
	type fileEdit struct {
		path     string
		orig     string
		edited   string
		needEdit bool
	}
	edits := map[string]*fileEdit{}
	for _, f := range parseNginxDump(dump) {
		// 常驻块的 server_name 是 _，永远不命中真实域名，天然跳过。
		blocks := analyzeNginxBlocks(f.Content)
		need := false
		for _, b := range blocks {
			for _, d := range domains {
				if strings.HasPrefix(d, "*.") {
					continue // 通配符不走 nginx 方式（上层已拦），这里防御性跳过
				}
				if serverNameMatches(d, b.ServerNames) {
					if ne, _, _ := blockChallengePlan(b); ne {
						need = true
					}
				}
			}
		}
		if need {
			edits[f.Path] = &fileEdit{path: f.Path, orig: f.Content}
		}
	}
	if len(edits) == 0 {
		// 无命中块（新域名走常驻块）或命中块无需改写（已有 location 且无 return）：无需临时改写。
		return func() error { return nil }, nil
	}
	// 逐文件应用改写（块倒序，保证行号不移位；先注释 return 再插 location）。
	for _, fe := range edits {
		blocks := analyzeNginxBlocks(fe.orig)
		lines := strings.Split(fe.orig, "\n")
		for i := len(blocks) - 1; i >= 0; i-- {
			b := blocks[i]
			hit := false
			for _, d := range domains {
				if serverNameMatches(d, b.ServerNames) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			needEdit, commentReturn, addLoc := blockChallengePlan(b)
			if !needEdit {
				continue
			}
			if commentReturn && b.ReturnLine >= 0 {
				lines[b.ReturnLine] = "# guijia-temp " + lines[b.ReturnLine]
			}
			if addLoc {
				loc := strings.Split(strings.TrimSuffix(nginxChallengeLocation(), "\n"), "\n")
				nl := append([]string{}, lines[:b.Start+1]...)
				nl = append(nl, loc...)
				nl = append(nl, lines[b.Start+1:]...)
				lines = nl
			}
		}
		fe.edited = strings.Join(lines, "\n")
	}
	// 备份 + 写标记（先标记后改写，崩溃也能自愈）。
	backupDir := filepath.Join(nginxBackupRoot(), time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, err
	}
	marker := nginxTempEditMarker{BackupDir: backupDir}
	for _, fe := range edits {
		bak := nginxBackupPath(backupDir, fe.path)
		if err := os.WriteFile(bak, []byte(fe.orig), 0644); err != nil {
			return nil, err
		}
		marker.Files = append(marker.Files, nginxTempEditFile{Path: fe.path, Backup: bak})
	}
	mb, _ := json.Marshal(marker)
	if err := os.WriteFile(nginxTempEditMarkerPath(), mb, 0644); err != nil {
		return nil, err
	}
	// restoreFromMarkerFile: 读标记 → 拷回备份 → -t → reload → 清标记。
	// 调用方须已持有 nginxEnsureMu（本函数内不加锁，避免临时改写失败路径上死锁）。
	restoreFromMarkerFile := func() error {
		mb, rerr := os.ReadFile(nginxTempEditMarkerPath())
		if rerr != nil {
			return nil // 标记已不在，视为已还原
		}
		var m nginxTempEditMarker
		if jerr := json.Unmarshal(mb, &m); jerr != nil {
			return jerr
		}
		for _, f := range m.Files {
			b, rerr := os.ReadFile(f.Backup)
			if rerr != nil {
				return fmt.Errorf("读备份失败 %s: %w", f.Backup, rerr)
			}
			mode := os.FileMode(0644)
			if st, serr := os.Stat(f.Path); serr == nil {
				mode = st.Mode()
			}
			if werr := os.WriteFile(f.Path, b, mode); werr != nil {
				return fmt.Errorf("还原失败 %s: %w", f.Path, werr)
			}
		}
		if _, err := runNginx("-t"); err != nil {
			return fmt.Errorf("还原后 nginx -t 未通过: %w", err)
		}
		if _, err := runNginx("-s", "reload"); err != nil {
			return fmt.Errorf("还原后 reload 失败，请手动执行 nginx -s reload: %w", err)
		}
		os.Remove(nginxTempEditMarkerPath())
		return nil
	}
	restore := func() error {
		nginxEnsureMu.Lock()
		defer nginxEnsureMu.Unlock()
		return restoreFromMarkerFile() // 失败时保留标记，下次启动自愈重试
	}
	for _, fe := range edits {
		mode := os.FileMode(0644)
		if st, serr := os.Stat(fe.path); serr == nil {
			mode = st.Mode()
		}
		if err := os.WriteFile(fe.path, []byte(fe.edited), mode); err != nil {
			restoreFromMarkerFile()
			return nil, err
		}
	}
	if _, err := runNginx("-t"); err != nil {
		restoreFromMarkerFile()
		return nil, fmt.Errorf("临时改写后 nginx -t 未通过，已还原: %w", err)
	}
	if _, err := runNginx("-s", "reload"); err != nil {
		// 配置已是合法新配置但 reload 失败：返回还原函数，调用方尽力还原；
		// 若调用方也没还原成，标记仍在，下次启动自愈重试。
		return restore, fmt.Errorf("临时改写已生效但 reload 失败，请手动执行 nginx -s reload: %w", err)
	}
	return restore, nil
}

// nginxHealTempEdits: 面板启动自愈——上次临时改写未清理（崩溃）时先还原再 reload。
// 只记日志，绝不卡启动；nginx 不存在时直接跳过。
func nginxHealTempEdits() {
	mb, err := os.ReadFile(nginxTempEditMarkerPath())
	if err != nil {
		return
	}
	var m nginxTempEditMarker
	if err := json.Unmarshal(mb, &m); err != nil {
		fmt.Fprintln(os.Stderr, "nginx 临时改写标记损坏，跳过自愈:", err)
		return
	}
	nginxEnsureMu.Lock()
	defer nginxEnsureMu.Unlock()
	for _, f := range m.Files {
		b, rerr := os.ReadFile(f.Backup)
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "nginx 自愈读备份失败:", f.Backup, rerr)
			return
		}
		mode := os.FileMode(0644)
		if st, serr := os.Stat(f.Path); serr == nil {
			mode = st.Mode()
		}
		if werr := os.WriteFile(f.Path, b, mode); werr != nil {
			fmt.Fprintln(os.Stderr, "nginx 自愈还原失败:", f.Path, werr)
			return
		}
	}
	if _, err := runNginx("-t"); err != nil {
		fmt.Fprintln(os.Stderr, "nginx 自愈后 -t 未通过:", err)
		return
	}
	if _, err := runNginx("-s", "reload"); err != nil {
		fmt.Fprintln(os.Stderr, "nginx 自愈后 reload 失败:", err)
		return
	}
	os.Remove(nginxTempEditMarkerPath())
	fmt.Fprintln(os.Stderr, "nginx 临时改写已自愈还原")
}

// ---------- 接口（均走登录鉴权，路由挂在 /api/ 下） ----------

func handleNginxAcmeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	st, err := getNginxAcmeStatus()
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}

func handleNginxAcmeEnsure(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	changed, err := nginxInstallDefaultAndProbe()
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	detail := "常驻代答块已是最新，两路自测通过"
	if changed {
		detail = "常驻代答块已安装，两路自测通过"
	}
	writeJSON(w, 200, map[string]any{"changed": changed, "ok": true, "detail": detail})
}
