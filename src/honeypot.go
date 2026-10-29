package main

// 蜜罐(第 6 项): 默认关; 只做 TCP; 监听 = 完成握手后立即关闭, 不回任何
// banner、不读 payload、不仿真登录页面; 对方数据只记录、不执行。
// 命中 = 完成 TCP 握手(accept 成功), 不算 raw SYN(防伪造源 IP 的 SYN 泛洪
// 借本应用的手误伤无辜 IP)。
// 前置条件(规格): 必须在软路由上把蜜罐端口转发到 NAS 本机, 否则 0 命中
// 不是坏了, 是没转发; 蜜罐别走雷池(来源 IP 会被挡一层)。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HoneypotConfig struct {
	Enabled      bool  `json:"enabled"`      // 总开关, 默认关
	Ports        []int `json:"ports"`        // 蜜罐端口
	AutoBan      bool  `json:"autoBan"`      // 自动拉黑, 默认关
	AlertEnabled bool  `json:"alertEnabled"` // 命中报警, 默认开
	HitThreshold int   `json:"hitThreshold"` // 命中 N 次即封, 默认 1
	BanHours     int   `json:"banHours"`     // 封 T 小时, 默认 24
}

var honeypotPresets = []struct {
	Port  int    `json:"port"`
	Label string `json:"label"`
}{
	{22, "SSH 爆破"}, {3389, "RDP 爆破"}, {23, "Telnet"}, {6379, "Redis 未授权"},
	{3306, "MySQL 未授权"}, {2375, "Docker API"}, {5555, "ADB"}, {5900, "VNC"},
}

// 静态保留端口: 80/443 走雷池的真服务入口, 绝不能当蜜罐。
var honeypotStaticDeny = map[int]bool{80: true, 443: true}

var (
	honeypotFile      string
	honeypotCfg       = HoneypotConfig{AlertEnabled: true, HitThreshold: 1, BanHours: 24}
	honeypotMu        sync.Mutex
	honeypotListeners = map[int]net.Listener{}
	honeypotIPHits    = map[string]int{}   // 公网非信任 IP -> 累计命中(内存, 重启清零)
	honeypotIPAlertAt = map[string]int64{} // IP -> 上次命中报警时间(10 分钟聚合)
	honeypotPortHits  = map[int]int{}      // 端口 -> 今日命中(内存)
	honeypotPortDay   = ""                 // portHits 的日期(中国时间)
	honeypotDeadAlert = map[int]int64{}    // 端口 -> 上次死亡报警时间(1 小时节流)
)

func loadHoneypot() {
	if b, err := os.ReadFile(honeypotFile); err == nil {
		json.Unmarshal(b, &honeypotCfg)
	} else {
		// 无文件 = 从未开启过: 显式回到包默认值(蜜罐关), 避免残留态被误带进来。
		// 本函数只在启动 loadAll 里调用, 保存路径恒写文件, 故此分支不影响已开启的用户。
		honeypotCfg = HoneypotConfig{AlertEnabled: true, HitThreshold: 1, BanHours: 24}
	}
	if honeypotCfg.HitThreshold < 1 {
		honeypotCfg.HitThreshold = 1
	}
	// 0 = 永久封禁, 只纠负数回默认 24 小时(旧配置恒 ≥1, 故 0 只代表用户新填的永久)。
	if honeypotCfg.BanHours < 0 {
		honeypotCfg.BanHours = 24
	}
}

func saveHoneypot() {
	saveJSON(honeypotFile, honeypotCfg)
}

func honeypotIsEnabled(port int) bool {
	honeypotMu.Lock()
	defer honeypotMu.Unlock()
	if !honeypotCfg.Enabled {
		return false
	}
	for _, p := range honeypotCfg.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// ---------- 监听生命周期 ----------

func honeypotServe(port int) {
	ln, err := net.Listen("tcp", ":"+itoa(port))
	if err != nil {
		return
	}
	honeypotMu.Lock()
	honeypotListeners[port] = ln
	honeypotMu.Unlock()
	honeypotServeFrom(ln, port)
}

func honeypotStopAll() {
	honeypotMu.Lock()
	lns := make([]net.Listener, 0, len(honeypotListeners))
	for _, ln := range honeypotListeners {
		lns = append(lns, ln)
	}
	honeypotListeners = map[int]net.Listener{}
	honeypotMu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
}

// honeypotStartAll 启动全部已启用端口(启动期专用): 单个端口冲突则跳过
// 该端口并报警, 绝不因一个端口卡住整个启动。
func honeypotStartAll() {
	honeypotMu.Lock()
	cfg := honeypotCfg
	honeypotMu.Unlock()
	if !cfg.Enabled {
		return
	}
	for _, p := range cfg.Ports {
		if confs := honeypotValidate([]int{p}); len(confs) > 0 {
			emit(Event{Type: "honeypot_status", Detail: fmt.Sprintf("蜜罐端口 %d 启动跳过: %s(%s)", p, confs[0].Layer, confs[0].Detail)}, cfg.AlertEnabled)
			continue
		}
		go honeypotServe(p)
	}
}

// honeypotApply 全量应用新配置: 硬校验不过 -> 拒绝(旧监听不动);
// 历史流量警告未确认 -> 返回 needConfirm(不动); 通过后停旧起新,
// 起新失败则回滚旧配置旧监听(失败不丢已有蜜罐)。
func honeypotApply(cfg HoneypotConfig, confirm bool) (needConfirm bool, history []int, err error) {
	// 归一化: 去重 + 排序
	seen := map[int]bool{}
	ports := []int{}
	for _, p := range cfg.Ports {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	cfg.Ports = ports
	if cfg.HitThreshold < 1 {
		cfg.HitThreshold = 1
	}
	// 0 = 永久封禁(applyBan 里 hours<=0 即 Until=0), 只纠负数回默认 24 小时。
	if cfg.BanHours < 0 {
		cfg.BanHours = 24
	}
	if cfg.Enabled {
		if confs := honeypotValidate(ports); len(confs) > 0 {
			msgs := make([]string, 0, len(confs))
			for _, c := range confs {
				msgs = append(msgs, fmt.Sprintf("端口 %d: %s(%s)", c.Port, c.Layer, c.Detail))
			}
			return false, nil, fmt.Errorf("蜜罐校验拒绝: %s", strings.Join(msgs, "; "))
		}
		// 历史流量只对"新加"的端口警告(已在跑的蜜罐端口历史是自己的命中, 不算)
		honeypotMu.Lock()
		oldPorts := map[int]bool{}
		for _, p := range honeypotCfg.Ports {
			oldPorts[p] = true
		}
		honeypotMu.Unlock()
		hist := honeypotHistoryPorts()
		for _, p := range ports {
			if !oldPorts[p] && hist[p] {
				history = append(history, p)
			}
		}
		if len(history) > 0 && !confirm {
			return true, history, nil
		}
	}
	honeypotMu.Lock()
	oldCfg := honeypotCfg
	honeypotMu.Unlock()
	honeypotStopAll()
	honeypotMu.Lock()
	honeypotCfg = cfg
	honeypotMu.Unlock()
	saveHoneypot()
	if cfg.Enabled {
		failed := []int{}
		for _, p := range ports {
			ln, err := net.Listen("tcp", ":"+itoa(p))
			if err != nil {
				failed = append(failed, p)
				continue
			}
			honeypotMu.Lock()
			honeypotListeners[p] = ln
			honeypotMu.Unlock()
			go honeypotServeFrom(ln, p)
		}
		if len(failed) > 0 {
			// 回滚: 停掉刚起的, 恢复旧配置旧监听
			honeypotStopAll()
			honeypotMu.Lock()
			honeypotCfg = oldCfg
			honeypotMu.Unlock()
			saveHoneypot()
			if oldCfg.Enabled {
				for _, p := range oldCfg.Ports {
					go honeypotServe(p)
				}
			}
			return false, nil, fmt.Errorf("蜜罐端口 %v 监听失败, 已回滚旧配置", failed)
		}
	}
	return false, nil, nil
}

// honeypotServeFrom 接管一个已 bind 好的监听器(apply 路径先 bind 探活,
// 再起 accept 循环, 避免 bind 与 serve 之间被抢占的竞态)。
// 监听被关时退出, 并只在登记的仍是自己时摘掉登记(防旧协程误删新监听)。
func honeypotServeFrom(ln net.Listener, port int) {
	for {
		c, err := ln.Accept()
		if err != nil {
			break
		}
		honeypotHit(port, c.RemoteAddr().String())
		c.Close()
	}
	honeypotMu.Lock()
	if honeypotListeners[port] == ln {
		delete(honeypotListeners, port)
	}
	honeypotMu.Unlock()
}

// ---------- 命中处理 ----------

func honeypotHit(port int, remoteAddr string) {
	ip, _ := splitHostPort(remoteAddr)
	pip := net.ParseIP(ip)
	if pip == nil || pip.IsLoopback() || isPrivateIP(pip) {
		return // 内网/回环一律不算命中(housekeep 自拨测也不会自命中)
	}
	honeypotMu.Lock()
	cfg := honeypotCfg
	if honeypotPortDay != time.Now().Format("2006-01-02") {
		honeypotPortDay = time.Now().Format("2006-01-02")
		honeypotPortHits = map[int]int{}
	}
	honeypotPortHits[port]++
	now := time.Now().Unix()
	honeypotMu.Unlock()
	if isTrusted(ip) {
		// 信任 IP: 只报警不封, 并单独提示(可能是自己设备误扫或信任给错了)
		emit(Event{Type: "honeypot_hit", IP: ip, Port: port,
			Detail: fmt.Sprintf("蜜罐命中(信任 IP, 不拉黑): 端口 %d", port)}, cfg.AlertEnabled)
		return
	}
	if isGloballyBanned(ip) {
		// 已全局生效封禁中: 只记事件, 不重复封禁(按端口封禁不算全局, 蜜罐仍可全局封)
		emit(Event{Type: "honeypot_hit", IP: ip, Port: port,
			Detail: fmt.Sprintf("蜜罐命中(已拉黑, 不重复封禁): 端口 %d", port)}, false)
		return
	}
	honeypotMu.Lock()
	honeypotIPHits[ip]++
	hits := honeypotIPHits[ip]
	lastAlert := honeypotIPAlertAt[ip]
	agg := now-lastAlert < 600 // 同一 IP 10 分钟内命中只报一次
	if !agg {
		honeypotIPAlertAt[ip] = now
	}
	honeypotMu.Unlock()
	emit(Event{Type: "honeypot_hit", IP: ip, Port: port,
		Detail: fmt.Sprintf("蜜罐命中: 端口 %d(累计 %d 次)", port, hits)}, cfg.AlertEnabled && !agg)
	if cfg.AutoBan && hits >= cfg.HitThreshold {
		if _, err := applyBan(ip, fmt.Sprintf("蜜罐命中 %d 次", hits), "honeypot", cfg.BanHours); err == nil {
			honeypotMu.Lock()
			delete(honeypotIPHits, ip) // 封禁后重新计数(到期/解封后再来从 0 算)
			honeypotMu.Unlock()
			// 触发封禁时再报一次(聚合之外的第二报)；统计由 statsOnEvent 对
			// honeypot_ban 事件统一计（Bans+1、HoneypotBans+1），这里不直增。
			emit(Event{Type: "honeypot_ban", IP: ip,
				Detail: fmt.Sprintf("蜜罐封禁: 命中 %d 次, 封 %d 小时", hits, cfg.BanHours)}, cfg.AlertEnabled)
		}
	}
}

// honeypotCheckAlive 运行期复核(housekeep 每分钟): 拨测 127.0.0.1,
// 监听死了、端口被别人占了, 不抢、不自动重绑, 直接 TG 报警(每端口 1 小时节流)。
func honeypotCheckAlive() {
	honeypotMu.Lock()
	cfg := honeypotCfg
	honeypotMu.Unlock()
	if !cfg.Enabled {
		return
	}
	now := time.Now().Unix()
	for _, p := range cfg.Ports {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(p), 2*time.Second)
		if err == nil {
			c.Close()
			continue
		}
		honeypotMu.Lock()
		last := honeypotDeadAlert[p]
		if now-last >= 3600 {
			honeypotDeadAlert[p] = now
			honeypotMu.Unlock()
			emit(Event{Type: "honeypot_status",
				Detail: fmt.Sprintf("蜜罐监听已死: 端口 %d 未响应拨测, 未自动重绑, 请检查", p)}, cfg.AlertEnabled)
		} else {
			honeypotMu.Unlock()
		}
	}
}

// ---------- 分层校验(fail-closed) ----------

type honeypotConflict struct {
	Port   int    `json:"port"`
	Layer  string `json:"layer"`
	Detail string `json:"detail"`
}

// appPort: 面板自身监听端口(星标排除自身用)。main() 已解析时直接用,
// 否则读环境变量, 再默认 59188。
func appPort() int {
	if panelPort > 0 {
		return panelPort
	}
	if v := os.Getenv("GUIJIA_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 65535 {
			return n
		}
	}
	return 59188
}

// honeypotValidate 跑 1/2/3/4/6 层硬校验(历史流量是软警告, 不在这里)。
func honeypotValidate(ports []int) []honeypotConflict {
	var confs []honeypotConflict
	seen := map[int]bool{}
	for _, p := range ports {
		// 1 层 格式
		if p < 1 || p > 65535 {
			confs = append(confs, honeypotConflict{p, "格式", "超出 1-65535"})
			continue
		}
		// 2 层 自身: 去重 + 应用自身端口 + 静态保留
		if seen[p] {
			confs = append(confs, honeypotConflict{p, "自身", "重复端口"})
			continue
		}
		seen[p] = true
		if p == 18793 || p == appPort() {
			confs = append(confs, honeypotConflict{p, "自身", "龟甲自身端口"})
			continue
		}
		if honeypotStaticDeny[p] {
			confs = append(confs, honeypotConflict{p, "保留端口", "80/443 走雷池的真服务入口, 绝不能当蜜罐"})
			continue
		}
	}
	if len(confs) > 0 {
		return confs
	}
	// 3 层 系统已知
	known := honeypotKnownPorts()
	for _, p := range ports {
		if who, ok := known[p]; ok {
			confs = append(confs, honeypotConflict{p, "系统已知", who})
		}
	}
	// 范围覆盖的端口同样属于系统已知(位图 O(1), 不展开枚举)
	for _, p := range ports {
		if rangeCovered(p) {
			confs = append(confs, honeypotConflict{p, "系统已知", "监控范围端口"})
		}
	}
	if len(confs) > 0 {
		return confs
	}
	// 4 层 实时监听(ss 全量, 含 127.0.0.1 与 IPv6; 自己在跑的蜜罐监听除外)
	lst := ssListeners()
	honeypotMu.Lock()
	running := map[int]bool{}
	for p := range honeypotListeners {
		running[p] = true
	}
	honeypotMu.Unlock()
	for _, p := range ports {
		if running[p] {
			continue
		}
		if proc, ok := lst[p]; ok {
			d := "有进程在监听"
			if proc != "" {
				d = "进程 " + proc + " 正在监听"
			}
			confs = append(confs, honeypotConflict{p, "实时监听", d})
		}
	}
	if len(confs) > 0 {
		return confs
	}
	// 6 层 终局裁决: 真正 bind 一次, 失败就拒绝(并报出占用进程名);
	// 自己在跑的监听不重复 bind(必失败, 不是占用)
	for _, p := range ports {
		if running[p] {
			continue
		}
		ln, err := net.Listen("tcp", ":"+itoa(p))
		if err != nil {
			d := "bind 失败"
			if proc, ok := lst[p]; ok && proc != "" {
				d = "bind 失败, 占用进程 " + proc
			}
			confs = append(confs, honeypotConflict{p, "终局 bind", d})
			continue
		}
		ln.Close()
	}
	return confs
}

// honeypotKnownPorts 系统已知层: 端口 -> 归属说明。
func honeypotKnownPorts() map[int]string {
	known := map[int]string{}
	if d := detectSSHPort(); d.Detected {
		known[d.Port] = "SSH 端口"
	}
	if d := detectWebUIPort(); d.Detected {
		known[d.Port] = "面板端口"
	}
	known[445] = "SMB 端口"
	// sshd 监听进程(端口可能与配置文件不一致时补一层)
	for p, proc := range ssListeners() {
		if strings.Contains(proc, "sshd") {
			known[p] = "SSH 监听端口"
		}
	}
	mu.Lock()
	for _, pw := range ports {
		if pw == nil {
			continue
		}
		known[pw.Port] = "监控清单端口" + func() string {
			if pw.Name != "" {
				return "(" + pw.Name + ")"
			}
			return ""
		}()
	}
	mu.Unlock()
	for p := range honeypotDockerPorts() {
		known[p] = "Docker 已发布端口"
	}
	for p := range honeypotDNATPorts() {
		known[p] = "DNAT 目标端口"
	}
	return known
}

// honeypotDockerPorts best-effort: docker ps 的已发布宿主端口; docker 不存在
// 或命令失败时返回空集(不阻塞, 实时监听与 bind 层仍兜底)。
func honeypotDockerPorts() map[int]bool {
	out := map[int]bool{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.Ports}}").CombinedOutput()
	if err != nil {
		return out
	}
	re := regexp.MustCompile(`(\d+)->`)
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		if n, err := strconv.Atoi(m[1]); err == nil {
			out[n] = true
		}
	}
	return out
}

// honeypotDNATPorts best-effort: iptables NAT 与 nft 规则集里的 DNAT 目标端口。
func honeypotDNATPorts() map[int]bool {
	out := map[int]bool{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "iptables", "-t", "nat", "-S").CombinedOutput(); err == nil {
		re := regexp.MustCompile(`--to-destination\s+\S+:(\d+)`)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			if n, err := strconv.Atoi(m[1]); err == nil {
				out[n] = true
			}
		}
	}
	if b, err := exec.CommandContext(ctx, "nft", "list", "ruleset").CombinedOutput(); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if !strings.Contains(ln, "dnat") {
				continue
			}
			re := regexp.MustCompile(`:(\d+)`)
			ms := re.FindAllStringSubmatch(ln, -1)
			if len(ms) > 0 {
				if n, err := strconv.Atoi(ms[len(ms)-1][1]); err == nil {
					out[n] = true
				}
			}
		}
	}
	return out
}

// honeypotHistoryPorts 历史流量层(软警告): 过去 7 天连接记录里出现过的端口。
func honeypotHistoryPorts() map[int]bool {
	out := map[int]bool{}
	now := time.Now()
	for i := 0; i < 7; i++ {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		for _, dir := range []string{eventsDir, eventsSrcDir} {
			if dir == "" {
				continue
			}
			b, err := os.ReadFile(dir + "/" + day + ".jsonl")
			if err != nil {
				continue
			}
			for _, ln := range strings.Split(string(b), "\n") {
				if ln == "" {
					continue
				}
				var ev struct {
					Type string `json:"type"`
					Port int    `json:"port"`
				}
				if json.Unmarshal([]byte(ln), &ev) != nil {
					continue
				}
				if (ev.Type == "new_conn" || ev.Type == "new_src") && ev.Port >= 1 {
					out[ev.Port] = true
				}
			}
		}
	}
	return out
}

// ---------- API ----------

func handleHoneypot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		honeypotMu.Lock()
		cfg := honeypotCfg
		status := map[int]bool{}
		for _, p := range cfg.Ports {
			_, status[p] = honeypotListeners[p]
		}
		hits := map[int]int{}
		for p, n := range honeypotPortHits {
			hits[p] = n
		}
		honeypotMu.Unlock()
		writeJSON(w, 200, map[string]any{
			"config": cfg, "presets": honeypotPresets, "status": status, "hitsToday": hits,
			"defaultPorts": map[string]any{"ssh": detectSSHPort(), "webui": detectWebUIPort()},
		})
	case "POST":
		body, _ := io.ReadAll(r.Body)
		var in struct {
			HoneypotConfig
			Confirm bool `json:"confirm"`
		}
		if json.Unmarshal(body, &in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		// 命中报警开关已移到设置页: 蜜罐保存不再传此键时, 沿用现值, 不许静默关掉。
		var raw map[string]any
		if json.Unmarshal(body, &raw) == nil {
			if _, ok := raw["alertEnabled"]; !ok {
				honeypotMu.Lock()
				in.AlertEnabled = honeypotCfg.AlertEnabled
				honeypotMu.Unlock()
			}
		}
		needConfirm, history, err := honeypotApply(in.HoneypotConfig, in.Confirm)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		if needConfirm {
			writeJSON(w, 200, map[string]any{"needConfirm": true, "historyPorts": history})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		http.Error(w, "method", 405)
	}
}
