package main

// 采集层:
// - 每 1 秒采样连接(第 5 项由 5 秒改到 1 秒, 闭口试探的 conntrack 条目默认存活
//   120 秒, 1 秒轮询在实践中不漏; 亚秒级全端口快扫理论上仍可能漏报):
//   ss 取本机 TCP(established + syn-recv 半开), conntrack 补 UDP 与
//   转发给 Docker 容器的 TCP(ss 无套接字看不见); 监控范围 = 清单端口 ∪ 当前所有监听端口
// - 新对端一律计入今日新来源统计(按 IP 去重); 事件/报警只给重点端口的 TCP 新连接
// - 重点端口洪峰检测: 短窗口内不同公网 IP 涌入超阈值 -> 临时关闭该端口(分布式爆破防护)
// - 每 60 秒拍监听快照, 新监听端口连续出现 2 次 -> 事件(哨兵)
// - 尾随系统 auth 日志: SSH 登录成功/失败, 爆破达阈值自动拉黑
//   (路径自动识别 auth.log/secure, 设置里可指定; 面板自身登录事件由鉴权层直接记)
// - housekeep: nft 看门狗 / 事件保留清理

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Conn struct {
	SrcIP   string `json:"ip"`
	SrcPort int    `json:"sport"`
	DstPort int    `json:"port"`
	Proc    string `json:"proc"`
	Proto   string `json:"proto"` // tcp | udp
	Since   int64  `json:"since"`
	// 流量(conntrack 字节计数, 同一对端在同端口的多条流已聚合):
	// Rx = 对端发给本机的累计字节(下载方向), Tx = 本机发给对端的累计字节(上传方向)
	Rx, Tx   uint64
	RxBps    int64 // 最近一个采样周期的实时速率
	TxBps    int64
	HasBytes bool  // false = conntrack 里没有这条流(如刚建立), 无流量数据
	bytesAt  int64 // 上次结算字节的时刻(秒)
}

var (
	connMu          sync.RWMutex
	liveConns       = map[string]*Conn{} // key: srcIP|dstPort|proto
	knownListen     = map[int]bool{}     // 已知的监听端口基线
	pendingLst      = map[int]int{}      // 新监听候选 -> 连续出现次数
	failWin         = map[string][]int64{}
	failMu          sync.Mutex
	lastAutoBan     = map[string]int64{}
	newConnAlertDay = map[string]string{} // 新连接 TG 去重: ip|port -> 已推送的自然日(中国时间)
)

// stripZone 去掉 IPv6 地址的 %zone 后缀(如 %enp2s0), 否则 ParseIP/端口解析会失败
func stripZone(h string) string {
	if i := strings.Index(h, "%"); i >= 0 {
		return h[:i]
	}
	return h
}

// normalizeIP 统一 IP 表示: 双栈套接字会把 IPv4 对端渲染成 ::ffff:1.2.3.4,
// 不归一化会与本机地址集/回环判断对不上, 被当成外部 IP 误报、重复计数
func normalizeIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func splitHostPort(s string) (string, int) {
	// IPv6 形式 [2409::1]:443 或 [2409::1]%enp2s0:443(ss 对绑定网卡的套接字会带 zone)
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			rest := s[i+1:]
			if strings.HasPrefix(rest, "%") {
				if j := strings.Index(rest, ":"); j >= 0 {
					rest = rest[j:]
				}
			}
			p, _ := strconv.Atoi(strings.TrimPrefix(rest, ":"))
			return normalizeIP(stripZone(s[1:i])), p
		}
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return normalizeIP(stripZone(s)), 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	return normalizeIP(stripZone(s[:i])), p
}

var procRe = regexp.MustCompile(`"([^"]+)"`)

func parseSS(out string, wantListen bool) (conns []Conn, listeners map[int]string) {
	listeners = map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// 进程字段(users:((...)))剥掉; 剩余字段末两列恒为 本地地址 对端地址
		// (不同 iproute2 版本可能带/不带 State 列, 故不按固定下标取)
		proc := ""
		if len(f) > 0 && strings.HasPrefix(f[len(f)-1], "users:") {
			if m := procRe.FindStringSubmatch(f[len(f)-1]); m != nil {
				proc = m[1]
			}
			f = f[:len(f)-1]
		}
		if len(f) < 4 {
			continue
		}
		local, peer := f[len(f)-2], f[len(f)-1]
		_, lport := splitHostPort(local)
		if wantListen {
			if lport > 0 {
				listeners[lport] = proc
			}
			continue
		}
		srcIP, sport := splitHostPort(peer)
		conns = append(conns, Conn{SrcIP: srcIP, SrcPort: sport, DstPort: lport, Proc: proc})
	}
	return
}

// ss 取本机终结的 TCP 连接: established 之外还要 syn-recv——
// 半开连接正是扫描/爆破试探的形态, 只看 established 会漏掉攻击进行时
func ssTCPConns() []Conn {
	out := []Conn{}
	seen := map[string]bool{}
	for _, st := range []string{"established", "syn-recv"} {
		b, err := exec.Command("ss", "-H", "-tnp", "state", st).CombinedOutput()
		if err != nil {
			continue
		}
		c, _ := parseSS(string(b), false)
		for _, cc := range c {
			cc.Proto = "tcp"
			k := cc.SrcIP + "|" + itoa(cc.SrcPort) + "|" + itoa(cc.DstPort)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, cc)
		}
	}
	return out
}

// ---------- conntrack: ss 看不见的连接都在这里 ----------
// 1) UDP 无连接状态且多路复用在单个套接字上, ss 列不出单个对端;
// 2) 转发给 Docker 容器的 TCP 连接在本机没有套接字, ss 完全看不见。
// 两类流都只存在于内核 conntrack 表。取向:
//   入站 = 对端 -> 本机IP:生效端口(本机终结与 DNAT 转发给容器的都算)
//   外连 = 本机(或本机容器)以服务监听端口为源端口连出(QB/uTP 属于后者)
// TCP 只取 ESTABLISHED 与 SYN_RECV, 与 ss 口径一致。

var ctPath = "/proc/net/nf_conntrack"

func localIPSet() map[string]bool {
	m := map[string]bool{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if addrs, err := ifc.Addrs(); err == nil {
				for _, a := range addrs {
					if ipn, ok := a.(*net.IPNet); ok {
						m[ipn.IP.String()] = true
					}
				}
			}
		}
	}
	return m
}

func ctConns(eff map[int]bool) []Conn {
	b, err := os.ReadFile(ctPath)
	if err != nil {
		return nil
	}
	// 生效端口 = 清单/监听(入参) ∪ 范围覆盖(位图, 不展开) ∪ 防火墙规则覆盖
	has := func(p int, proto string) bool { return eff[p] || rangeCovered(p) || fwCoversPort(p, proto) }
	locals := localIPSet()
	out := []Conn{}
	agg := map[string]*Conn{} // 同一对端在同一端口可能有多条流(不同源端口), 字节按对端聚合
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := f[2]
		if proto != "udp" && proto != "tcp" {
			continue
		}
		if proto == "tcp" {
			// TCP 行带状态词(ESTABLISHED/SYN_RECV/TIME_WAIT...), 只取前两种
			stOK := false
			for _, tok := range f[3:] {
				if tok == "ESTABLISHED" || tok == "SYN_RECV" {
					stOK = true
					break
				}
				if strings.Contains(tok, "=") {
					break
				}
			}
			if !stOK {
				continue
			}
		}
		// 键值对按元组分组: 每组以 src= 开头(原始方向 / 回复方向)。
		// 元组序固定为 src dst sport dport packets bytes, 故每组内首个 packets= 之后的
		// bytes= 就是该方向的字节数; 按位置(第几个 packets=)配对, 不靠 map 键(同名键会互相覆盖)。
		var tupBytes [2]uint64
		tupIdx := -1
		sawBytes := false // 本行是否真的带 bytes= 字段(内核 nf_conntrack_acct 关闭时整表都没有)
		for _, tok := range f[4:] {
			if tok == "packets" || strings.HasPrefix(tok, "packets=") {
				if tupIdx < 1 {
					tupIdx++
				}
				continue
			}
			if strings.HasPrefix(tok, "bytes=") && tupIdx >= 0 {
				sawBytes = true
				if bv, err := strconv.ParseUint(tok[len("bytes="):], 10, 64); err == nil {
					tupBytes[tupIdx] = bv
				}
			}
		}
		tuples := []map[string]string{{}}
		cur := tuples[0]
		for _, tok := range f[4:] {
			eq := strings.Index(tok, "=")
			if eq < 0 {
				continue
			}
			k, v := tok[:eq], tok[eq+1:]
			if k == "src" && len(cur) > 0 {
				cur = map[string]string{}
				tuples = append(tuples, cur)
			}
			cur[k] = v
		}
		orig := tuples[0]
		srcIP, dstIP := normalizeIP(orig["src"]), normalizeIP(orig["dst"])
		sport, _ := strconv.Atoi(orig["sport"])
		dport, _ := strconv.Atoi(orig["dport"])
		var peer string
		var peerPort, wport int
		inbound := false
		switch {
		case locals[dstIP] && has(dport, proto):
			peer, peerPort, wport = srcIP, sport, dport // 入站: 对端 -> 本机端口(终结或转发给容器)
			inbound = true
		case locals[srcIP] && has(sport, proto):
			peer, peerPort, wport = dstIP, dport, sport // 外连: 本机以监听端口为源端口连出
		case has(sport, proto):
			// 本机容器(桥接网络, 源 IP 是容器内网 IP)以服务端口为源端口外连
			if pip := net.ParseIP(srcIP); pip != nil && isPrivateIP(pip) {
				peer, peerPort, wport = dstIP, dport, sport
			} else {
				continue
			}
		default:
			continue
		}
		if peer == "" || locals[peer] {
			continue
		}
		if pip := net.ParseIP(peer); pip == nil || pip.IsLoopback() {
			continue
		}
		// 字节计数: 原始方向 bytes 与回复方向 bytes(conntrack 每条流都带,
		// 已在上面按 packets= 出现顺序配对好)。
		// 入站: 原始=对端发来(下载 Rx), 回复=本机发出(上传 Tx); 外连正好相反。
		origB, replyB := tupBytes[0], tupBytes[1]
		rx, tx := origB, replyB
		if !inbound {
			rx, tx = replyB, origB
		}
		key := peer + "|" + itoa(wport) + "|" + proto
		if ac, ok := agg[key]; ok {
			ac.Rx += rx
			ac.Tx += tx
			ac.HasBytes = ac.HasBytes || sawBytes
			continue
		}
		nc := Conn{SrcIP: peer, SrcPort: peerPort, DstPort: wport, Proto: proto, Rx: rx, Tx: tx, HasBytes: sawBytes}
		agg[key] = &nc
		out = append(out, nc)
	}
	// 把聚合后的字节回写到 out(agg 里是同一批流的累计值)
	for i := range out {
		key := out[i].SrcIP + "|" + itoa(out[i].DstPort) + "|" + out[i].Proto
		if ac, ok := agg[key]; ok {
			out[i].Rx, out[i].Tx, out[i].HasBytes = ac.Rx, ac.Tx, ac.HasBytes
		}
	}
	return out
}

// 监听端口(TCP+UDP) -> 进程名
func ssListeners() map[int]string {
	out := map[int]string{}
	for _, args := range [][]string{{"-H", "-tlnp"}, {"-H", "-ulnp"}} {
		b, err := exec.Command("ss", args...).CombinedOutput()
		if err != nil {
			continue
		}
		_, l := parseSS(string(b), true)
		for p, proc := range l {
			if out[p] == "" {
				out[p] = proc
			}
		}
	}
	return out
}

func watchedSet() map[int]*PortWatch {
	mu.Lock()
	defer mu.Unlock()
	m := map[int]*PortWatch{}
	for _, p := range ports {
		m[p.Port] = p
	}
	return m
}

// 内网访问不通知: 开启时, 内网来源的报警只记录不推送(日报不受影响)
func muteInternalAlert(ev Event) bool {
	if ev.IP == "" {
		return false
	}
	mu.Lock()
	m := settings.AlertMuteInternal
	mu.Unlock()
	if !m {
		return false
	}
	ip := net.ParseIP(ev.IP)
	return ip != nil && isPrivateIP(ip)
}

func emit(ev Event, alert bool) {
	// 时间戳只在这里打一次: pushEvent 按值收 ev, 它内部补的时间戳回不到
	// 调用方, 曾导致 TG 通知里的时间恒为 UnixMilli(0)=1970-01-01。
	if ev.Ts == 0 {
		ev.Ts = nowMs()
	}
	pushEvent(ev)
	if alert && muteInternalAlert(ev) {
		alert = false
	}
	if alert {
		tgSendEvent(ev)
	}
}

// 生效端口 = 监控清单 ∪ 当前监听端口: 没加进清单的服务(新装的下载器、
// 容器服务等)连接也必须可见, 否则就是盲区。用户删过/忽略的端口不自动纳入。
// 返回生效端口表与监听进程表(端口 -> 进程名)。
func effPorts() (map[int]*PortWatch, map[int]string) {
	ws := watchedSet()
	lst := ssListeners()
	mu.Lock()
	defer mu.Unlock()
	eff := map[int]*PortWatch{}
	for p, pw := range ws {
		eff[p] = pw
	}
	for port, proc := range lst {
		if eff[port] != nil || ignoredPorts[port] {
			continue
		}
		if honeypotIsEnabled(port) {
			continue // 蜜罐端口不自动纳入监控清单(否则 ss 会把它当扫描条目)
		}
		eff[port] = &PortWatch{Port: port, Proto: "tcp", Name: proc, Source: "scan", Kind: guessKind(port, proc)}
	}
	// 防火墙覆盖的端口不再展开进 eff(1-65535 会爆炸): 采集层用
	// fwCoversPort() 查范围覆盖, 未监听/被忽略的防护端口照样可见
	// (见 ctConns 的 has 与 handle 的合成条目)。
	return eff, lst
}

func sampleConns() {
	eff, lst := effPorts()
	effSet := map[int]bool{}
	for p := range eff {
		effSet[p] = true
	}
	locals := localIPSet()
	now := time.Now().Unix()
	seen := map[string]bool{}
	handle := func(c Conn) {
		pw, ok := eff[c.DstPort]
		if !ok {
			// 范围覆盖的端口不在 eff 表里(范围不展开): 查位图合成条目
			if rp := lookupPort(c.DstPort); rp != nil {
				pw, ok = rp, true
			}
		}
		if !ok {
			// 防火墙覆盖的端口不在 eff 表里: 合成条目, 让防火墙检查跑起来
			if fwCoversPort(c.DstPort, c.Proto) {
				pw, ok = &PortWatch{Port: c.DstPort, Proto: c.Proto, Name: "防火墙", Source: "firewall", Kind: "other"}, true
			}
		}
		if !ok {
			return
		}
		// 回环/本机自连不算外部连接, 不展示不统计
		if pip := net.ParseIP(c.SrcIP); pip == nil || pip.IsLoopback() || locals[c.SrcIP] {
			return
		}
		key := c.SrcIP + "|" + itoa(c.DstPort) + "|" + c.Proto
		seen[key] = true
		connMu.Lock()
		_, exists := liveConns[key]
		if exists {
			if c.Proc != "" {
				liveConns[key].Proc = c.Proc
			}
		} else {
			cc := c
			cc.Since = now
			liveConns[key] = &cc
		}
		connMu.Unlock()
		if exists {
			return
		}
		// 防火墙: 新连接先过规则, 拒绝命中按规则端口封禁、允许命中放行、
		// 无命中按受防护端口默认封禁(拒绝优先于允许)
		portGuardCheck(c.SrcIP, c.DstPort, c.Proto)
		// 扫描识别(第 5 项): 新 TCP 连接先喂给扫描跟踪
		if c.Proto == "tcp" {
			scanObserve(c.SrcIP, c.DstPort, now)
		}
		// 新对端一律计入今日新来源统计(按 IP 去重): 含 UDP 与转发连接,
		// 否则 QB 几十个 UDP 对端在统计里纹丝不动, 与连接列表对不上。
		firstToday := statsNewConn(c.SrcIP, c.DstPort)
		if pw.Star {
			floodTrack(pw, c.SrcIP) // 洪峰检测: 所有协议的新连接都算涌入
			// 重点端口的 TCP 新连接: 记事件 + 按开关报警(原有行为)
			if c.Proto == "tcp" {
				emit(Event{Type: "new_conn", IP: c.SrcIP, Port: c.DstPort,
					Detail: "新连接 → " + portLabel(pw)}, newConnAlert(c.SrcIP, c.DstPort, time.Now()))
				return
			}
		}
		// 其余新对端(普通端口 / UDP / 转发): 只在该 IP 当日首次出现时补记一条
		// new_src 事件(不报警, 独立目录/独立保留期), 让「今日新来源 IP」点进
		// 事件页能逐条对上——按 IP 每天至多一条, 不会灌爆。
		if firstToday && settings.NewSrcKeepDays > 0 {
			d := "新来源 → " + portLabel(pw)
			if c.Proto == "udp" {
				d += " · UDP"
			}
			pushEvent(Event{Type: "new_src", IP: c.SrcIP, Port: c.DstPort, Detail: d})
		}
	}
	for _, c := range ssTCPConns() {
		handle(c)
	}
	cts := ctConns(effSet)
	for _, c := range cts {
		if c.Proc == "" {
			c.Proc = lst[c.DstPort] // conntrack 无进程信息, 借同端口监听的进程名
		}
		handle(c)
	}
	scanCtPass(now) // 闭口试探(第 5 项): conntrack 原始元组扫一遍
	// 流量结算: 本轮 conntrack 聚合字节与上轮的差值 / 时间差 = 实时速率
	ctBytes := map[string][2]uint64{}
	for _, c := range cts {
		if c.HasBytes { // 内核没开字节统计时整表无 bytes=, 不把 0 当真实流量
			ctBytes[c.SrcIP+"|"+itoa(c.DstPort)+"|"+c.Proto] = [2]uint64{c.Rx, c.Tx}
		}
	}
	connMu.Lock()
	for k, lc := range liveConns {
		b, ok := ctBytes[k]
		if !ok {
			lc.RxBps, lc.TxBps = 0, 0 // 本轮 conntrack 里没有它: 无可测流量
			continue
		}
		if lc.HasBytes && lc.bytesAt > 0 {
			if dt := now - lc.bytesAt; dt > 0 {
				if b[0] >= lc.Rx {
					lc.RxBps = int64(b[0]-lc.Rx) / dt
				} else {
					lc.RxBps = 0
				}
				if b[1] >= lc.Tx {
					lc.TxBps = int64(b[1]-lc.Tx) / dt
				} else {
					lc.TxBps = 0
				}
			}
		}
		lc.Rx, lc.Tx = b[0], b[1]
		lc.HasBytes = true
		lc.bytesAt = now
	}
	connMu.Unlock()
	connMu.Lock()
	for k := range liveConns {
		if !seen[k] {
			delete(liveConns, k)
		}
	}
	connMu.Unlock()
}

// ---------- 重点端口洪峰防护(分布式爆破) ----------
// 单 IP 爆破有 SSH 失败阈值与自动拉黑管; 但代理池分布式爆破每个 IP 只试一两次,
// 阈值永远抓不到。这里按重点端口统计滑动窗口内不同公网 IP 的新连接数, 超阈值即
// 判定洪峰: 临时关闭该端口(只拦公网新连接, 内网不受影响) + 升级报警。

var (
	floodMu  sync.Mutex
	floodWin = map[int]map[string]int64{} // port -> ip -> 最近新连接时间
)

func floodTrack(pw *PortWatch, ip string) {
	if !settings.FloodEnabled || isPortClosed(pw.Port) {
		return
	}
	pip := net.ParseIP(ip)
	if pip == nil || isPrivateIP(pip) || isTrusted(ip) {
		return // 只统计公网来源: 内网设备再多也不算洪峰
	}
	now := time.Now().Unix()
	winSec := int64(settings.FloodWindowMin * 60)
	if winSec < 60 {
		winSec = 60
	}
	floodMu.Lock()
	m := floodWin[pw.Port]
	if m == nil {
		m = map[string]int64{}
		floodWin[pw.Port] = m
	}
	for k, t := range m {
		if now-t > winSec {
			delete(m, k)
		}
	}
	m[ip] = now
	cnt := len(m)
	thr := settings.FloodDistinctIPs
	floodMu.Unlock()
	if thr < 2 || cnt < thr {
		return
	}
	floodMu.Lock()
	delete(floodWin, pw.Port) // 先清窗口, 防关端口期间重复触发
	floodMu.Unlock()
	closePort(pw.Port, settings.FloodCloseMin, "洪峰防护自动关闭")
	emit(Event{Type: "port_flood", Port: pw.Port,
		Detail: "重点端口 " + portLabel(pw) + " 在 " + itoa(settings.FloodWindowMin) + " 分钟内涌入 " + itoa(cnt) +
			" 个不同公网 IP 的新连接(疑似分布式爆破), 已临时关闭该端口 " + itoa(settings.FloodCloseMin) + " 分钟(只拦公网新连接, 内网不受影响)"},
		settings.AlertPortFlood)
}

// 新连接 TG 去重(第 8 项): 同一 (IP, 端口) 自然日内只推一次,
// 当天的重复连接只记事件、不推 TG; 跨端口算不同事件, 照常提醒。
// now 由调用方传入(中国时间, time.Local 已在 init 里设为 Asia/Shanghai)。
func newConnAlertAllowed(ip string, port int, now time.Time) bool {
	day := now.Format("2006-01-02")
	key := ip + "|" + itoa(port)
	if newConnAlertDay[key] == day {
		return false
	}
	newConnAlertDay[key] = day
	return true
}

// newConnAlert 是重点端口新连接的最终推送判定: 开关 + 未拉黑 + 当日去重。
// SSH 端口另受 SSH 连接开关叠加约束: 关后只静默 SSH 端口, 其他重点端口不变。
func newConnAlert(ip string, port int, now time.Time) bool {
	if !settings.AlertNewConnStar || isBannedFor(ip, port) {
		return false
	}
	if !settings.AlertSSHConn {
		if ssh := detectSSHPort(); ssh.Detected && ssh.Port == port {
			return false
		}
	}
	return newConnAlertAllowed(ip, port, now)
}

func portLabel(pw *PortWatch) string {
	if pw.Name != "" {
		return pw.Name + "(" + itoa(pw.Port) + ")"
	}
	return "端口 " + itoa(pw.Port)
}

var baselineDone bool

func sampleListeners() {
	lst := ssListeners()
	if len(lst) == 0 {
		return
	}
	if !baselineDone {
		// 第一拍只建基线: 启动时已存在的监听不算"新监听"
		for port := range lst {
			knownListen[port] = true
		}
		baselineDone = true
		return
	}
	mu.Lock()
	watched := map[int]bool{}
	for _, p := range ports {
		watched[p.Port] = true
	}
	mu.Unlock()
	for port, proc := range lst {
		if watched[port] || rangeCovered(port) || ignoredPorts[port] || rangeIgnored(port) || knownListen[port] {
			pendingLst[port] = 0
			knownListen[port] = true
			continue
		}
		pendingLst[port]++
		if pendingLst[port] >= 2 {
			knownListen[port] = true
			name := proc
			if name == "" {
				name = "未知进程"
			}
			emit(Event{Type: "new_listener", Port: port,
				Detail: "新监听端口 " + itoa(port) + " (" + name + ")"}, settings.AlertNewListener)
		}
	}
	// 已消失的从基线移除, 下次再出现重新报告
	for port := range knownListen {
		if _, ok := lst[port]; !ok {
			delete(knownListen, port)
			delete(pendingLst, port)
		}
	}
}

// ---------- 日志尾随 ----------

type tailer struct {
	path string
	off  int64
	init bool
}

func (t *tailer) readNew() []string {
	fi, err := os.Stat(t.path)
	if err != nil {
		return nil
	}
	if !t.init {
		t.off = fi.Size()
		t.init = true
		return nil
	}
	if fi.Size() < t.off {
		t.off = 0 // 轮转
	}
	if fi.Size() == t.off {
		return nil
	}
	f, err := os.Open(t.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	f.Seek(t.off, 0)
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	t.off = fi.Size()
	return lines
}

var (
	reAccepted = regexp.MustCompile(`Accepted \S+ for (\S+) from (\S+) port`)
	reFailed   = regexp.MustCompile(`Failed \S+ for (?:invalid user )?(\S+) from (\S+) port`)
)

func onSSHFail(ip, user string) {
	pushEvent(Event{Type: "ssh_fail", IP: ip, Detail: "SSH 登录失败 (用户 " + user + ")"})
	if isTrusted(ip) {
		return
	}
	if pip := net.ParseIP(ip); pip != nil && isPrivateIP(pip) {
		return // 内网不自动拉黑
	}
	failMu.Lock()
	now := time.Now().Unix()
	win := int64(settings.BruteWindowMin * 60)
	arr := append(failWin[ip], now)
	keep := arr[:0]
	for _, t := range arr {
		if now-t <= win {
			keep = append(keep, t)
		}
	}
	failWin[ip] = keep
	cnt := len(keep)
	last := lastAutoBan[ip]
	failMu.Unlock()
	if settings.AutoBanEnabled && cnt >= settings.BruteThreshold && now-last > 3600 && !isGloballyBanned(ip) {
		if b, err := applyAutoBan(ip, "SSH 爆破自动拉黑"); err == nil {
			failMu.Lock()
			lastAutoBan[ip] = now
			failMu.Unlock()
			dur := "永久"
			if b.Until > 0 {
				dur = itoa(int((b.Until-now)/3600)) + " 小时"
			}
			emit(Event{Type: "autoban", IP: ip,
				Detail: "爆破自动拉黑: " + itoa(settings.BruteWindowMin) + " 分钟内失败 " + itoa(cnt) + " 次, 第 " + itoa(b.Offenses) + " 次触发, 封禁 " + dur}, settings.AlertSSHBrute)
		}
	}
}

// resolveAuthLogPath: 设置指定 > 环境变量 > 自动识别(auth.log 优先, 其次 secure)。
// 两个文件都不存在时仍回落 auth.log(尾随器对缺失文件静默等待, 不报错)。
func resolveAuthLogPath() string {
	mu.Lock()
	cfg := settings.AuthLogPath
	mu.Unlock()
	if strings.TrimSpace(cfg) != "" {
		return strings.TrimSpace(cfg)
	}
	if v := os.Getenv("GUIJIA_AUTHLOG"); v != "" {
		return v
	}
	if _, err := os.Stat("/var/log/auth.log"); err == nil {
		return "/var/log/auth.log"
	}
	if _, err := os.Stat("/var/log/secure"); err == nil {
		return "/var/log/secure"
	}
	return "/var/log/auth.log"
}

func watchLogs() {
	at := &tailer{path: resolveAuthLogPath()}
	for {
		for _, ln := range at.readNew() {
			if m := reAccepted.FindStringSubmatch(ln); m != nil {
				emit(Event{Type: "ssh_login", IP: m[2], Detail: "SSH 登录成功 (用户 " + m[1] + ")"}, settings.AlertSSHLogin && !isTrusted(m[2]))
			} else if m := reFailed.FindStringSubmatch(ln); m != nil {
				onSSHFail(m[2], m[1])
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func collectLoop() {
	go watchLogs()
	sampleListeners() // 建初始基线
	t1 := time.NewTicker(1 * time.Second)
	t60 := time.NewTicker(60 * time.Second)
	for {
		select {
		case <-t1.C:
			sampleConns()
		case <-t60.C:
			sampleListeners()
		}
	}
}

func housekeepLoop() {
	for {
		time.Sleep(60 * time.Second)
		if !dryBan {
			ensureSetAndRule()
			reconcileBans() // 名单与内核集合对齐: 生效中必封, 非生效中必不在集合
		}
		rescueCheckAutoRestore(time.Now()) // 急救模式到期自动恢复
		honeypotCheckAlive()               // 蜜罐监听复核: 死了只报警, 不自动重绑
		syncTrafficAcct()                  // 流量统计开关自检: 被外部关掉/设置里关了, 都在一分钟内对齐
		saveStats()                        // 每分钟落盘: 进程重启后「今日新来源」去重集合不丢, 事件不重复记
		ledgerFlush()                      // 流量账本落盘(脏了才写)
		ledgerPrune()                      // 流量每日明细按保留期清理
		now := time.Now()
		if now.Hour() == 0 && now.Minute() < 2 {
			pruneEvents()
			saveStats()
		}
	}
}
