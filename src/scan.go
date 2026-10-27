package main

// 端口扫描识别(第 5 项): 被动观察, 只做 TCP, 不发任何探测包。
// 两个喂给源:
//  (a) sampleConns 的 handle(): 对监控/监听端口的新 TCP 连接;
//  (b) scanCtPass(): /proc/net/nf_conntrack 原始元组, 抓"对端 -> 本机任意端口"
//      的 SYN_SENT/SYN_RECV/ESTABLISHED——闭口试探只有这里看得见
//      (ss 无套接字、ctConns 只过监控端口)。
// 采样二选一: 1 秒轮询(collectLoop 已由 5 秒改到 1 秒)。
// 选 1 秒不选 conntrack -E 的理由: 不新增子进程依赖(各发行版上 conntrack
// 命令是否存在未必一致); /proc 解析已是现有成熟路径; SYN_SENT 条目默认存活
// 120 秒, 1 秒轮询在实践中不漏。残留缺口(诚实说明): 亚秒级全端口快扫
// 理论上可能漏报, 防护页文案里写明。

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	scanMu    sync.Mutex
	scanTrack = map[string]*scanEntry{}
)

type scanEntry struct {
	ports     map[int]int64 // 触达过的端口 -> 最近一次时间(unix 秒)
	lastAlert int64         // 上次报警时间(unix 秒), 1 小时重报冷却
}

// scanObserve 记录一次"某 IP 触达某 TCP 端口"; 窗口内不同端口数达阈值时
// 记事件、按开关报警、可选自动拉黑(走递进阶梯, 第 1 项)。
func scanObserve(ip string, port int, now int64) {
	mu.Lock()
	sc := settings
	mu.Unlock()
	if !sc.ScanEnabled || port < 1 || port > 65535 {
		return
	}
	if pip := net.ParseIP(ip); pip == nil || pip.IsLoopback() || isPrivateIP(pip) {
		return
	}
	if isTrusted(ip) {
		return
	}
	window := int64(sc.ScanWindowMin) * 60
	if window < 60 {
		window = 60
	}
	threshold := sc.ScanDistinctPorts
	if threshold < 2 {
		threshold = 2
	}
	scanMu.Lock()
	e := scanTrack[ip]
	if e == nil {
		e = &scanEntry{ports: map[int]int64{}}
		scanTrack[ip] = e
	}
	e.ports[port] = now
	distinct := 0
	for p, t := range e.ports {
		if now-t > window {
			delete(e.ports, p)
		} else {
			distinct++
		}
	}
	if distinct < threshold {
		// 窗口已空且冷却已过: 删条目, 避免无用 IP 永久占内存
		if len(e.ports) == 0 && now-e.lastAlert > 3600 {
			delete(scanTrack, ip)
		}
		scanMu.Unlock()
		return
	}
	if isGloballyBanned(ip) {
		// 已全局拉黑: 不报警、不占报警状态(与第 8 项同款口径; 按端口封禁不算全局)
		scanMu.Unlock()
		return
	}
	if now-e.lastAlert < 3600 {
		scanMu.Unlock()
		return
	}
	e.lastAlert = now
	scanMu.Unlock()
	emit(Event{Type: "port_scan", IP: ip,
		Detail: fmt.Sprintf("疑似端口扫描: %d 分钟内触达 %d 个不同 TCP 端口", sc.ScanWindowMin, distinct)}, sc.AlertScan)
	if sc.ScanAutoBan {
		// 扫描自动拉黑此前只写记录不发事件，今日拉黑漏计；成功时补一次 autoban 事件（恰好一次）。
		if _, err := applyAutoBan(ip, fmt.Sprintf("端口扫描: %d 分钟内触达 %d 个不同端口", sc.ScanWindowMin, distinct)); err == nil {
			emit(Event{Type: "autoban", IP: ip,
				Detail: fmt.Sprintf("扫描自动拉黑: %d 分钟内触达 %d 个不同端口", sc.ScanWindowMin, distinct)}, sc.AlertScan)
		}
	}
}

// scanCtPass 轻量扫一遍 conntrack 原始元组, 只为抓闭口试探:
// 对端 -> 本机任意端口的 SYN_SENT/SYN_RECV/ESTABLISHED。字节、回复元组
// 一概不算, 只取首个元组的方向与端口。
func scanCtPass(now int64) {
	b, err := os.ReadFile(ctPath)
	if err != nil {
		return
	}
	locals := localIPSet()
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[2] != "tcp" {
			continue
		}
		stOK := false
		for _, tok := range f[3:] {
			if tok == "SYN_SENT" || tok == "SYN_RECV" || tok == "ESTABLISHED" {
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
		var src, dst string
		var dport int
		for _, tok := range f[4:] {
			eq := strings.Index(tok, "=")
			if eq < 0 {
				continue
			}
			k, v := tok[:eq], tok[eq+1:]
			if k == "src" && src != "" {
				break // 第二元组(回复方向)开始, 停
			}
			switch k {
			case "src":
				src = v
			case "dst":
				dst = v
			case "dport":
				dport, _ = strconv.Atoi(v)
			}
		}
		src = normalizeIP(src)
		dst = normalizeIP(dst)
		if src == "" || !locals[dst] {
			continue
		}
		scanObserve(src, dport, now)
	}
}
