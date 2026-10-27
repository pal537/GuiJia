package main

// 第 5 项回归测试: 端口扫描识别(阈值/窗口/冷却/豁免/自动拉黑/conntrack 闭口试探)。

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func scanTestSetup(t *testing.T) {
	t.Helper()
	banTestSetup(t)
	// 测试进程不跑 main(), eventsDir 默认是空串, pushEvent 会把事件写进
	// 当前目录(src/*.jsonl)污染源码树并干扰 TestListEventsPaging: 重定向到临时目录。
	evDir, srcDir := t.TempDir(), t.TempDir()
	oldEv, oldSrc := eventsDir, eventsSrcDir
	eventsDir, eventsSrcDir = evDir, srcDir
	mu.Lock()
	old := settings
	settings.ScanEnabled = true
	settings.AlertScan = true
	settings.ScanAutoBan = false
	settings.ScanWindowMin = 5
	settings.ScanDistinctPorts = 5
	settings.TrustedIPs = []string{}
	mu.Unlock()
	scanMu.Lock()
	scanTrack = map[string]*scanEntry{}
	scanMu.Unlock()
	t.Cleanup(func() {
		eventsDir, eventsSrcDir = oldEv, oldSrc
		mu.Lock()
		settings = old
		mu.Unlock()
		scanMu.Lock()
		scanTrack = map[string]*scanEntry{}
		scanMu.Unlock()
	})
}

func scanEntryOf(t *testing.T, ip string) *scanEntry {
	t.Helper()
	scanMu.Lock()
	defer scanMu.Unlock()
	return scanTrack[ip]
}

func TestScanThresholdAndCooldown(t *testing.T) {
	scanTestSetup(t)
	now := time.Now().Unix()
	ip := "203.0.113.90"
	for i, p := range []int{22, 80, 443, 3306} {
		scanObserve(ip, p, now+int64(i))
		if e := scanEntryOf(t, ip); e == nil || e.lastAlert != 0 {
			t.Fatalf("4 个端口未达阈值不应报警, lastAlert=%v", e)
		}
	}
	scanObserve(ip, 6379, now+4)
	if e := scanEntryOf(t, ip); e == nil || e.lastAlert == 0 {
		t.Fatal("第 5 个不同端口应触发报警(lastAlert 置位)")
	}
	firstAlert := scanEntryOf(t, ip).lastAlert
	// 冷却期内再触 5 个新端口也不重报
	for i, p := range []int{21, 23, 25, 110, 143} {
		scanObserve(ip, p, now+10+int64(i))
	}
	if e := scanEntryOf(t, ip); e.lastAlert != firstAlert {
		t.Fatalf("1 小时冷却期内不应重报, %d -> %d", firstAlert, e.lastAlert)
	}
	// 冷却过后 5 个新端口再次触发
	for i, p := range []int{8080, 8081, 8082, 8083, 8084} {
		scanObserve(ip, p, now+3601+int64(i))
	}
	if e := scanEntryOf(t, ip); e.lastAlert == firstAlert {
		t.Fatal("冷却过后应可再次报警")
	}
	// 同一端口重复触达不增加不同端口数
	scanTestSetup(t)
	now = time.Now().Unix()
	for i := 0; i < 5; i++ {
		scanObserve(ip, 22, now+int64(i))
	}
	if e := scanEntryOf(t, ip); e != nil && e.lastAlert != 0 {
		t.Fatal("同一端口重复 5 次不应算 5 个不同端口")
	}
}

func TestScanWindowExpiry(t *testing.T) {
	scanTestSetup(t)
	now := time.Now().Unix()
	ip := "203.0.113.91"
	for i, p := range []int{22, 80, 443, 3306, 6379} {
		scanObserve(ip, p, now+int64(i))
	}
	if e := scanEntryOf(t, ip); e == nil || e.lastAlert == 0 {
		t.Fatal("5 个端口应触发")
	}
	// 6 分钟后(窗口 5 分钟已过)再触 1 个新端口: 旧端口全部过期, 不应立即重报
	scanObserve(ip, 8080, now+360)
	if e := scanEntryOf(t, ip); e == nil || len(e.ports) != 1 {
		t.Fatalf("窗口过期后应只剩 1 个端口, 实际 %+v", e)
	}
}

func TestScanExemptions(t *testing.T) {
	scanTestSetup(t)
	now := time.Now().Unix()
	// 内网 IP 不跟踪
	for _, p := range []int{22, 80, 443, 3306, 6379} {
		scanObserve("192.168.1.99", p, now)
	}
	if e := scanEntryOf(t, "192.168.1.99"); e != nil {
		t.Fatal("内网 IP 不应进入扫描跟踪")
	}
	// 信任 IP 不跟踪
	mu.Lock()
	settings.TrustedIPs = []string{"203.0.113.92"}
	mu.Unlock()
	for _, p := range []int{22, 80, 443, 3306, 6379} {
		scanObserve("203.0.113.92", p, now)
	}
	if e := scanEntryOf(t, "203.0.113.92"); e != nil {
		t.Fatal("信任 IP 不应进入扫描跟踪")
	}
	// 已拉黑 IP 不再报警
	if _, err := applyBan("203.0.113.93", "test", "manual", 24); err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{22, 80, 443, 3306, 6379} {
		scanObserve("203.0.113.93", p, now)
	}
	if e := scanEntryOf(t, "203.0.113.93"); e != nil && e.lastAlert != 0 {
		t.Fatal("已拉黑 IP 不应再发扫描报警")
	}
	// 检测关闭时不跟踪
	mu.Lock()
	settings.ScanEnabled = false
	mu.Unlock()
	for _, p := range []int{22, 80, 443, 3306, 6379} {
		scanObserve("203.0.113.94", p, now)
	}
	if e := scanEntryOf(t, "203.0.113.94"); e != nil {
		t.Fatal("检测关闭时不应跟踪")
	}
}

func TestScanAutoBan(t *testing.T) {
	scanTestSetup(t)
	mu.Lock()
	settings.ScanAutoBan = true
	mu.Unlock()
	bansBefore := todayStats().Bans
	now := time.Now().Unix()
	ip := "203.0.113.95"
	for i, p := range []int{22, 80, 443, 3306, 6379} {
		scanObserve(ip, p, now+int64(i))
	}
	if !isBanned(ip) {
		t.Fatal("扫描自动拉黑开启时, 达阈值应自动拉黑")
	}
	if d := todayStats().Bans - bansBefore; d != 1 {
		t.Fatalf("扫描自动拉黑应恰好发一次 autoban 事件计入今日拉黑, 实际增量 %d", d)
	}
	banMu.Lock()
	defer banMu.Unlock()
	for _, b := range bans {
		if b.IP == ip && b.Source != "auto" {
			t.Fatalf("扫描拉黑来源应为 auto, 实际 %q", b.Source)
		}
	}
}

func TestScanCtPass(t *testing.T) {
	scanTestSetup(t)
	// 闭口试探: 5 条 SYN_SENT, 对端 -> 本机 lo(127.0.0.1 属本机地址),
	// 另加干扰行(UDP、非本机目标、TIME_WAIT)应被忽略。
	lines := ""
	for _, p := range []int{22, 3389, 23, 6379, 3306} {
		lines += "ipv4 2 tcp 6 119 SYN_SENT src=203.0.113.96 dst=127.0.0.1 sport=45678 dport=" + itoa(p) + " packets=1 bytes=60 [UNREPLIED] src=127.0.0.1 dst=203.0.113.96 sport=" + itoa(p) + " dport=45678 packets=0 bytes=0\n"
	}
	lines += "ipv4 2 udp 17 30 src=203.0.113.96 dst=127.0.0.1 sport=1234 dport=53 packets=1 bytes=60\n"
	lines += "ipv4 2 tcp 6 119 SYN_SENT src=203.0.113.96 dst=198.51.100.1 sport=45678 dport=8080 packets=1 bytes=60\n"
	lines += "ipv4 2 tcp 6 60 TIME_WAIT src=203.0.113.96 dst=127.0.0.1 sport=45678 dport=9999 packets=1 bytes=60\n"
	f := filepath.Join(t.TempDir(), "nf_conntrack")
	if err := os.WriteFile(f, []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}
	oldCt := ctPath
	ctPath = f
	defer func() { ctPath = oldCt }()
	scanCtPass(time.Now().Unix())
	if e := scanEntryOf(t, "203.0.113.96"); e == nil || e.lastAlert == 0 {
		t.Fatalf("5 个闭口试探应触发扫描报警, 实际 %+v", e)
	} else if len(e.ports) != 5 {
		t.Fatalf("干扰行应被忽略, 只剩 5 个端口, 实际 %d", len(e.ports))
	}
}
