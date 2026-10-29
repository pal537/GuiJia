package main

// 第 6 项回归测试: 蜜罐(分层校验 fail-closed、命中/聚合/封禁/统计分开、
// 历史流量警告、应用回滚)。

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func honeypotTestSetup(t *testing.T) {
	t.Helper()
	banTestSetup(t)
	evDir, srcDir := t.TempDir(), t.TempDir()
	oldEv, oldSrc := eventsDir, eventsSrcDir
	eventsDir, eventsSrcDir = evDir, srcDir
	mu.Lock()
	oldSettings := settings
	settings.TrustedIPs = []string{}
	mu.Unlock()
	honeypotMu.Lock()
	oldCfg := honeypotCfg
	honeypotCfg = HoneypotConfig{AlertEnabled: false, HitThreshold: 1, BanHours: 24}
	honeypotIPHits = map[string]int{}
	honeypotIPAlertAt = map[string]int64{}
	honeypotPortHits = map[int]int{}
	honeypotPortDay = ""
	honeypotDeadAlert = map[int]int64{}
	honeypotMu.Unlock()
	t.Cleanup(func() {
		eventsDir, eventsSrcDir = oldEv, oldSrc
		mu.Lock()
		settings = oldSettings
		mu.Unlock()
		honeypotStopAll()
		honeypotMu.Lock()
		honeypotCfg = oldCfg
		honeypotIPHits = map[string]int{}
		honeypotIPAlertAt = map[string]int64{}
		honeypotPortHits = map[int]int{}
		honeypotPortDay = ""
		honeypotDeadAlert = map[int]int64{}
		honeypotMu.Unlock()
	})
}

func TestHoneypotValidateLayers(t *testing.T) {
	honeypotTestSetup(t)
	// 1 层格式
	if confs := honeypotValidate([]int{0}); len(confs) == 0 || confs[0].Layer != "格式" {
		t.Fatalf("端口 0 应被格式层拒绝, 实际 %v", confs)
	}
	if confs := honeypotValidate([]int{70000}); len(confs) == 0 || confs[0].Layer != "格式" {
		t.Fatalf("端口 70000 应被格式层拒绝, 实际 %v", confs)
	}
	// 保留端口 80/443
	if confs := honeypotValidate([]int{80}); len(confs) == 0 || confs[0].Layer != "保留端口" {
		t.Fatalf("端口 80 应被保留端口层拒绝, 实际 %v", confs)
	}
	// 自身端口 + 去重(1/2 层先行返回, 不受本机监听状态干扰)
	if confs := honeypotValidate([]int{18793}); len(confs) == 0 || confs[0].Layer != "自身" {
		t.Fatalf("端口 18793 应被自身层拒绝, 实际 %v", confs)
	}
	if confs := honeypotValidate([]int{45678, 45678}); len(confs) == 0 || confs[0].Layer != "自身" {
		t.Fatalf("重复端口应被自身层拒绝, 实际 %v", confs)
	}
	// 3 层系统已知: ports.json 里的端口
	mu.Lock()
	oldPorts := ports
	ports = []*PortWatch{{Port: 45679, Proto: "tcp", Name: "测试服务", Source: "manual", Kind: "other"}}
	mu.Unlock()
	defer func() {
		mu.Lock()
		ports = oldPorts
		mu.Unlock()
	}()
	if confs := honeypotValidate([]int{45679}); len(confs) == 0 || confs[0].Layer != "系统已知" {
		t.Fatalf("监控清单端口应被系统已知层拒绝, 实际 %v", confs)
	}
	// 4/6 层: 已有进程监听的端口必被拒绝(至于是 ss 报出还是 bind 裁决, 看本机工具有无)
	ln, err := net.Listen("tcp", ":45680")
	if err != nil {
		t.Skip("测试端口 45680 已被占用, 跳过监听层用例")
	}
	defer ln.Close()
	if confs := honeypotValidate([]int{45680}); len(confs) == 0 {
		t.Fatal("已有监听的端口必须被拒绝(实时监听或终局 bind 任一层)")
	} else if confs[0].Layer != "实时监听" && confs[0].Layer != "终局 bind" {
		t.Fatalf("监听端口应被实时监听/终局 bind 层拒绝, 实际 %v", confs)
	}
	// 自己在跑的蜜罐监听不算占用
	honeypotMu.Lock()
	honeypotCfg.Enabled = true
	honeypotCfg.Ports = []int{45681}
	honeypotMu.Unlock()
	go honeypotServe(45681)
	deadline := time.Now().Add(2 * time.Second)
	for {
		honeypotMu.Lock()
		_, ok := honeypotListeners[45681]
		honeypotMu.Unlock()
		if ok || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if confs := honeypotValidate([]int{45681}); len(confs) != 0 {
		t.Fatalf("自己在跑的蜜罐端口不应被判占用, 实际 %v", confs)
	}
}

func TestHoneypotHitBanAndStats(t *testing.T) {
	honeypotTestSetup(t)
	honeypotMu.Lock()
	honeypotCfg.Enabled = true
	honeypotCfg.AutoBan = true
	honeypotCfg.AlertEnabled = false
	honeypotCfg.HitThreshold = 1
	honeypotCfg.BanHours = 24
	honeypotMu.Unlock()
	dsBefore := todayStats()
	bansBefore, hpBefore := dsBefore.Bans, dsBefore.HoneypotBans
	// 公网命中 1 次即封(默认 N=1)，统计进今日拉黑总数与蜜罐明细
	honeypotHit(22, "203.0.113.100:45678")
	if !isBanned("203.0.113.100") {
		t.Fatal("蜜罐自动拉黑开启且 N=1 时, 命中 1 次应封禁")
	}
	ds := todayStats()
	statsMu.Lock()
	hpAfter, bansAfter := ds.HoneypotBans, ds.Bans
	statsMu.Unlock()
	if hpAfter-hpBefore != 1 {
		t.Fatalf("蜜罐明细应 +1, 实际 %d->%d", hpBefore, hpAfter)
	}
	if bansAfter-bansBefore != 1 {
		t.Fatalf("蜜罐封禁应计入今日拉黑总数 +1, 实际 %d->%d", bansBefore, bansAfter)
	}
	banMu.Lock()
	src := ""
	for _, b := range bans {
		if b.IP == "203.0.113.100" {
			src = b.Source
		}
	}
	banMu.Unlock()
	if src != "honeypot" {
		t.Fatalf("蜜罐封禁来源应为 honeypot, 实际 %q", src)
	}
	// 内网命中不算(换一个此前无命中的端口断言, 避免与上面公网命中的计数混淆)
	honeypotHit(3389, "192.168.1.5:45678")
	honeypotMu.Lock()
	_, privCounted := honeypotPortHits[3389]
	honeypotMu.Unlock()
	if privCounted {
		t.Fatal("内网命中不应计入端口命中")
	}
	// 信任 IP 只报警不封(计数器也不进)
	mu.Lock()
	settings.TrustedIPs = []string{"203.0.113.101"}
	mu.Unlock()
	honeypotHit(22, "203.0.113.101:45678")
	if isBanned("203.0.113.101") {
		t.Fatal("信任 IP 命中蜜罐不应被封")
	}
	honeypotMu.Lock()
	_, trustedCounted := honeypotIPHits["203.0.113.101"]
	honeypotMu.Unlock()
	if trustedCounted {
		t.Fatal("信任 IP 不应进入封禁计数器")
	}
	// 已拉黑 IP 再命中不重复封禁(仍只有一条记录)
	if _, err := applyBan("203.0.113.102", "test", "manual", 24); err != nil {
		t.Fatal(err)
	}
	honeypotHit(22, "203.0.113.102:45678")
	banMu.Lock()
	n := 0
	for _, b := range bans {
		if b.IP == "203.0.113.102" {
			n++
		}
	}
	banMu.Unlock()
	if n != 1 {
		t.Fatalf("已拉黑 IP 再命中不应产生重复记录, 实际 %d 条", n)
	}
	// 10 分钟聚合: 未开自动拉黑时, 同一 IP 两次命中只置一次报警时间
	honeypotMu.Lock()
	honeypotCfg.AutoBan = false
	honeypotMu.Unlock()
	honeypotHit(3389, "203.0.113.103:45678")
	honeypotMu.Lock()
	first := honeypotIPAlertAt["203.0.113.103"]
	honeypotMu.Unlock()
	honeypotHit(3389, "203.0.113.103:45679")
	honeypotMu.Lock()
	second := honeypotIPAlertAt["203.0.113.103"]
	honeypotMu.Unlock()
	if first == 0 || second != first {
		t.Fatalf("10 分钟内同一 IP 不应重复置报警时间, %d -> %d", first, second)
	}
}

func TestHoneypotHistoryPorts(t *testing.T) {
	honeypotTestSetup(t)
	today := time.Now().Format("2006-01-02")
	old := time.Now().AddDate(0, 0, -8).Format("2006-01-02")
	lines := "{\"type\":\"new_conn\",\"ip\":\"203.0.113.110\",\"port\":45683,\"detail\":\"x\"}\n" +
		"{\"type\":\"ban\",\"ip\":\"203.0.113.110\",\"port\":45684,\"detail\":\"x\"}\n"
	if err := os.WriteFile(filepath.Join(eventsDir, today+".jsonl"), []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(eventsDir, old+".jsonl"), []byte("{\"type\":\"new_conn\",\"ip\":\"203.0.113.110\",\"port\":45685,\"detail\":\"x\"}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	hist := honeypotHistoryPorts()
	if !hist[45683] {
		t.Fatal("7 天内 new_conn 的端口应进历史集合")
	}
	if hist[45684] {
		t.Fatal("ban 事件端口不是真实流量, 不应进历史集合")
	}
	if hist[45685] {
		t.Fatal("8 天前的端口已出 7 天窗口, 不应进历史集合")
	}
}

func TestHoneypotApplyAndRollback(t *testing.T) {
	honeypotTestSetup(t)
	// 保留端口拒绝, 且旧配置不动
	if _, _, err := honeypotApply(HoneypotConfig{Enabled: true, Ports: []int{80}, AlertEnabled: true, HitThreshold: 1, BanHours: 24}, true); err == nil {
		t.Fatal("80 端口启用蜜罐必须被拒绝")
	} else if !strings.Contains(err.Error(), "80") {
		t.Fatalf("拒绝原因应点名端口, 实际 %v", err)
	}
	honeypotMu.Lock()
	wasEnabled := honeypotCfg.Enabled
	honeypotMu.Unlock()
	if wasEnabled {
		t.Fatal("拒绝后旧配置不应被启用")
	}
	// 正常启用: 拨测能通; 再关掉: 拨测不通
	cfg := HoneypotConfig{Enabled: true, Ports: []int{45686}, AlertEnabled: false, HitThreshold: 1, BanHours: 24}
	if _, _, err := honeypotApply(cfg, true); err != nil {
		t.Fatalf("空闲端口启用蜜罐应成功, 实际 %v", err)
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:45686", 2*time.Second)
	if err != nil {
		t.Fatalf("启用后蜜罐端口应可拨通, 实际 %v", err)
	}
	c.Close()
	cfg.Enabled = false
	if _, _, err := honeypotApply(cfg, true); err != nil {
		t.Fatalf("关闭蜜罐应成功, 实际 %v", err)
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:45686", 500*time.Millisecond); err == nil {
		t.Fatal("关闭后蜜罐端口应不再监听")
	}
}

// 第 7 项回归测试: 蜜罐封禁时长 0 = 永久, 只纠负数回默认 24 小时。
func TestHoneypotBanHoursZeroPermanent(t *testing.T) {
	dir := t.TempDir()
	oldFile, oldCfg := honeypotFile, honeypotCfg
	honeypotFile = filepath.Join(dir, "honeypot.json")
	t.Cleanup(func() {
		honeypotMu.Lock()
		honeypotFile, honeypotCfg = oldFile, oldCfg
		honeypotMu.Unlock()
	})
	readBanHours := func() int {
		t.Helper()
		honeypotMu.Lock()
		defer honeypotMu.Unlock()
		return honeypotCfg.BanHours
	}
	// 落盘 0: load 不应钳回 24
	honeypotMu.Lock()
	honeypotCfg = HoneypotConfig{BanHours: 0}
	honeypotMu.Unlock()
	saveHoneypot()
	honeypotMu.Lock()
	honeypotCfg = HoneypotConfig{}
	honeypotMu.Unlock()
	loadHoneypot()
	if got := readBanHours(); got != 0 {
		t.Fatalf("落盘 BanHours=0 经 load 应保持 0, 实际 %d", got)
	}
	// 落盘负数: 纠回 24
	honeypotMu.Lock()
	honeypotCfg = HoneypotConfig{BanHours: -5}
	honeypotMu.Unlock()
	saveHoneypot()
	honeypotMu.Lock()
	honeypotCfg = HoneypotConfig{}
	honeypotMu.Unlock()
	loadHoneypot()
	if got := readBanHours(); got != 24 {
		t.Fatalf("落盘 BanHours=-5 经 load 应纠回 24, 实际 %d", got)
	}
	// apply 路径: 0 落盘保持 0, 负数纠回 24(不启用, 不监听, 不触发确认)
	if _, _, err := honeypotApply(HoneypotConfig{BanHours: 0, HitThreshold: 1}, false); err != nil {
		t.Fatalf("apply BanHours=0 应成功, 实际 %v", err)
	}
	if got := readBanHours(); got != 0 {
		t.Fatalf("apply BanHours=0 应落盘 0, 实际 %d", got)
	}
	if _, _, err := honeypotApply(HoneypotConfig{BanHours: -3, HitThreshold: 1}, false); err != nil {
		t.Fatalf("apply BanHours=-3 应成功, 实际 %v", err)
	}
	if got := readBanHours(); got != 24 {
		t.Fatalf("apply BanHours=-3 应纠回 24, 实际 %d", got)
	}
}
