package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSplitHostPortZone(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"[2001:db8:1::696]%enp2s0:34579", "2001:db8:1::696", 34579},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"192.168.1.5:22", "192.168.1.5", 22},
		{"[fe80::1]%eth0:8080", "fe80::1", 8080},
	}
	for _, c := range cases {
		ip, p := splitHostPort(c.in)
		if ip != c.ip || p != c.port {
			t.Errorf("splitHostPort(%q) = %q,%d want %q,%d", c.in, ip, p, c.ip, c.port)
		}
	}
}

func TestParseSSZoned(t *testing.T) {
	out := "0 0 [2001:db8::696]%enp2s0:34579 [2001:db8:1::38]:34263 users:((\"qbittorrent\",pid=1,fd=1))\n" +
		"0 0 192.168.1.2:22 203.0.113.5:51000 users:((\"sshd\",pid=2,fd=2))\n"
	conns, _ := parseSS(out, false)
	if len(conns) != 2 {
		t.Fatalf("want 2 conns got %d: %+v", len(conns), conns)
	}
	if conns[0].DstPort != 34579 || conns[0].SrcIP != "2001:db8:1::38" {
		t.Errorf("zoned conn parsed wrong: %+v", conns[0])
	}
}

func TestCTConns(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ct")
	data := "ipv4 2 udp 17 25 src=203.0.113.7 dst=127.0.0.1 sport=51234 dport=34579 src=127.0.0.1 dst=203.0.113.7 sport=34579 dport=51234 mark=0 zone=0 use=2\n" +
		"ipv4 2 udp 17 25 src=127.0.0.1 dst=198.51.100.9 sport=34579 dport=6881 src=198.51.100.9 dst=127.0.0.1 sport=6881 dport=34579 mark=0 use=1\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=203.0.113.8 dst=127.0.0.1 sport=1111 dport=34579 src=127.0.0.1 dst=203.0.113.8 sport=34579 dport=1111 [ASSURED] mark=0 use=1\n" +
		// DNAT 转发给容器: 原始方向 dst 是本机 IP, 回复方向 src 是容器 IP(172.17.0.5), ss 看不见, 必须算入站
		"ipv4 2 tcp 6 100 ESTABLISHED src=203.0.113.10 dst=127.0.0.1 sport=4444 dport=34579 src=172.17.0.5 dst=203.0.113.10 sport=8080 dport=4444 [ASSURED] mark=0 use=1\n" +
		// TCP 非 ESTABLISHED/SYN_RECV 状态不取
		"ipv4 2 tcp 6 100 TIME_WAIT src=203.0.113.11 dst=127.0.0.1 sport=5555 dport=34579 src=127.0.0.1 dst=203.0.113.11 sport=34579 dport=5555 [ASSURED] mark=0 use=1\n" +
		"ipv4 2 udp 17 25 src=203.0.113.9 dst=127.0.0.1 sport=2222 dport=9999 src=127.0.0.1 dst=203.0.113.9 sport=9999 dport=2222 mark=0 use=1\n" +
		"ipv4 2 udp 17 25 src=127.0.0.1 dst=127.0.0.1 sport=34579 dport=34579 src=127.0.0.1 dst=127.0.0.1 sport=34579 dport=34579 mark=0 use=1\n"
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	old := ctPath
	ctPath = p
	defer func() { ctPath = old }()
	eff := map[int]bool{34579: true}
	got := ctConns(eff)
	udp, tcp := map[string]bool{}, map[string]bool{}
	for _, c := range got {
		if c.DstPort != 34579 {
			t.Errorf("bad conn port: %+v", c)
		}
		switch c.Proto {
		case "udp":
			udp[c.SrcIP] = true
		case "tcp":
			tcp[c.SrcIP] = true
		default:
			t.Errorf("bad proto: %+v", c)
		}
	}
	if !udp["203.0.113.7"] || !udp["198.51.100.9"] || len(udp) != 2 {
		t.Errorf("udp peers wrong: %+v", got)
	}
	if !tcp["203.0.113.8"] || !tcp["203.0.113.10"] || len(tcp) != 2 {
		t.Errorf("tcp peers wrong (terminated + forwarded expected): %+v", got)
	}
}

func TestParseNetDev(t *testing.T) {
	content := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n" +
		"enp2s0: 26232153970 66183176 0 11 0 0 0 76570 22110598184 58745203 0 26 0 0 0 0\n" +
		"enp3s0-ovs: 59404951442 52458528 0 58829 0 0 0 0 102241273337 60784050 0 0 0 0 0 0\n"
	m := parseNetDev(content)
	if len(m) != 3 {
		t.Fatalf("want 3 ifaces got %d: %+v", len(m), m)
	}
	if m["enp2s0"][0] != 26232153970 || m["enp2s0"][1] != 22110598184 {
		t.Errorf("enp2s0 counters wrong: %+v", m["enp2s0"])
	}
	if m["lo"][0] != 1000 || m["lo"][1] != 1000 {
		t.Errorf("lo counters wrong: %+v", m["lo"])
	}
}

func TestIsPhysicalNIC(t *testing.T) {
	dir := t.TempDir()
	old := sysNetDir
	sysNetDir = dir
	defer func() { sysNetDir = old }()
	mk := func(name string, device bool, state string) {
		d := filepath.Join(dir, name)
		os.MkdirAll(d, 0755)
		if device {
			os.MkdirAll(filepath.Join(dir, "dev-"+name), 0755)
			os.Symlink(filepath.Join(dir, "dev-"+name), filepath.Join(d, "device"))
		}
		os.WriteFile(filepath.Join(d, "operstate"), []byte(state+"\n"), 0644)
	}
	mk("enp2s0", true, "up")     // 物理口在用: 要
	mk("enp3s0", true, "up")     // 物理口在用: 要
	mk("enp4s0", true, "down")   // 物理口没插线: 不要
	mk("enp3s0-ovs", true, "up") // OVS 镜像: 不要(与物理口重复计数)
	mk("docker0", false, "up")   // 虚拟网桥: 不要
	mk("veth1234", false, "up")  // 容器虚拟口: 不要
	mk("lo", true, "unknown")    // 回环: 不要
	want := map[string]bool{"enp2s0": true, "enp3s0": true, "enp4s0": false,
		"enp3s0-ovs": false, "docker0": false, "veth1234": false, "lo": false}
	for name, w := range want {
		if got := isPhysicalNIC(name); got != w {
			t.Errorf("isPhysicalNIC(%q) = %v want %v", name, got, w)
		}
	}
}

func TestTrafficRate(t *testing.T) {
	dir := t.TempDir()
	oldDev, oldSys := procNetDev, sysNetDir
	defer func() { procNetDev, sysNetDir = oldDev, oldSys }()
	sysDir := filepath.Join(dir, "sys")
	os.MkdirAll(filepath.Join(sysDir, "enp2s0"), 0755)
	os.MkdirAll(filepath.Join(dir, "pci"), 0755)
	os.Symlink(filepath.Join(dir, "pci"), filepath.Join(sysDir, "enp2s0", "device"))
	os.WriteFile(filepath.Join(sysDir, "enp2s0", "operstate"), []byte("up\n"), 0644)
	sysNetDir = sysDir
	devFile := filepath.Join(dir, "dev")
	procNetDev = devFile
	write := func(rx, tx uint64) {
		content := "enp2s0: " + itoa(int(rx)) + " 1 0 0 0 0 0 0 " + itoa(int(tx)) + " 1 0 0 0 0 0 0\n" +
			"    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n"
		os.WriteFile(devFile, []byte(content), 0644)
	}
	trafMu.Lock()
	trafPrev, trafCur = map[string]devSample{}, map[string]IfaceTraffic{}
	trafMu.Unlock()
	write(1000000, 2000000)
	trafficTick() // 基线, 速率应为 0
	snap := trafficSnapshot()
	if len(snap) != 1 || snap[0].Name != "enp2s0" {
		t.Fatalf("snapshot wrong (lo must be excluded): %+v", snap)
	}
	if snap[0].RxBps != 0 || snap[0].TxBps != 0 {
		t.Errorf("first tick rate must be 0: %+v", snap[0])
	}
	// 手工把基线时间拨回 2 秒前, 再喂新计数: rx +2000000, tx +1000000 -> 1MB/s, 0.5MB/s
	trafMu.Lock()
	p := trafPrev["enp2s0"]
	p.at = p.at.Add(-2 * 1000000000)
	trafPrev["enp2s0"] = p
	trafMu.Unlock()
	write(3000000, 3000000)
	trafficTick()
	snap = trafficSnapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot wrong: %+v", snap)
	}
	if snap[0].RxBps < 950000 || snap[0].RxBps > 1050000 {
		t.Errorf("rx rate wrong: %d", snap[0].RxBps)
	}
	if snap[0].TxBps < 450000 || snap[0].TxBps > 550000 {
		t.Errorf("tx rate wrong: %d", snap[0].TxBps)
	}
	if snap[0].RxTot != 3000000 || snap[0].TxTot != 3000000 {
		t.Errorf("totals wrong: %+v", snap[0])
	}
}

func TestListEventsPaging(t *testing.T) {
	dir := t.TempDir()
	old := eventsDir
	eventsDir = dir
	defer func() { eventsDir = old }()
	// 写 250 条 new_conn + 30 条 ssh_fail 到同一天文件
	var lines []byte
	for i := 0; i < 250; i++ {
		lines = append(lines, []byte(`{"id":"n`+itoa(i)+`","ts":`+itoa(1700000000+i)+`,"type":"new_conn","ip":"203.0.113.`+itoa(i%250)+`","port":34579,"detail":"新来源"}`+"\n")...)
	}
	for i := 0; i < 30; i++ {
		lines = append(lines, []byte(`{"id":"s`+itoa(i)+`","ts":`+itoa(1700001000+i)+`,"type":"ssh_fail","ip":"198.51.100.7","detail":"SSH 登录失败"}`+"\n")...)
	}
	if err := os.WriteFile(filepath.Join(dir, "2026-10-23.jsonl"), lines, 0644); err != nil {
		t.Fatal(err)
	}
	page, total := listEvents("new_conn", "", 100, 0)
	if total != 250 || len(page) != 100 {
		t.Fatalf("page1: total=%d len=%d want 250/100", total, len(page))
	}
	page, total = listEvents("new_conn", "", 100, 200)
	if total != 250 || len(page) != 50 {
		t.Fatalf("page3: total=%d len=%d want 250/50", total, len(page))
	}
	page, total = listEvents("", "", 500, 0)
	if total != 280 || len(page) != 280 {
		t.Fatalf("all: total=%d len=%d want 280/280", total, len(page))
	}
	if page[0].Type != "ssh_fail" {
		t.Errorf("newest first expected, got %s", page[0].Type)
	}
	_, total = listEvents("", "198.51.100", 100, 0)
	if total != 30 {
		t.Errorf("q filter: total=%d want 30", total)
	}
	page, _ = listEvents("new_conn", "", 100, 9999)
	if len(page) != 0 {
		t.Errorf("offset beyond total must be empty, got %d", len(page))
	}
}

func TestCTBytes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ct")
	data := // 入站 UDP: 原始 bytes=对端发来(Rx), 回复 bytes=本机发出(Tx)
		"ipv4 2 udp 17 25 src=203.0.113.7 dst=127.0.0.1 sport=51234 dport=34579 packets=3 bytes=300 src=127.0.0.1 dst=203.0.113.7 sport=34579 dport=51234 packets=2 bytes=200 mark=0 use=2\n" +
			// 同一对端同端口第二条流(源端口不同): 字节应聚合到同一行
			"ipv4 2 udp 17 25 src=203.0.113.7 dst=127.0.0.1 sport=51235 dport=34579 packets=1 bytes=100 src=127.0.0.1 dst=203.0.113.7 sport=34579 dport=51235 packets=1 bytes=50 mark=0 use=2\n" +
			// 外连 UDP: 原始方向是本机发出(Tx), 回复是对端发来(Rx)
			"ipv4 2 udp 17 25 src=127.0.0.1 dst=198.51.100.9 sport=34579 dport=6881 packets=9 bytes=1000 src=198.51.100.9 dst=127.0.0.1 sport=6881 dport=34579 packets=9 bytes=4000 mark=0 use=1\n" +
			// 入站 TCP
			"ipv4 2 tcp 6 100 ESTABLISHED src=203.0.113.8 dst=127.0.0.1 sport=1111 dport=34579 packets=9 bytes=5000 src=127.0.0.1 dst=203.0.113.8 sport=34579 dport=1111 packets=9 bytes=600 [ASSURED] mark=0 use=1\n"
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	old := ctPath
	ctPath = p
	defer func() { ctPath = old }()
	got := ctConns(map[int]bool{34579: true})
	if len(got) != 3 {
		t.Fatalf("want 3 aggregated conns got %d: %+v", len(got), got)
	}
	byIP := map[string]Conn{}
	for _, c := range got {
		byIP[c.SrcIP] = c
	}
	if c := byIP["203.0.113.7"]; c.Rx != 400 || c.Tx != 250 || !c.HasBytes {
		t.Errorf("inbound aggregated bytes wrong: %+v", c)
	}
	if c := byIP["198.51.100.9"]; c.Rx != 4000 || c.Tx != 1000 {
		t.Errorf("outbound bytes wrong: %+v", c)
	}
	if c := byIP["203.0.113.8"]; c.Rx != 5000 || c.Tx != 600 {
		t.Errorf("tcp bytes wrong: %+v", c)
	}
}

func TestCTNoBytes(t *testing.T) {
	// 内核 nf_conntrack_acct 关闭时, conntrack 行里根本没有 packets=/bytes= 字段:
	// 必须识别为「无流量数据」(HasBytes=false), 不能报成 0 流量
	dir := t.TempDir()
	p := filepath.Join(dir, "ct")
	data := "ipv4 2 tcp 6 100 ESTABLISHED src=203.0.113.8 dst=127.0.0.1 sport=1111 dport=34579 src=127.0.0.1 dst=203.0.113.8 sport=34579 dport=1111 [ASSURED] mark=0 zone=0 use=1\n"
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	old := ctPath
	ctPath = p
	defer func() { ctPath = old }()
	got := ctConns(map[int]bool{34579: true})
	if len(got) != 1 {
		t.Fatalf("want 1 conn got %d", len(got))
	}
	if got[0].HasBytes {
		t.Errorf("no bytes= fields must mean HasBytes=false: %+v", got[0])
	}
}

func TestListEventsTwoDirs(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	old1, old2 := eventsDir, eventsSrcDir
	eventsDir, eventsSrcDir = d1, d2
	defer func() { eventsDir, eventsSrcDir = old1, old2 }()
	os.WriteFile(filepath.Join(d1, "2026-10-23.jsonl"), []byte(
		`{"id":"a","ts":1700002000,"type":"ssh_login","ip":"203.0.113.1","detail":"SSH 登录"}`+"\n"+
			`{"id":"b","ts":1700001000,"type":"new_conn","ip":"203.0.113.2","port":16722,"detail":"新连接"}`+"\n"), 0644)
	os.WriteFile(filepath.Join(d2, "2026-10-23.jsonl"), []byte(
		`{"id":"c","ts":1700003000,"type":"new_src","ip":"203.0.113.3","port":34579,"detail":"新来源"}`+"\n"+
			`{"id":"d","ts":1700000500,"type":"new_src","ip":"203.0.113.4","port":34579,"detail":"新来源"}`+"\n"), 0644)
	page, total := listEvents("", "", 100, 0)
	if total != 4 || len(page) != 4 {
		t.Fatalf("merged total=%d len=%d want 4/4", total, len(page))
	}
	if page[0].ID != "c" || page[3].ID != "d" {
		t.Errorf("must be ts-desc across dirs: %s..%s", page[0].ID, page[3].ID)
	}
	_, total = listEvents("new_src", "", 100, 0)
	if total != 2 {
		t.Errorf("new_src filter total=%d want 2", total)
	}
	page, _ = listEvents("", "", 2, 2)
	if len(page) != 2 || page[0].ID != "b" {
		t.Errorf("paging across dirs wrong: %+v", page)
	}
}

func TestPruneNewSrc(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	old1, old2 := eventsDir, eventsSrcDir
	eventsDir, eventsSrcDir = d1, d2
	oldSet := settings
	defer func() { eventsDir, eventsSrcDir = old1, old2; settings = oldSet }()
	settings.LogKeepDays = 30
	settings.NewSrcKeepDays = 7
	old10 := time.Now().AddDate(0, 0, -10).Format("2006-01-02")
	old3 := time.Now().AddDate(0, 0, -3).Format("2006-01-02")
	os.WriteFile(filepath.Join(d1, old10+".jsonl"), []byte("{}\n"), 0644)
	os.WriteFile(filepath.Join(d2, old10+".jsonl"), []byte("{}\n"), 0644)
	os.WriteFile(filepath.Join(d2, old3+".jsonl"), []byte("{}\n"), 0644)
	pruneEvents()
	if _, err := os.Stat(filepath.Join(d2, old10+".jsonl")); !os.IsNotExist(err) {
		t.Errorf("new_src older than 7d must be pruned")
	}
	if _, err := os.Stat(filepath.Join(d2, old3+".jsonl")); err != nil {
		t.Errorf("new_src within 7d must stay")
	}
	if _, err := os.Stat(filepath.Join(d1, old10+".jsonl")); err != nil {
		t.Errorf("regular events within 30d must stay")
	}
}
