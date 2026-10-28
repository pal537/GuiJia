package main

// 防火墙重做回归: 旧规则迁移、新规则 API 校验、国家接口、采集路径端到端。

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFirewallMigration: 旧"端口+省白名单"规则自动转为新格式并回写。
func TestFirewallMigration(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	oldRules := pgRules
	defer func() { pgMu.Lock(); pgRules = oldRules; pgMu.Unlock() }()

	oldJSON := `[{"id":"gold","ports":[45167,3004],"locations":[{"kind":"province","name":"江苏"},{"kind":"city","name":"南京","province":"江苏"}],"banHours":48,"enabled":false}]`
	if err := os.WriteFile(filepath.Join(dir, "portguard.json"), []byte(oldJSON), 0644); err != nil {
		t.Fatal(err)
	}
	loadPortGuard()
	pgMu.Lock()
	if len(pgRules) != 1 {
		pgMu.Unlock()
		t.Fatalf("迁移后应为 1 条规则, 实际 %d", len(pgRules))
	}
	r := pgRules[0]
	pgMu.Unlock()
	if r.ID != "gold" || r.PortText != "45167,3004" || r.Proto != "all" || r.Action != "allow" {
		t.Fatalf("迁移字段不对: %+v", r)
	}
	if r.Source.Kind != "custom_cn" || len(r.Source.Locations) != 2 {
		t.Fatalf("迁移来源应为自定义位置（中国）(旧省名单), 得到 %+v", r.Source)
	}
	if !rangesEqual(r.ranges, [][2]int{{3004, 3004}, {45167, 45167}}) {
		t.Fatalf("迁移端口范围不对: %v", r.ranges)
	}
	if r.BanHours != 48 || r.Enabled {
		t.Fatalf("迁移应保留时长与禁用态: %+v", r)
	}
	// 回写文件应为新格式: 顶层无 ports, 有 source
	b, _ := os.ReadFile(filepath.Join(dir, "portguard.json"))
	var items []map[string]any
	if err := json.Unmarshal(b, &items); err != nil || len(items) != 1 {
		t.Fatalf("回写文件解析失败: %v", err)
	}
	if _, ok := items[0]["ports"]; ok {
		t.Fatal("回写文件不应再有顶层 ports")
	}
	if _, ok := items[0]["source"]; !ok {
		t.Fatal("回写文件应有 source")
	}
	// 新格式再加载: 不改写文件(字节一致)
	before, _ := os.ReadFile(filepath.Join(dir, "portguard.json"))
	loadPortGuard()
	after, _ := os.ReadFile(filepath.Join(dir, "portguard.json"))
	if string(before) != string(after) {
		t.Fatal("新格式加载不应改写文件")
	}
}

// TestFirewallAPIValidation: 新增规则的校验(端口/CIDR/自定义位置/重复)。
func TestFirewallAPIValidation(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	pgMu.Lock()
	pgRules = nil
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	post := func(body string) int {
		req := httptest.NewRequest("POST", "/api/portguard", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handlePortGuard(rec, req)
		return rec.Code
	}
	if code := post(`{"portText":"8000-8010","proto":"all","source":{"kind":"cn_in"},"action":"allow","banHours":24}`); code != 200 {
		t.Fatalf("合法规则应 200, 实际 %d", code)
	}
	if code := post(`{"portText":"90-80","proto":"all","source":{"kind":"all"},"action":"allow"}`); code != 400 {
		t.Fatalf("起止颠倒应 400, 实际 %d", code)
	}
	if code := post(`{"portText":"80","proto":"all","source":{"kind":"custom_ip","cidr":"999.1.1.1"},"action":"allow"}`); code != 400 {
		t.Fatalf("非法 CIDR 应 400, 实际 %d", code)
	}
	if code := post(`{"portText":"80","proto":"all","source":{"kind":"custom_ip"},"action":"allow"}`); code != 400 {
		t.Fatalf("自定义 IP 为空应 400, 实际 %d", code)
	}
	if code := post(`{"portText":"80","proto":"all","source":{"kind":"custom_cn"},"action":"allow"}`); code != 400 {
		t.Fatalf("自定义位置（中国）空选应 400, 实际 %d", code)
	}
	if code := post(`{"portText":"80","proto":"all","source":{"kind":"custom_foreign","countries":["不存在的国家"]},"action":"allow"}`); code != 400 {
		t.Fatalf("未知国家应 400, 实际 %d", code)
	}
	if code := post(`{"portText":"80","proto":"all","source":{"kind":"custom_foreign","countries":["HK"]},"action":"allow"}`); code != 200 {
		t.Fatalf("港澳台地区级选项应 200, 实际 %d", code)
	}
	if code := post(`{"portText":"80","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"香港"}]},"action":"allow"}`); code != 400 {
		t.Fatalf("中国选择器含港澳台应 400, 实际 %d", code)
	}
	if code := post(`{"portText":"80","proto":"all","source":{"kind":"custom_loc","countries":["美国"]},"action":"allow"}`); code != 400 {
		t.Fatalf("旧 kind custom_loc 应 400, 实际 %d", code)
	}
	// 旧字符串归一化入库: "美国"存为 US
	if code := post(`{"portText":"81","proto":"all","source":{"kind":"custom_foreign","countries":["美国","United States"]},"action":"allow"}`); code != 200 {
		t.Fatalf("旧国家字符串应归一化入库, 实际 %d", code)
	}
	// 完全相同规则 -> 400
	if code := post(`{"portText":"8000-8010","proto":"all","source":{"kind":"cn_in"},"action":"allow","banHours":24}`); code != 400 {
		t.Fatalf("完全相同规则应 400, 实际 %d", code)
	}
	// 一个端口一条规则: 只撞端口、来源不同也 400(允许+拒绝同端口就是逻辑冲突)
	if code := post(`{"portText":"8000-8010","proto":"all","source":{"kind":"cn_out"},"action":"deny","banHours":24}`); code != 400 {
		t.Fatalf("同端口不同来源/动作也应 400, 实际 %d", code)
	}
	// 端口范围相交且动作相反也算冲突: 8005 落在 8000-8010 内
	if code := post(`{"portText":"8005","proto":"all","source":{"kind":"all"},"action":"deny"}`); code != 400 {
		t.Fatalf("端口范围相交反动作应 400, 实际 %d", code)
	}
	// 端口范围相交但同动作是并集: 8005 允许应 200
	if code := post(`{"portText":"8005","proto":"all","source":{"kind":"all"},"action":"allow"}`); code != 200 {
		t.Fatalf("端口范围相交同动作应 200, 实际 %d", code)
	}
	// 协议不相交不冲突: 同端口 TCP 与 UDP 各一条可以共存
	if code := post(`{"portText":"9000","proto":"tcp","source":{"kind":"all"},"action":"allow"}`); code != 200 {
		t.Fatalf("TCP 规则应 200, 实际 %d", code)
	}
	if code := post(`{"portText":"9000","proto":"udp","source":{"kind":"all"},"action":"deny"}`); code != 200 {
		t.Fatalf("UDP 规则与 TCP 规则不冲突应 200, 实际 %d", code)
	}
	// 全部协议与 TCP 相交: 9000 已有 TCP 规则, 再建 all 规则应 400
	if code := post(`{"portText":"9000","proto":"all","source":{"kind":"all"},"action":"allow"}`); code != 400 {
		t.Fatalf("全部协议与 TCP 规则相交应 400, 实际 %d", code)
	}
	// 自定义 IP 多个逗号分隔: 合法应 200, 其中一个非法应 400
	if code := post(`{"portText":"9100","proto":"all","source":{"kind":"custom_ip","cidr":"8.8.8.8, 1.2.3.0/24"},"action":"allow"}`); code != 200 {
		t.Fatalf("多 IP 自定义应 200, 实际 %d", code)
	}
	if code := post(`{"portText":"9101","proto":"all","source":{"kind":"custom_ip","cidr":"8.8.8.8, 999.1.1.1"},"action":"allow"}`); code != 400 {
		t.Fatalf("多 IP 中有非法应 400, 实际 %d", code)
	}
	// 留空时长 = 24 小时(沿用旧语义: 前端留空传 0 时后端按 0 存? 这里验证
	// parseFWRuleInput 对 0 的处理: 0=永久, 与"留空"区分在前端换算层)
	rule, err := parseFWRuleInput("80", "all", FWSource{Kind: "all"}, "allow", 0)
	if err != nil || rule.BanHours != 0 {
		t.Fatalf("时长 0 应为永久, 得到 %+v %v", rule, err)
	}
}

// TestGeoCountriesEndpoint: 国家接口返回库原字符串 + 港澳台选项。
func TestGeoCountriesEndpoint(t *testing.T) {
	geoLoadV4Embedded()
	req := httptest.NewRequest("GET", "/api/geo/countries", nil)
	rec := httptest.NewRecorder()
	handleGeoCountries(rec, req)
	if rec.Code != 200 {
		t.Fatalf("国家接口应 200, 实际 %d", rec.Code)
	}
	var m struct {
		Countries []string `json:"countries"`
		SAR       []string `json:"sar"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Countries) < 200 {
		t.Fatalf("国家数过少: %d", len(m.Countries))
	}
	found := map[string]bool{}
	for _, c := range m.Countries {
		found[c] = true
	}
	for _, want := range []string{"中国", "United States", "Japan", "Bangladesh"} {
		if !found[want] {
			t.Fatalf("国家列表缺 %s", want)
		}
	}
	if found["Reserved"] {
		t.Fatal("国家列表不应含 Reserved")
	}
	if len(m.SAR) != 3 || m.SAR[0] != "香港" || m.SAR[1] != "澳门" || m.SAR[2] != "台湾" {
		t.Fatalf("港澳台选项不对: %v", m.SAR)
	}
}

// TestFirewallCollectionPath: 采集路径端到端(伪造 conntrack 文件 + sampleConns)。
// 证明: 未监听的防护端口照样可见(范围不展开也能触发)、TCP 与 UDP 都能触发、
// 允许规则放行、默认封禁只封规则端口。DRYBAN 下以 bans.json 里的封禁决策为准。
func TestFirewallCollectionPath(t *testing.T) {
	dir := banTestSetup(t)
	oldData, oldEvents, oldEventsSrc, oldCt := dataDir, eventsDir, eventsSrcDir, ctPath
	dataDir = dir
	eventsDir = filepath.Join(dir, "events")
	eventsSrcDir = filepath.Join(dir, "events-src")
	os.MkdirAll(eventsDir, 0755)
	os.MkdirAll(eventsSrcDir, 0755)
	defer func() { dataDir, eventsDir, eventsSrcDir, ctPath = oldData, oldEvents, oldEventsSrc, oldCt }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()
	oldAlert := settings.AlertPortGuardBan
	settings.AlertPortGuardBan = false
	defer func() { settings.AlertPortGuardBan = oldAlert }()
	geoLoadV4Embedded()

	// 本机 IP(伪造行的 dst, 必须是 localIPSet 里的地址)
	locals := localIPSet()
	var local string
	for ip := range locals {
		if ip != "127.0.0.1" && !strings.HasPrefix(ip, "::") {
			local = ip
			break
		}
	}
	if local == "" {
		t.Skip("本机无非回环 IP, 无法构造入站伪造行")
	}
	// 规则: 只允许江苏(114.114.114.114 是江苏南京, 应放行; 其余默认封禁)
	pgMu.Lock()
	pgRules = []*PortGuardRule{{ID: "gtest", PortText: "45167", Proto: "all",
		Source:   FWSource{Kind: "custom_cn", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}},
		Action:   "allow",
		BanHours: 24, Enabled: true, ranges: [][2]int{{45167, 45167}}}}
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	// 伪造 conntrack: TCP(203.0.113.99, 澳大利亚 -> 默认封禁)、UDP(203.0.113.98
	// -> 默认封禁)、TCP(114.114.114.114 江苏 -> 放行)、TCP(8.8.8.8 美国 -> 默认封禁)
	lines := []string{
		"ipv4 2 tcp 6 100 ESTABLISHED src=203.0.113.99 dst=" + local + " sport=40000 dport=45167 packets=1 bytes=60 src=" + local + " dst=203.0.113.99 sport=45167 dport=40000 packets=1 bytes=60 mark=0 use=1",
		"ipv4 2 udp 17 100 src=203.0.113.98 dst=" + local + " sport=40001 dport=45167 packets=1 bytes=60 src=" + local + " dst=203.0.113.98 sport=45167 dport=40001 packets=1 bytes=60 mark=0 use=1",
		"ipv4 2 tcp 6 100 ESTABLISHED src=114.114.114.114 dst=" + local + " sport=40002 dport=45167 packets=1 bytes=60 src=" + local + " dst=114.114.114.114 sport=45167 dport=40002 packets=1 bytes=60 mark=0 use=1",
		"ipv4 2 tcp 6 100 ESTABLISHED src=8.8.8.8 dst=" + local + " sport=40003 dport=45167 packets=1 bytes=60 src=" + local + " dst=8.8.8.8 sport=45167 dport=40003 packets=1 bytes=60 mark=0 use=1",
	}
	ctFile := filepath.Join(dir, "nf_conntrack")
	if err := os.WriteFile(ctFile, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ctPath = ctFile
	sampleConns()

	if !isBannedFor("203.0.113.99", 45167) {
		t.Fatal("TCP 默认封禁未触发(未监听端口应照样可见)")
	}
	if !isBannedFor("203.0.113.98", 45167) {
		t.Fatal("UDP 默认封禁未触发(UDP 经 conntrack 应可防护)")
	}
	if isBanned("114.114.114.114") {
		t.Fatal("江苏 IP 应被允许规则放行")
	}
	if !isBannedFor("8.8.8.8", 45167) || isGloballyBanned("8.8.8.8") {
		t.Fatal("美国 IP 应只被规则端口封禁, 不扩全局")
	}
	// 封禁记录的作用域必须是规则范围(不是旧 Ports, 不是全局)
	banMu.Lock()
	var scopes int
	for _, b := range bans {
		if b.IP == "203.0.113.99" {
			scopes = len(b.Scopes)
		}
	}
	banMu.Unlock()
	if scopes != 1 {
		t.Fatalf("203.0.113.99 应有 1 条规则作用域, 实际 %d", scopes)
	}
}

// TestFirewallCustomLocSplit: v1.0.9 custom_loc 迁移拆分。
// 只有省市 -> custom_cn(ID 不变); 只有国家 -> custom_foreign(归一化为代码);
// 两边都有 + 港澳台省市 -> 拆成 ID-cn(大陆省市) + ID-foreign(国家 + HK)。
func TestFirewallCustomLocSplit(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	oldRules := pgRules
	defer func() { pgMu.Lock(); pgRules = oldRules; pgMu.Unlock() }()

	seed := func(json string) {
		if err := os.WriteFile(filepath.Join(dir, "portguard.json"), []byte(json), 0644); err != nil {
			t.Fatal(err)
		}
		loadPortGuard()
	}
	kinds := func() map[string]FWSource {
		pgMu.Lock()
		defer pgMu.Unlock()
		m := map[string]FWSource{}
		for _, r := range pgRules {
			m[r.ID] = r.Source
		}
		return m
	}

	seed(`[{"id":"a","portText":"80","proto":"all","source":{"kind":"custom_loc","locations":[{"kind":"province","name":"江苏"}]},"action":"allow","banHours":24,"enabled":true}]`)
	if m := kinds(); len(m) != 1 || m["a"].Kind != "custom_cn" || len(m["a"].Locations) != 1 {
		t.Fatalf("只有省市应转 custom_cn: %+v", m)
	}

	seed(`[{"id":"b","portText":"80","proto":"all","source":{"kind":"custom_loc","countries":["美国","United States","Japan"]},"action":"deny","banHours":24,"enabled":true}]`)
	if m := kinds(); len(m) != 1 || m["b"].Kind != "custom_foreign" || strings.Join(m["b"].Countries, ",") != "US,JP" {
		t.Fatalf("只有国家应转 custom_foreign 且归一化为代码: %+v", m)
	}

	seed(`[{"id":"c","portText":"443","proto":"tcp","source":{"kind":"custom_loc","countries":["美国"],"locations":[{"kind":"province","name":"江苏"},{"kind":"province","name":"香港"}]},"action":"allow","banHours":48,"enabled":true}]`)
	m := kinds()
	if len(m) != 2 {
		t.Fatalf("两边都有应拆成 2 条, 实际 %+v", m)
	}
	if cn, ok := m["c-cn"]; !ok || cn.Kind != "custom_cn" || len(cn.Locations) != 1 || cn.Locations[0].Name != "江苏" {
		t.Fatalf("拆分 custom_cn 应只有江苏: %+v", m)
	}
	if fr, ok := m["c-foreign"]; !ok || fr.Kind != "custom_foreign" || strings.Join(fr.Countries, ",") != "US,HK" {
		t.Fatalf("拆分 custom_foreign 应为 US,HK: %+v", m)
	}
	pgMu.Lock()
	for _, r := range pgRules {
		if r.PortText != "443" || r.Proto != "tcp" || r.Action != "allow" || r.BanHours != 48 || !r.Enabled {
			pgMu.Unlock()
			t.Fatalf("拆分后端口/协议/动作/时长/生效态应与旧规则一致: %+v", r)
		}
	}
	pgMu.Unlock()
	// 回写文件不再含 custom_loc
	b, _ := os.ReadFile(filepath.Join(dir, "portguard.json"))
	if strings.Contains(string(b), "custom_loc") {
		t.Fatal("回写文件不应再含 custom_loc")
	}

	seed(`[{"id":"d","portText":"80","proto":"all","source":{"kind":"custom_loc"},"action":"allow","banHours":24,"enabled":true}]`)
	if m := kinds(); len(m) != 0 {
		t.Fatalf("空的旧规则应丢弃, 实际 %+v", m)
	}
}
