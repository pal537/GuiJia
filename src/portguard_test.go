package main

// 防火墙回归测试: 端口解析(含范围)、归一化、来源分类、按规则封禁作用域。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePortRanges(t *testing.T) {
	cases := []struct {
		in   string
		want [][2]int
	}{
		{"45167", [][2]int{{45167, 45167}}},
		{"45167,3004", [][2]int{{3004, 3004}, {45167, 45167}}},
		{"45167，3004", [][2]int{{3004, 3004}, {45167, 45167}}},  // 中文逗号
		{"45167/3004", [][2]int{{3004, 3004}, {45167, 45167}}},  // 斜杠
		{"45167\\3004", [][2]int{{3004, 3004}, {45167, 45167}}}, // 反斜杠
		{"45167、3004", [][2]int{{3004, 3004}, {45167, 45167}}},  // 顿号
		{"45167, 3004，56806 / 8005", [][2]int{{3004, 3004}, {8005, 8005}, {45167, 45167}, {56806, 56806}}},
		{"45167,45167,3004", [][2]int{{3004, 3004}, {45167, 45167}}}, // 去重
		{"45167,", [][2]int{{45167, 45167}}},                         // 尾部分隔符容忍
		{"8000-8010", [][2]int{{8000, 8010}}},                        // 范围
		{"1-65535", [][2]int{{1, 65535}}},                            // 全范围
		{"80,8000-8010,443", [][2]int{{80, 80}, {443, 443}, {8000, 8010}}},
		{"80-90,85-100", [][2]int{{80, 100}}}, // 重叠合并
		{"80,81-90", [][2]int{{80, 90}}},      // 相邻合并
	}
	for _, c := range cases {
		got, err := parsePortRanges(c.in)
		if err != nil {
			t.Fatalf("parsePortRanges(%q) unexpected error: %v", c.in, err)
		}
		if !rangesEqual(got, c.want) {
			t.Fatalf("parsePortRanges(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	bad := []struct {
		in   string
		frag string
	}{
		{"8080;8443", "符号 ';' 不对，不可以"}, // 不支持的符号必须报错, 不静默丢掉
		{"8080|8443", "符号 '|' 不对，不可以"},
		{"0", "超出范围"},
		{"65536", "超出范围"},
		{"", "请填写端口"},
		{"abc", "符号 'a' 不对，不可以"},
		{"90-80", "起止不对"},
		{"80-90-100", "格式不对"},
		{"80-", "请填写端口"},
	}
	for _, c := range bad {
		if _, err := parsePortRanges(c.in); err == nil || !strings.Contains(err.Error(), c.frag) {
			t.Fatalf("parsePortRanges(%q) err = %v, want containing %q", c.in, err, c.frag)
		}
	}
	if got := formatPortRanges([][2]int{{1, 65535}}); got != "全部端口" {
		t.Fatalf("全范围展示 = %q, want 全部端口", got)
	}
	if got := formatPortRanges([][2]int{{80, 80}, {8000, 8010}}); got != "80,8000-8010" {
		t.Fatalf("混合展示 = %q, want 80,8000-8010", got)
	}
}

func TestNormRegionName(t *testing.T) {
	cases := map[string]string{
		"江苏省": "江苏", "上海市": "上海", "北京市": "北京", "重庆市": "重庆",
		"内蒙古自治区": "内蒙古", "广西壮族自治区": "广西", "新疆维吾尔自治区": "新疆",
		"宁夏回族自治区": "宁夏", "西藏自治区": "西藏", "香港特别行政区": "香港",
		"江苏": "江苏", "南京市": "南京", "南京": "南京",
		"延边朝鲜族自治州": "延边朝鲜族自治州", "阿勒泰地区": "阿勒泰地区", "锡林郭勒盟": "锡林郭勒盟",
		"0": "", "": "",
	}
	for in, want := range cases {
		if got := normRegionName(in); got != want {
			t.Fatalf("normRegionName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGuardLocationAllowed(t *testing.T) {
	jiangsu := []GuardLocation{{Kind: "province", Name: "江苏"}}
	nanjing := []GuardLocation{{Kind: "city", Name: "南京", Province: "江苏"}}
	mixed := append(append([]GuardLocation{}, jiangsu...), nanjing...)

	geoNJ := GeoInfo{Country: "中国", Province: "江苏省", City: "南京市"}
	geoSZ := GeoInfo{Country: "中国", Province: "江苏省", City: "苏州市"}
	geoHZ := GeoInfo{Country: "中国", Province: "浙江省", City: "杭州市"}
	geoNJNoSuffix := GeoInfo{Country: "中国", Province: "江苏", City: "南京"} // 库里无后缀也要对上
	geoQuirk := GeoInfo{Country: "中国", Province: "广州", City: "广州市"}     // Cloudflare 怪省
	geoUnknown := GeoInfo{}
	guangdong := []GuardLocation{{Kind: "province", Name: "广东"}}
	guangzhou := []GuardLocation{{Kind: "city", Name: "广州", Province: "广东"}}

	if !guardLocationAllowed(jiangsu, geoNJ) || !guardLocationAllowed(jiangsu, geoSZ) {
		t.Fatal("省条目应放行省内所有市")
	}
	if guardLocationAllowed(jiangsu, geoHZ) {
		t.Fatal("省条目不应放行外省")
	}
	if !guardLocationAllowed(nanjing, geoNJ) || guardLocationAllowed(nanjing, geoSZ) {
		t.Fatal("市条目应只放行该市")
	}
	if !guardLocationAllowed(nanjing, geoNJNoSuffix) {
		t.Fatal("无后缀的库字段也要对上")
	}
	if !guardLocationAllowed(mixed, geoSZ) || !guardLocationAllowed(mixed, geoNJ) {
		t.Fatal("省市混选任一命中即放行")
	}
	if !guardLocationAllowed(guangdong, geoQuirk) || !guardLocationAllowed(guangzhou, geoQuirk) {
		t.Fatal("怪省 IP 应归属到广东/广州市")
	}
	if guardLocationAllowed(jiangsu, geoUnknown) || guardLocationAllowed(nil, geoNJ) {
		t.Fatal("未知归属地与空 allowlist 默认拦")
	}
	// 市条目带错省不应命中(同名市防串)
	wrongProv := []GuardLocation{{Kind: "city", Name: "南京", Province: "浙江"}}
	if guardLocationAllowed(wrongProv, geoNJ) {
		t.Fatal("市条目所属省不对不应命中")
	}
}

// TestGuardProvinceOnlyWholeProvince: 只选省、没选市 = 整个省都是白名单
// （用户 2026-10-26 提问的确认项：已有 TestGuardLocationAllowed 覆盖省内多市，
// 这里补“城市字段为空的 IP”与“保存路径不丢省条目”两点）。
func TestGuardProvinceOnlyWholeProvince(t *testing.T) {
	jiangsu := []GuardLocation{{Kind: "province", Name: "江苏"}}
	for _, geo := range []GeoInfo{
		{Country: "中国", Province: "江苏省", City: "南京市"},
		{Country: "中国", Province: "江苏省", City: "苏州市"},
		{Country: "中国", Province: "江苏省", City: ""}, // 库里无城市字段：省对上即放行
	} {
		if !guardLocationAllowed(jiangsu, geo) {
			t.Fatalf("只选省应放行全省，%+v 未命中", geo)
		}
	}
	if guardLocationAllowed(jiangsu, GeoInfo{Country: "中国", Province: "浙江省", City: "杭州市"}) {
		t.Fatal("只选省不应放行外省")
	}
	// 保存路径：只选省的条目归一化后仍是省条目（不丢省、不变市）。
	rule, err := parseFWRuleInput("8080", "all", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "江苏省"}}}, "allow", 24)
	if err != nil {
		t.Fatal(err)
	}
	locs := rule.Source.Locations
	if len(locs) != 1 || locs[0].Kind != "province" || locs[0].Name != "江苏" || locs[0].Province != "" {
		t.Fatalf("只选省保存后应仍为省条目，得到 %+v", locs)
	}
	// 对照：省+市只命中该市。
	nanjing := []GuardLocation{{Kind: "city", Name: "南京", Province: "江苏"}}
	if !guardLocationAllowed(nanjing, GeoInfo{Province: "江苏省", City: "南京市"}) || guardLocationAllowed(nanjing, GeoInfo{Province: "江苏省", City: "苏州市"}) {
		t.Fatal("省+市应只命中该市")
	}
}

func TestRegionsList(t *testing.T) {
	if len(chinaRegions) < 400 {
		t.Fatalf("省市清单过短: %d 条", len(chinaRegions))
	}
	provs, seen := map[string]bool{}, map[string]bool{}
	for _, r := range chinaRegions {
		k := r.Kind + "|" + r.Name + "|" + r.Province
		if seen[k] {
			t.Fatalf("清单重复: %s", k)
		}
		seen[k] = true
		if r.Kind == "province" {
			provs[r.Name] = true
			if r.Display == "" {
				t.Fatalf("省级 %s 缺展示名", r.Name)
			}
		}
		if r.Kind == "city" && !provs[r.Province] {
			// 省条目在市条目前, 到这里父省应已登记; 顺序无关, 兜底用集合补查
			found := false
			for _, x := range chinaRegions {
				if x.Kind == "province" && x.Name == r.Province {
					found = true
				}
			}
			if !found {
				t.Fatalf("市 %s 的父省 %s 不在清单", r.Name, r.Province)
			}
		}
	}
	if len(provs) != 34 {
		t.Fatalf("省级应为 34 个, 实际 %d: %v", len(provs), provs)
	}
	// 抽查关键条目
	want := map[string]string{
		"province|江苏|": "江苏省", "province|上海|": "上海市",
		"city|南京|江苏": "南京市（江苏省）", "city|延边|吉林": "延边朝鲜族自治州（吉林省）",
		"city|广州|广东": "广州市（广东省）", "city|大理|云南": "大理白族自治州（云南省）",
	}
	for k, disp := range want {
		found := false
		for _, r := range chinaRegions {
			if r.Kind+"|"+r.Name+"|"+r.Province == k {
				found = true
				if r.Display != disp {
					t.Fatalf("%s 展示名 = %q, want %q", k, r.Display, disp)
				}
			}
		}
		if !found {
			t.Fatalf("清单缺条目 %s", k)
		}
	}
}

func TestRuleBanScope(t *testing.T) {
	dir := banTestSetup(t)
	oldEvents := eventsDir
	eventsDir = filepath.Join(dir, "events")
	os.MkdirAll(eventsDir, 0755)
	defer func() { eventsDir = oldEvents }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()

	ip := "203.0.113.60"
	ranges := [][2]int{{45167, 45167}, {3004, 3004}}
	b, fresh, err := applyRuleBan(ip, "防火墙测试", "portguard", 24, "gtest", ranges)
	if err != nil || !fresh || b == nil {
		t.Fatalf("applyRuleBan = %v, %v, %v", b, fresh, err)
	}
	if len(b.Scopes) != 1 || !isBannedFor(ip, 45167) || !isBannedFor(ip, 3004) {
		t.Fatalf("按规则封禁应只覆盖规则端口: %+v", b)
	}
	if isBannedFor(ip, 9999) {
		t.Fatal("按规则封禁不应覆盖规则外端口")
	}
	if isGloballyBanned(ip) {
		t.Fatal("按规则封禁不算全局封禁")
	}
	// 同一 IP 再命中另一规则: 追加 Scopes, 不新开记录
	b2, fresh2, err := applyRuleBan(ip, "防火墙测试2", "portguard", 24, "gtest2", [][2]int{{56806, 56806}})
	if err != nil || !fresh2 {
		t.Fatalf("追加规则封禁失败: %v, %v, %v", b2, fresh2, err)
	}
	if len(b2.Scopes) != 2 || !isBannedFor(ip, 56806) {
		t.Fatalf("追加后应为 2 条 Scopes: %+v", b2)
	}
	// 同规则再命中: 只刷新, 不重复事件(返回 fresh=false)
	_, fresh3, _ := applyRuleBan(ip, "防火墙测试3", "portguard", 24, "gtest", ranges)
	if fresh3 {
		t.Fatal("同规则再命中不应算新封")
	}
	// 全局封禁覆盖按规则: 转全局, Scopes 清掉
	banMu.Lock()
	upsertBanLocked(ip, "手动拉黑", "manual", 24)
	banMu.Unlock()
	if !isGloballyBanned(ip) || len(b2.Scopes) != 0 {
		t.Fatalf("全局封禁应取代按规则: %+v", b2)
	}
	// 解封: 记录保留、状态变 released
	if !releaseBan(ip) || isBanned(ip) {
		t.Fatal("解封后不应再封禁")
	}
	found := false
	for _, x := range allBans() {
		if x.IP == ip && x.Status == BanReleased {
			found = true
		}
	}
	if !found {
		t.Fatal("解封只改状态, 记录必须保留")
	}
	// 已全局封禁时按规则命中不重复封
	banMu.Lock()
	upsertBanLocked(ip, "手动拉黑", "manual", 24)
	banMu.Unlock()
	_, fresh4, _ := applyRuleBan(ip, "防火墙", "portguard", 24, "gtest", ranges)
	if fresh4 {
		t.Fatal("已全局封禁时按规则不应重复封禁")
	}
}

// TestLegacyPortsBanSemantics: 旧 Ports 记录(从 bans.json 读回的遗留数据)
// 的判定语义必须保持: 按端口只覆盖列出的端口, 不算全局。
func TestLegacyPortsBanSemantics(t *testing.T) {
	banTestSetup(t)
	ip := "203.0.113.61"
	banMu.Lock()
	bans = append(bans, &Ban{IP: ip, Ports: []int{45167}, Status: BanActive})
	banMu.Unlock()
	if !isBannedFor(ip, 45167) || isBannedFor(ip, 3004) || isGloballyBanned(ip) {
		t.Fatal("旧 Ports 记录语义不对")
	}
}

func TestPortGuardCheckEndToEnd(t *testing.T) {
	dir := banTestSetup(t)
	oldEvents := eventsDir
	eventsDir = filepath.Join(dir, "events")
	os.MkdirAll(eventsDir, 0755)
	defer func() { eventsDir = oldEvents }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()
	oldAlert := settings.AlertPortGuardBan
	settings.AlertPortGuardBan = false
	defer func() { settings.AlertPortGuardBan = oldAlert }()
	geoLoadV4Embedded()

	mkRule := func(id, proto, action string, src FWSource) *PortGuardRule {
		return &PortGuardRule{ID: id, PortText: "45167", Proto: proto, Source: src, Action: action, BanHours: 24, Enabled: true, ranges: [][2]int{{45167, 45167}}}
	}
	setRules := func(rs ...*PortGuardRule) {
		pgMu.Lock()
		pgRules = rs
		pgMu.Unlock()
	}
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	// 114.114.114.114 在内嵌库里是江苏南京: 规则只允许浙江 -> 应封禁(默认封禁)
	setRules(mkRule("gtest", "all", "allow", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "浙江"}}}))
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if !isBannedFor("114.114.114.114", 45167) {
		t.Fatal("江苏 IP 连只允许浙江的端口应被默认封禁")
	}
	if isBannedFor("114.114.114.114", 3004) || isGloballyBanned("114.114.114.114") {
		t.Fatal("按规则封禁不应扩散到其他端口或全局")
	}
	// 规则改成允许江苏 -> 同一 IP 不应再封(先解封再测)
	releaseBan("114.114.114.114")
	setRules(mkRule("gtest", "all", "allow", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}))
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if isBanned("114.114.114.114") {
		t.Fatal("白名单内 IP 不应被封禁")
	}
	// 市级规则: 只允许南京市 -> 南京 IP 放行
	setRules(mkRule("gtest", "all", "allow", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "city", Name: "南京", Province: "江苏"}}}))
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if isBanned("114.114.114.114") {
		t.Fatal("南京市白名单应放行南京 IP")
	}
	// 拒绝规则: 拒绝江苏 -> 南京 IP 被拒绝封禁, 原因含"防火墙拒绝"
	setRules(mkRule("gtest", "all", "deny", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}))
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if !isBannedFor("114.114.114.114", 45167) {
		t.Fatal("拒绝规则命中应封禁")
	}
	banMu.Lock()
	var reason string
	for _, b := range bans {
		if b.IP == "114.114.114.114" {
			reason = b.Reason
		}
	}
	banMu.Unlock()
	if !strings.Contains(reason, "防火墙拒绝") {
		t.Fatalf("拒绝原因应含'防火墙拒绝', 得到 %q", reason)
	}
	// 拒绝优先于允许: 允许江苏 + 拒绝全部 IP 同时命中 -> 仍封禁
	releaseBan("114.114.114.114")
	setRules(
		mkRule("gallow", "all", "allow", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}),
		mkRule("gdeny", "all", "deny", FWSource{Kind: "all"}),
	)
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if !isBannedFor("114.114.114.114", 45167) {
		t.Fatal("拒绝优先于允许: 同时命中时应封禁")
	}
	// 禁用规则不生效
	releaseBan("114.114.114.114")
	disabled := mkRule("gtest", "all", "deny", FWSource{Kind: "all"})
	disabled.Enabled = false
	setRules(disabled)
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if isBanned("114.114.114.114") {
		t.Fatal("禁用规则不应生效")
	}
	// 协议不匹配不生效: TCP 规则不拦 UDP 连接
	setRules(mkRule("gtest", "tcp", "deny", FWSource{Kind: "all"}))
	portGuardCheck("114.114.114.114", 45167, "udp")
	if isBanned("114.114.114.114") {
		t.Fatal("TCP 规则不应拦 UDP 连接")
	}
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if !isBannedFor("114.114.114.114", 45167) {
		t.Fatal("TCP 规则应拦 TCP 连接")
	}
}

// TestPortGuardCheckUnknownGeo: 归属地未知(v6 库未加载时的 v6 地址)走默认封禁,
// 原因必须记"归属地未知", 且不命中任何国家/省份类允许规则。
func TestPortGuardCheckUnknownGeo(t *testing.T) {
	dir := banTestSetup(t)
	oldEvents := eventsDir
	eventsDir = filepath.Join(dir, "events")
	os.MkdirAll(eventsDir, 0755)
	defer func() { eventsDir = oldEvents }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()
	oldAlert := settings.AlertPortGuardBan
	settings.AlertPortGuardBan = false
	defer func() { settings.AlertPortGuardBan = oldAlert }()
	// 强制 v6 库未加载, 使 v6 地址查不到归属地(真实"未知"路径, 非合成)
	geoMu.Lock()
	oldV6 := geoV6
	geoV6 = nil
	geoMu.Unlock()
	defer func() { geoMu.Lock(); geoV6 = oldV6; geoMu.Unlock() }()
	geoCacheMu.Lock()
	delete(geoCache, "2606:4700:4700::1111")
	geoCacheMu.Unlock()
	geoLoadV4Embedded()

	ip := "2606:4700:4700::1111"
	if g := geoLookup(ip); g.Country != "" {
		t.Fatalf("前置条件失败: %s 在无 v6 库时应查不到国家, 得到 %+v", ip, g)
	}
	pgMu.Lock()
	pgRules = []*PortGuardRule{{ID: "gtest", PortText: "45167", Proto: "all",
		Source:   FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}},
		Action:   "allow",
		BanHours: 24, Enabled: true, ranges: [][2]int{{45167, 45167}}}}
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()
	portGuardCheck(ip, 45167, "tcp")
	if !isBannedFor(ip, 45167) {
		t.Fatal("未知归属地连只允许江苏的端口应被默认封禁")
	}
	banMu.Lock()
	var reason string
	for _, b := range bans {
		if b.IP == ip {
			reason = b.Reason
		}
	}
	banMu.Unlock()
	if !strings.Contains(reason, "归属地未知") {
		t.Fatalf("未知归属地封禁原因必须记'归属地未知', 得到 %q", reason)
	}
	if isGloballyBanned(ip) {
		t.Fatal("未知归属地封禁也不应扩成全局")
	}
}
