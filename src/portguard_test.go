package main

// 端口防护(第 9 项)回归测试: 端口解析、归一化、白名单匹配、按端口封禁作用域。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePortList(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"45167", []int{45167}},
		{"45167,3004", []int{3004, 45167}},
		{"45167，3004", []int{3004, 45167}},  // 中文逗号
		{"45167/3004", []int{3004, 45167}},  // 斜杠
		{"45167\\3004", []int{3004, 45167}}, // 反斜杠
		{"45167、3004", []int{3004, 45167}},  // 顿号
		{"45167, 3004，56806 / 8005", []int{3004, 8005, 45167, 56806}},
		{"45167,45167,3004", []int{3004, 45167}}, // 去重
		{"45167,", []int{45167}},                 // 尾部分隔符容忍
	}
	for _, c := range cases {
		got, err := parsePortList(c.in)
		if err != nil {
			t.Fatalf("parsePortList(%q) unexpected error: %v", c.in, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("parsePortList(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("parsePortList(%q) = %v, want %v", c.in, got, c.want)
			}
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
	}
	for _, c := range bad {
		if _, err := parsePortList(c.in); err == nil || !strings.Contains(err.Error(), c.frag) {
			t.Fatalf("parsePortList(%q) err = %v, want containing %q", c.in, err, c.frag)
		}
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
	_, locs, _, err := parseGuardRuleInput("8080", []GuardLocation{{Kind: "province", Name: "江苏省"}}, 24)
	if err != nil {
		t.Fatal(err)
	}
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

func TestScopedBanScope(t *testing.T) {
	dir := banTestSetup(t)
	oldEvents := eventsDir
	eventsDir = filepath.Join(dir, "events")
	os.MkdirAll(eventsDir, 0755)
	defer func() { eventsDir = oldEvents }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()

	ip := "203.0.113.60"
	b, fresh, err := applyScopedBan(ip, "端口防护测试", "portguard", 24, []int{45167, 3004})
	if err != nil || !fresh || b == nil {
		t.Fatalf("applyScopedBan = %v, %v, %v", b, fresh, err)
	}
	if len(b.Ports) != 2 || !isBannedFor(ip, 45167) || !isBannedFor(ip, 3004) {
		t.Fatalf("按端口封禁应只覆盖规则端口: %+v", b)
	}
	if isBannedFor(ip, 9999) {
		t.Fatal("按端口封禁不应覆盖规则外端口")
	}
	if isGloballyBanned(ip) {
		t.Fatal("按端口封禁不算全局封禁")
	}
	// 同一 IP 再命中另一规则端口: 合并并集, 不新开记录
	b2, fresh2, err := applyScopedBan(ip, "端口防护测试2", "portguard", 24, []int{56806})
	if err != nil || !fresh2 {
		t.Fatalf("合并封禁失败: %v, %v, %v", b2, fresh2, err)
	}
	if len(b2.Ports) != 3 || !isBannedFor(ip, 56806) {
		t.Fatalf("合并后应为 3 个端口: %+v", b2)
	}
	// 全局封禁覆盖按端口: 转全局, 端口元素清掉
	banMu.Lock()
	upsertBanLocked(ip, "手动拉黑", "manual", 24)
	banMu.Unlock()
	if !isGloballyBanned(ip) || len(b2.Ports) != 0 {
		t.Fatalf("全局封禁应取代按端口: %+v", b2)
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
	// 已全局封禁时按端口命中不重复封
	banMu.Lock()
	upsertBanLocked(ip, "手动拉黑", "manual", 24)
	banMu.Unlock()
	_, fresh3, _ := applyScopedBan(ip, "端口防护", "portguard", 24, []int{45167})
	if fresh3 {
		t.Fatal("已全局封禁时按端口不应重复封禁")
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
	geoLoadV4Embedded()

	// 114.114.114.114 在内嵌库里是江苏南京: 规则只允许浙江 -> 应封禁
	pgMu.Lock()
	pgRules = []*PortGuardRule{{ID: "gtest", Ports: []int{45167}, Locations: []GuardLocation{{Kind: "province", Name: "浙江"}}, BanHours: 24, Enabled: true}}
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	portGuardCheck("114.114.114.114", 45167)
	if !isBannedFor("114.114.114.114", 45167) {
		t.Fatal("江苏 IP 连只允许浙江的端口应被按端口封禁")
	}
	if isBannedFor("114.114.114.114", 3004) || isGloballyBanned("114.114.114.114") {
		t.Fatal("按端口封禁不应扩散到其他端口或全局")
	}
	// 规则改成允许江苏 -> 同一 IP 不应再封(先解封再测)
	releaseBan("114.114.114.114")
	pgMu.Lock()
	pgRules[0].Locations = []GuardLocation{{Kind: "province", Name: "江苏"}}
	pgMu.Unlock()
	portGuardCheck("114.114.114.114", 45167)
	if isBanned("114.114.114.114") {
		t.Fatal("白名单内 IP 不应被封禁")
	}
	// 市级规则: 只允许南京市 -> 南京 IP 放行
	pgMu.Lock()
	pgRules[0].Locations = []GuardLocation{{Kind: "city", Name: "南京", Province: "江苏"}}
	pgMu.Unlock()
	portGuardCheck("114.114.114.114", 45167)
	if isBanned("114.114.114.114") {
		t.Fatal("南京市白名单应放行南京 IP")
	}
}
