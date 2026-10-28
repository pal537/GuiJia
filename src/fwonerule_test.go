package main

// 一个端口一条规则回归: 重叠判定、新建/编辑/启用拦截、旧数据迁移、
// 单规则语义(允许=除源外一律拒绝, 拒绝=除源外一律允许)、多 IP 自定义。

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustCIDRNets(t *testing.T, s string) []*net.IPNet {
	t.Helper()
	nets, err := parseCIDRNets(s)
	if err != nil {
		t.Fatalf("parseCIDRNets(%q) 失败: %v", s, err)
	}
	return nets
}

func TestFwRuleConflict(t *testing.T) {
	mk := func(id, portText, proto, action string) *PortGuardRule {
		r, err := parseFWRuleInput(portText, proto, FWSource{Kind: "all"}, action, 0)
		if err != nil {
			t.Fatal(err)
		}
		r.ID = id
		return r
	}
	seed := []*PortGuardRule{mk("a", "59188", "all", "allow"), mk("b", "9000", "tcp", "deny")}
	pgMu.Lock()
	old := pgRules
	pgRules = seed
	for _, r := range seed {
		r.Enabled = true
	}
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = old; pgMu.Unlock() }()

	cases := []struct {
		name string
		r    *PortGuardRule
		want string // ""=无冲突, 否则冲突规则 ID
	}{
		{"同端口同动作是并集不冲突", mk("x", "59188", "all", "allow"), ""},
		{"同端口反动作冲突", mk("x", "59188", "all", "deny"), "a"},
		{"全部协议与单协议反动作相交", mk("x", "59188", "tcp", "deny"), "a"},
		{"同端口不同协议不冲突", mk("x", "9000", "udp", "allow"), ""},
		{"全部协议与单协议反动作相交2", mk("x", "9000", "all", "allow"), "b"},
		{"同端口同协议同动作不冲突", mk("x", "9000", "tcp", "deny"), ""},
		{"范围相交反动作冲突", mk("x", "59180-59200", "all", "deny"), "a"},
		{"范围相交同动作不冲突", mk("x", "59180-59200", "all", "allow"), ""},
		{"范围不交", mk("x", "59200-59300", "all", "deny"), ""},
		{"多端口其一反动作相交", mk("x", "80,59188", "all", "deny"), "a"},
	}
	for _, c := range cases {
		if got := fwRuleConflict(c.r, ""); (got == nil) != (c.want == "") || (got != nil && got.ID != c.want) {
			id := ""
			if got != nil {
				id = got.ID
			}
			t.Errorf("%s: 冲突=%q, want %q", c.name, id, c.want)
		}
	}
	// 编辑跳过自身: 拿 a 改端口仍为 59188 不应撞自己
	if got := fwRuleConflict(seed[0], "a"); got != nil {
		t.Errorf("编辑跳过自身应无冲突, 得到 %q", got.ID)
	}
	// 只比生效规则: 停用 a 后, 反动作新建不应再撞它
	seed[0].Enabled = false
	if got := fwRuleConflict(mk("x", "59188", "all", "deny"), ""); got != nil {
		t.Errorf("停用规则不应算冲突, 得到 %q", got.ID)
	}
}

func TestFwSingleRuleAPI(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	pgMu.Lock()
	pgRules = nil
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	post := func(body string) (int, string) {
		req := httptest.NewRequest("POST", "/api/portguard", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handlePortGuard(rec, req)
		return rec.Code, rec.Body.String()
	}
	put := func(id, body string) (int, string) {
		req := httptest.NewRequest("PUT", "/api/portguard/"+id, bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handlePortGuardItem(rec, req)
		return rec.Code, rec.Body.String()
	}
	ruleID := func(portText string) string {
		pgMu.Lock()
		defer pgMu.Unlock()
		for _, r := range pgRules {
			if r.PortText == portText {
				return r.ID
			}
		}
		return ""
	}
	if code, _ := post(`{"portText":"59188","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"action":"allow"}`); code != 200 {
		t.Fatalf("首条规则应 200, 实际 %d", code)
	}
	// 同端口反动作(拒绝江苏)必须 400, 且报错要点名冲突规则
	if code, body := post(`{"portText":"59188","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"action":"deny"}`); code != 400 || !strings.Contains(body, "不许同时存在允许和拒绝") {
		t.Fatalf("同端口反动作应 400 且点名, 实际 %d %s", code, body)
	}
	// 同端口同动作不同来源是并集, 应 200
	if code, _ := post(`{"portText":"59188","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"浙江"}]},"action":"allow"}`); code != 200 {
		t.Fatalf("同动作并集应 200, 实际 %d", code)
	}
	// 完全相同规则仍 400(精确重复)
	if code, body := post(`{"portText":"59188","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"action":"allow"}`); code != 400 || !strings.Contains(body, "已存在相同规则") {
		t.Fatalf("精确重复应 400, 实际 %d %s", code, body)
	}
	// 另一端口建拒绝规则, 再编辑撞 59188 反动作 -> 400; 改同动作 -> 200
	if code, _ := post(`{"portText":"2200","proto":"all","source":{"kind":"all"},"action":"deny"}`); code != 200 {
		t.Fatalf("2200 规则应 200, 实际 %d", code)
	}
	id2200 := ruleID("2200")
	if code, _ := put(id2200, `{"portText":"59188","proto":"all","source":{"kind":"all"},"action":"deny"}`); code != 400 {
		t.Fatalf("编辑撞反动作应 400, 实际 %d", code)
	}
	if code, _ := put(id2200, `{"portText":"59188","proto":"all","source":{"kind":"all"},"action":"allow"}`); code != 200 {
		t.Fatalf("编辑改同动作并集应 200, 实际 %d", code)
	}
	// 启用关: 59188 现有三条允许(江苏/浙江/全部 IP, 最后一条是 2200 改过来的);
	// 停用全部允许后建拒绝应 200, 再启用任一停用的允许应 400。
	pgMu.Lock()
	ids := []string{}
	for _, r := range pgRules {
		if r.PortText == "59188" {
			ids = append(ids, r.ID)
		}
	}
	pgMu.Unlock()
	for _, id := range ids {
		if code, _ := put(id, `{"enabled":false}`); code != 200 {
			t.Fatalf("停用应 200, 实际 %d", code)
		}
	}
	if code, _ := post(`{"portText":"59188","proto":"all","source":{"kind":"all"},"action":"deny"}`); code != 200 {
		t.Fatalf("允许全停用后建拒绝应 200, 实际 %d", code)
	}
	if code, body := put(ids[0], `{"enabled":true}`); code != 400 || !strings.Contains(body, "不许同时存在允许和拒绝") {
		t.Fatalf("启用撞已生效反动作应 400, 实际 %d %s", code, body)
	}
}

func TestFwOverlapMigration(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	oldRules := pgRules
	defer func() { pgMu.Lock(); pgRules = oldRules; pgMu.Unlock() }()

	rulesJSON := `[
		{"id":"allow59188","portText":"59188","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"action":"allow","enabled":true},
		{"id":"deny59188","portText":"59188","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"action":"deny","enabled":true},
		{"id":"deny2200","portText":"2200","proto":"all","source":{"kind":"custom_ip","cidr":"1.2.3.4"},"action":"deny","enabled":true},
		{"id":"allow3300","portText":"3300","proto":"tcp","source":{"kind":"all"},"action":"allow","enabled":true},
		{"id":"allow4400a","portText":"4400","proto":"all","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"action":"allow","enabled":true},
		{"id":"allow4400b","portText":"4400","proto":"all","source":{"kind":"custom_foreign","countries":["US"]},"action":"allow","enabled":true}
	]`
	if err := os.WriteFile(filepath.Join(dir, "portguard.json"), []byte(rulesJSON), 0644); err != nil {
		t.Fatal(err)
	}
	bansJSON := `[
		{"ip":"5.6.7.8","until":0,"reason":"防火墙拒绝：端口 59188 · 全部协议 · 自定义位置（中国）：江苏，来源江苏","source":"portguard","createdAt":1700000000,"status":"active","scopes":[{"ruleId":"deny59188","ranges":[[59188,59188]]}]},
		{"ip":"9.9.9.9","until":0,"reason":"防火墙默认封禁：未命中允许规则（规则：端口 59188 · 全部协议 · 自定义位置（中国）：江苏），来源浙江","source":"portguard","createdAt":1700000000,"status":"active","scopes":[{"ruleId":"allow59188","ranges":[[59188,59188]]}]},
		{"ip":"2.3.4.5","until":0,"reason":"防火墙拒绝：端口 2200 · 全部协议 · 1.2.3.4，来源某地","source":"portguard","createdAt":1700000000,"status":"active","scopes":[{"ruleId":"deny2200","ranges":[[2200,2200]]}]},
		{"ip":"3.4.5.6","until":0,"reason":"防火墙默认封禁：未命中允许规则（规则：端口 2200 · 全部协议 · 1.2.3.4），来源某地","source":"portguard","createdAt":1700000000,"status":"active","scopes":[{"ruleId":"deny2200","ranges":[[2200,2200]]}]}
	]`
	if err := os.WriteFile(filepath.Join(dir, "bans.json"), []byte(bansJSON), 0644); err != nil {
		t.Fatal(err)
	}
	loadBans()
	loadPortGuard()

	pgMu.Lock()
	byID := map[string]*PortGuardRule{}
	for _, r := range pgRules {
		byID[r.ID] = r
	}
	pgMu.Unlock()
	if byID["deny59188"].Enabled {
		t.Fatal("重叠对中后建的拒绝规则应被改禁用")
	}
	if !byID["allow59188"].Enabled || !byID["deny2200"].Enabled || !byID["allow3300"].Enabled {
		t.Fatal("保留规则与无关规则不应被动")
	}
	// 同动作并集对原样保留: 两条允许同端口都不动
	if !byID["allow4400a"].Enabled || !byID["allow4400b"].Enabled {
		t.Fatal("同动作并集对不应被迁移动")
	}
	banMu.Lock()
	byIP := map[string]*Ban{}
	for _, b := range bans {
		byIP[b.IP] = b
	}
	banMu.Unlock()
	// 拒绝规则产生的封禁随规则停用释放; 允许端口默认封禁保留;
	// 拒绝命中保留; 拒绝端口旧默认封禁释放(新语义下未命中一律放行)。
	if byIP["5.6.7.8"].Status != BanReleased {
		t.Fatalf("停用规则的封禁应释放, 得到 %q", byIP["5.6.7.8"].Status)
	}
	if byIP["9.9.9.9"].Status != BanActive {
		t.Fatalf("允许端口默认封禁应保留, 得到 %q", byIP["9.9.9.9"].Status)
	}
	if byIP["2.3.4.5"].Status != BanActive {
		t.Fatalf("拒绝命中封禁应保留, 得到 %q", byIP["2.3.4.5"].Status)
	}
	if byIP["3.4.5.6"].Status != BanReleased {
		t.Fatalf("拒绝端口旧默认封禁应释放, 得到 %q", byIP["3.4.5.6"].Status)
	}
	// 落盘: 拒绝规则已写回禁用态
	b, _ := os.ReadFile(filepath.Join(dir, "portguard.json"))
	var items []map[string]any
	if err := json.Unmarshal(b, &items); err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it["id"] == "deny59188" && it["enabled"] != false {
			t.Fatal("落盘里拒绝规则应为禁用态")
		}
	}
}

func TestFwMultiIPMatch(t *testing.T) {
	nets, err := parseCIDRNets("8.8.8.8, 1.2.3.0/24, 8.8.8.8")
	if err != nil || len(nets) != 2 {
		t.Fatalf("多 IP 解析应去重为 2 条, 得到 %v %v", len(nets), err)
	}
	src := FWSource{Kind: "custom_ip", CIDR: "8.8.8.8, 1.2.3.0/24", cidrNets: nets}
	for ip, want := range map[string]bool{"8.8.8.8": true, "1.2.3.99": true, "1.2.4.1": false, "8.8.4.4": false} {
		if got := fwSourceMatch(src, net.ParseIP(ip), GeoInfo{}); got != want {
			t.Errorf("多 IP %s 命中=%v, want %v", ip, got, want)
		}
	}
	if _, err := parseCIDRNets("8.8.8.8, 999.1.1.1"); err == nil {
		t.Fatal("多 IP 中有非法应整体失败")
	}
}

// TestFwSingleRuleUI: 防火墙卡片与对话框文案必须讲新语义, 旧语义残留即失败。
func TestFwSingleRuleUI(t *testing.T) {
	html := unifyHTML(t)
	for _, s := range []string{
		"一个端口（同一协议）只能有一种动作",
		"不许同时存在允许和拒绝",
		"同动作多条规则按来源并集算",
		"允许规则只放行来源命中的，其余一律拒绝",
		"拒绝规则只拒绝来源命中的，其余一律放行",
		"没有规则的端口防火墙不管",
		"多个逗号分隔",
	} {
		if !strings.Contains(html, s) {
			t.Errorf("下发 HTML 缺 %q", s)
		}
	}
	for _, s := range []string{
		"多条命中时拒绝优先",
		"删除规则不自动解封",
		"无规则命中时按受防护端口默认封禁",
		"拒绝命中与默认封禁一律永久封禁",
		"只能有一条规则",
		"想换规则请先删除旧规则",
	} {
		if strings.Contains(html, s) {
			t.Errorf("下发 HTML 不应再有旧语义 %q", s)
		}
	}
}

// TestFwUnionMatch: 同动作多规则按来源并集判定(允许: 任一命中放行;
// 拒绝: 任一命中拒绝)。114.114.114.114=江苏南京, 8.8.8.8=美国, 203.0.113.99=澳大利亚。
func TestFwUnionMatch(t *testing.T) {
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

	mkRule := func(id, action string, src FWSource) *PortGuardRule {
		return &PortGuardRule{ID: id, PortText: "45167", Proto: "all", Source: src, Action: action, Enabled: true, ranges: [][2]int{{45167, 45167}}}
	}
	setRules := func(rs ...*PortGuardRule) {
		pgMu.Lock()
		pgRules = rs
		pgMu.Unlock()
	}
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	// 允许并集: 江苏 + 美国, 江苏 IP 放行, 美国 IP 放行, 澳大利亚 IP 被拒绝
	setRules(
		mkRule("u1", "allow", FWSource{Kind: "custom_cn", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}),
		mkRule("u2", "allow", FWSource{Kind: "custom_foreign", Countries: []string{"US"}}),
	)
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if isBanned("114.114.114.114") {
		t.Fatal("并集允许: 江苏 IP 应放行")
	}
	portGuardCheck("8.8.8.8", 45167, "tcp")
	if isBanned("8.8.8.8") {
		t.Fatal("并集允许: 美国 IP 应放行")
	}
	portGuardCheck("203.0.113.99", 45167, "tcp")
	if !isBannedFor("203.0.113.99", 45167) {
		t.Fatal("并集允许: 澳大利亚 IP 应被拒绝")
	}
	// 拒绝并集: 拒绝江苏 + 拒绝美国, 两者都封, 澳大利亚放行
	releaseBan("203.0.113.99")
	setRules(
		mkRule("d1", "deny", FWSource{Kind: "custom_cn", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}),
		mkRule("d2", "deny", FWSource{Kind: "custom_foreign", Countries: []string{"US"}}),
	)
	portGuardCheck("114.114.114.114", 45167, "tcp")
	if !isBannedFor("114.114.114.114", 45167) {
		t.Fatal("并集拒绝: 江苏 IP 应被拒绝")
	}
	portGuardCheck("8.8.8.8", 45167, "tcp")
	if !isBannedFor("8.8.8.8", 45167) {
		t.Fatal("并集拒绝: 美国 IP 应被拒绝")
	}
	portGuardCheck("203.0.113.99", 45167, "tcp")
	if isBanned("203.0.113.99") {
		t.Fatal("并集拒绝: 澳大利亚 IP 应放行")
	}
}
