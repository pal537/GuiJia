package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// 国旗映射: 中文名、英文名、ISO 代码 -> 国旗; 命中不了无旗不猜。
func TestFlagEmoji(t *testing.T) {
	cases := []struct{ in, want string }{
		{"中国", "🇨🇳"}, {"美国", "🇺🇸"}, {"日本", "🇯🇵"}, {"香港", "🇭🇰"},
		{"台湾", "🇹🇼"}, {"澳门", "🇲🇴"}, {"新加坡", "🇸🇬"}, {"德国", "🇩🇪"},
		{"China", "🇨🇳"}, {"United States", "🇺🇸"}, {"USA", "🇺🇸"},
		{"CN", "🇨🇳"}, {"us", "🇺🇸"},
		{"", ""}, {"未知", ""}, {"内网", ""}, {"火星", ""},
	}
	for _, c := range cases {
		if got := flagEmojiForCountry(c.in); got != c.want {
			t.Errorf("flagEmojiForCountry(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// 架构展示名: amd64 -> x86_64(其余原样, 与运行环境无关的分支只测映射关系)。
func TestArchDisplayKnown(t *testing.T) {
	if got := archDisplay(); got == "" {
		t.Fatal("archDisplay 不应为空")
	}
}

// 配对码重新生成即作废旧码。
func TestPairingCodeRegenInvalidates(t *testing.T) {
	defer setupHubTest(t)()
	code1, _ := newPairingCode()
	code2, _ := newPairingCode()
	if code1 == code2 {
		t.Fatal("两次生成的码不应相同")
	}
	if consumePairingCode(code1) {
		t.Fatal("旧码应在重新生成后作废")
	}
	if !consumePairingCode(code2) {
		t.Fatal("新码应可用")
	}
}

// ping 同步名称与系统信息(改名后随下次 ping 同步到首页与顶部标识)。
func TestPingSyncsNameAndSysInfo(t *testing.T) {
	defer setupHubTest(t)()
	fp := strings.Repeat("a", 64)
	hubServers = []*hubServer{{
		Fingerprint: fp, Name: "旧名字", TokenHash: hashToken("tok123"),
		Status: "online",
	}}
	req := httptest.NewRequest("POST", "/api/nodes/ping", strings.NewReader(
		`{"version":"v9","tgMode":"hub","name":"RN圣何塞","ip":"1.2.3.4","os":"Debian 13","arch":"x86_64"}`))
	// 第 7 项后 IP 以 hub 观测为准: 拨入地址即节点 IP, 测试须显式给出拨入地址
	// (httptest 默认 RemoteAddr 192.0.2.1 会被当成拨入公网而优先采纳)。
	req.RemoteAddr = "1.2.3.4:54321"
	req.Header.Set("X-Node-Fingerprint", fp)
	req.Header.Set("X-Node-Token", "tok123")
	rec := httptest.NewRecorder()
	handleNodePing(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ping 应 200, 得到 %d body=%s", rec.Code, rec.Body.String())
	}
	s := hubServers[0]
	if s.Name != "RN圣何塞" || s.IP != "1.2.3.4" || s.OS != "Debian 13" || s.Arch != "x86_64" || s.Version != "v9" {
		t.Fatalf("ping 未同步名称/系统信息: %+v", s)
	}
}

// hello 已登记路径同样同步名称与系统信息。
func TestHelloApprovedSyncsNameAndSysInfo(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pub := hubTestKey(t)
	hubServers = []*hubServer{{Fingerprint: fp, Name: "旧名字"}}
	req := httptest.NewRequest("POST", "/api/nodes/hello", strings.NewReader(
		`{"fingerprint":"`+fp+`","pubKey":"`+pub+`","name":"新名字","version":"v9","ip":"5.6.7.8","os":"Debian 12","arch":"arm64"}`))
	// 第 7 项后 IP 以 hub 观测为准, 见 ping 测试同名注释。
	req.RemoteAddr = "5.6.7.8:1234"
	rec := httptest.NewRecorder()
	handleNodeHello(rec, req)
	if rec.Code != 200 {
		t.Fatalf("hello 应 200, 得到 %d body=%s", rec.Code, rec.Body.String())
	}
	s := hubServers[0]
	if s.Name != "新名字" || s.IP != "5.6.7.8" || s.OS != "Debian 12" || s.Arch != "arm64" {
		t.Fatalf("hello 未同步名称/系统信息: %+v", s)
	}
}

// 归属地设置: 节点写注册表并持久化, local 写本机设置。
func TestNodeLocation(t *testing.T) {
	defer setupHubTest(t)()
	oldSettingFile := settingFile
	settingFile = filepath.Join(t.TempDir(), "settings.json")
	defer func() { settingFile = oldSettingFile }()
	fp := strings.Repeat("b", 64)
	hubServers = []*hubServer{{Fingerprint: fp, Name: "节点"}}
	req := httptest.NewRequest("POST", "/api/nodes/location", strings.NewReader(
		`{"fingerprint":"`+fp+`","location":"日本"}`))
	rec := httptest.NewRecorder()
	handleNodeLocation(rec, req)
	if rec.Code != 200 || hubServers[0].Location != "日本" {
		t.Fatalf("节点归属地应写入注册表: code=%d loc=%q", rec.Code, hubServers[0].Location)
	}
	req = httptest.NewRequest("POST", "/api/nodes/location", strings.NewReader(
		`{"fingerprint":"local","location":"香港"}`))
	rec = httptest.NewRecorder()
	handleNodeLocation(rec, req)
	if rec.Code != 200 || settings.ManualLocation != "香港" {
		t.Fatalf("本机归属地应写入设置: code=%d loc=%q", rec.Code, settings.ManualLocation)
	}
	// 手动值优先于自动解析并据此匹配国旗。
	pub := hubServerPublic(hubServers[0])
	if pub["location"] != "日本" || pub["flag"] != "🇯🇵" {
		t.Fatalf("手动归属地应优先并匹配国旗: %+v", pub)
	}
	req = httptest.NewRequest("POST", "/api/nodes/location", strings.NewReader(
		`{"fingerprint":"`+fp+`","location":""}`))
	rec = httptest.NewRecorder()
	handleNodeLocation(rec, req)
	if rec.Code != 200 || hubServers[0].Location != "" {
		t.Fatalf("空归属地应清除手动值: code=%d loc=%q", rec.Code, hubServers[0].Location)
	}
}

// 本机信息接口: 名称/IP/系统/归属地/国旗齐全。
func TestLocalInfo(t *testing.T) {
	defer setupHubTest(t)()
	req := httptest.NewRequest("GET", "/api/local-info", nil)
	rec := httptest.NewRecorder()
	handleLocalInfo(rec, req)
	if rec.Code != 200 {
		t.Fatalf("local-info 应 200, 得到 %d", rec.Code)
	}
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"name", "ip", "os", "arch", "location", "country", "flag", "manualLocation"} {
		if _, ok := v[k]; !ok {
			t.Errorf("local-info 缺字段 %s", k)
		}
	}
	if v["os"] == "" || v["arch"] == "" || v["location"] == "" {
		t.Fatalf("local-info 系统/归属地不应为空: %+v", v)
	}
}

// 移除管理即吊销: 删登记后节点 ping 应 401, 走 revoked 回退链路。
func TestRemoveRevokesNode(t *testing.T) {
	defer setupHubTest(t)()
	fp := strings.Repeat("c", 64)
	hubServers = []*hubServer{{Fingerprint: fp, Name: "节点", TokenHash: hashToken("tok123")}}
	req := httptest.NewRequest("POST", "/api/nodes/remove", strings.NewReader(
		`{"fingerprint":"`+fp+`"}`))
	rec := httptest.NewRecorder()
	handleNodeRemove(rec, req)
	if rec.Code != 200 || len(hubServers) != 0 {
		t.Fatalf("移除应删登记: code=%d left=%d", rec.Code, len(hubServers))
	}
	req = httptest.NewRequest("POST", "/api/nodes/ping", strings.NewReader(`{}`))
	req.Header.Set("X-Node-Fingerprint", fp)
	req.Header.Set("X-Node-Token", "tok123")
	rec = httptest.NewRecorder()
	handleNodePing(rec, req)
	if rec.Code != 401 {
		t.Fatalf("移除后 ping 应 401, 得到 %d", rec.Code)
	}
}

// 节点 TG 单选即选择, 不再二次确认: 选独立即启用并要求凭据,
// 切回走主服务器即停用, 已存 token/chat 保留备用。
func TestNodeTGModeSingleChoice(t *testing.T) {
	defer setupNodeTest(t)()
	oldQueue := tgHubQueueFile
	tgHubQueueFile = filepath.Join(t.TempDir(), "tg-hub-queue.json")
	defer func() { tgHubQueueFile = oldQueue }()
	settings.RunMode = "managed"
	loadNodeIdentity()
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/tg/mode", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handleNodeTGMode(rec, req)
		return rec
	}
	// 无凭据时选独立应 400。
	if rec := post(`{"mode":"independent","token":"","chatId":""}`); rec.Code != 400 {
		t.Fatalf("无凭据选独立应 400, 得到 %d", rec.Code)
	}
	// 选独立 + 凭据: 启用, 模式 independent。
	if rec := post(`{"mode":"independent","token":"123:abc","chatId":"12345"}`); rec.Code != 200 {
		t.Fatalf("选独立应 200, 得到 %d body=%s", rec.Code, rec.Body.String())
	}
	en, tok, chat := nodeTGConfig()
	if !en || tok != "123:abc" || chat != "12345" || settings.NodeTGMode != "independent" {
		t.Fatalf("独立模式应启用并保存凭据: en=%v tok=%q chat=%q mode=%q", en, tok, chat, settings.NodeTGMode)
	}
	// 切回走主服务器(即使请求里带 enabled:true 也以模式为准): 停用, 凭据保留。
	if rec := post(`{"mode":"hub","enabled":true}`); rec.Code != 200 {
		t.Fatalf("切回走主服务器应 200, 得到 %d", rec.Code)
	}
	en, tok, chat = nodeTGConfig()
	if en || tok != "123:abc" || chat != "12345" || settings.NodeTGMode != "hub" {
		t.Fatalf("切回后应停用且凭据保留: en=%v tok=%q chat=%q mode=%q", en, tok, chat, settings.NodeTGMode)
	}
}
