package main

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// 注意: 本文件不用全角方括号字面量, 一律用 \u 转义拼标题(字面量会被工具层剥离)。
const tgTestTitle = "\u3010甲骨文服务器\u3011\n"

// mockTGAPI: 拦截 tgAPI 调用并记录, 恢复由 Cleanup 保证。token/chatID 绝不进测试。
func mockTGAPI(t *testing.T) *[]map[string]any {
	t.Helper()
	old := tgAPI
	var calls []map[string]any
	tgAPI = func(method string, payload any, timeout time.Duration) (map[string]any, error) {
		calls = append(calls, map[string]any{"method": method, "payload": payload})
		return map[string]any{"ok": true}, nil
	}
	t.Cleanup(func() { tgAPI = old })
	return &calls
}

func tgPayloadText(call map[string]any) string {
	p, _ := call["payload"].(map[string]any)
	s, _ := p["text"].(string)
	return s
}

func tgPayloadKB(call map[string]any) []map[string]string {
	p, _ := call["payload"].(map[string]any)
	rm, _ := p["reply_markup"].(map[string]any)
	kb, _ := rm["inline_keyboard"].([][]map[string]string)
	var out []map[string]string
	for _, row := range kb {
		out = append(out, row...)
	}
	return out
}

func TestTGTitlePrefix(t *testing.T) {
	freshInstallSetup(t)
	oldHost := tgHostname
	t.Cleanup(func() { tgHostname = oldHost })

	settings.ServerName = "甲骨文服务器"
	if p := tgTitlePrefix(); p != tgTestTitle {
		t.Errorf("有名时标题不对, 得到 %q", p)
	}
	if got := tgWithTitle("报警内容"); got != tgTestTitle+"报警内容" {
		t.Errorf("标题拼接不对, 得到 %q", got)
	}
	if got := tgWithTitle(tgTestTitle + "报警内容"); got != tgTestTitle+"报警内容" {
		t.Errorf("已带标题不应重复加, 得到 %q", got)
	}

	// 无名回落 hostname。
	settings.ServerName = ""
	tgHostname = func() (string, error) { return "myhost", nil }
	if p := tgTitlePrefix(); p != "\u3010myhost\u3011\n" {
		t.Errorf("无名时应回落 hostname, 得到 %q", p)
	}
	// hostname 也取不到时不加标题, 绝不发空标题。
	tgHostname = func() (string, error) { return "", errors.New("no host") }
	if p := tgTitlePrefix(); p != "" {
		t.Errorf("无名无 hostname 时标题应为空, 得到 %q", p)
	}
	if got := tgWithTitle("报警内容"); got != "报警内容" {
		t.Errorf("无标题时原文应原样发出, 得到 %q", got)
	}
}

func TestTGRegisterCommands(t *testing.T) {
	freshInstallSetup(t)
	calls := mockTGAPI(t)
	settings.TGEnabled = true
	settings.TGBotToken = "x"
	settings.TGChatID = "12345"
	tgRegisterCommands()
	if len(*calls) != 1 {
		t.Fatalf("应恰好调一次 setMyCommands, 得到 %d 次", len(*calls))
	}
	call := (*calls)[0]
	if call["method"] != "setMyCommands" {
		t.Fatalf("方法应为 setMyCommands, 得到 %v", call["method"])
	}
	p, _ := call["payload"].(map[string]any)
	cmds, _ := p["commands"].([]map[string]string)
	want := map[string]string{"rescue": "急救菜单", "trust": "解封并信任一个 IP", "start": "查看帮助"}
	if len(cmds) != len(want) {
		t.Fatalf("命令表应恰好 3 条(rescue/trust/start), 得到 %v", cmds)
	}
	for _, c := range cmds {
		if want[c["command"]] != c["description"] {
			t.Errorf("命令 %q 说明不对, 得到 %q", c["command"], c["description"])
		}
	}

	// 未配置 TG 时不调用; API 失败时不 panic。
	*calls = (*calls)[:0]
	settings.TGEnabled = false
	tgRegisterCommands()
	if len(*calls) != 0 {
		t.Errorf("未配置 TG 时不应调用, 得到 %d 次", len(*calls))
	}
	settings.TGEnabled = true
	old := tgAPI
	tgAPI = func(method string, payload any, timeout time.Duration) (map[string]any, error) {
		return nil, errors.New("net fail")
	}
	defer func() { tgAPI = old }()
	tgRegisterCommands() // 只记日志, 不应 panic
}

func TestTGCallbackFingerprint(t *testing.T) {
	freshInstallSetup(t)
	settings.ServerID = "a1b2c3d4"
	if got := tgCB("ban:1.2.3.4"); got != "ban:1.2.3.4:a1b2c3d4" {
		t.Errorf("指纹附加不对, 得到 %q", got)
	}
	if stripped, ok := tgCheckCallback("ban:1.2.3.4:a1b2c3d4"); !ok || stripped != "ban:1.2.3.4" {
		t.Errorf("本机指纹应通过并剥离, 得到 %q,%v", stripped, ok)
	}
	if _, ok := tgCheckCallback("ban:1.2.3.4:deadbeef"); ok {
		t.Error("他机指纹应拒绝")
	}
	if _, ok := tgCheckCallback("ban:1.2.3.4"); ok {
		t.Error("缺失指纹应拒绝(旧按钮 fail closed)")
	}
	// IPv6 含冒号: 剥离只认末尾指纹, IP 原样恢复。
	orig := "bd:2001:db8::1:24"
	if stripped, ok := tgCheckCallback(tgCB(orig)); !ok || stripped != orig {
		t.Errorf("IPv6 回调往返不对, 得到 %q,%v", stripped, ok)
	}
	// 指纹空时放行(生产里 loadAll 已生成, 正常走不到)。
	settings.ServerID = ""
	if stripped, ok := tgCheckCallback("ban:1.2.3.4"); !ok || stripped != "ban:1.2.3.4" {
		t.Errorf("指纹空时应原样放行, 得到 %q,%v", stripped, ok)
	}
}

func TestTGTrustConfirmFlow(t *testing.T) {
	freshInstallSetup(t)
	calls := mockTGAPI(t)
	settings.TGEnabled = true
	settings.TGBotToken = "x"
	settings.TGChatID = "12345"
	settings.ServerID = "a1b2c3d4"
	settings.ServerName = "甲骨文服务器"

	// /trust 先回确认消息, 不立即执行。
	handleTGMessage(map[string]any{
		"chat":       map[string]any{"id": float64(12345)},
		"text":       "/trust 203.0.113.99",
		"message_id": float64(1),
	})
	if len(*calls) != 1 {
		t.Fatalf("/trust 应只发一条确认消息, 得到 %d 次调用", len(*calls))
	}
	confirm := (*calls)[0]
	if confirm["method"] != "sendMessage" {
		t.Fatalf("确认应用 sendMessage 发出, 得到 %v", confirm["method"])
	}
	if txt := tgPayloadText(confirm); !strings.Contains(txt, tgTestTitle) || !strings.Contains(txt, "确认信任 IP 203.0.113.99") {
		t.Errorf("确认消息应带标题与 IP, 得到 %q", txt)
	}
	kb := tgPayloadKB(confirm)
	var cbOK, cbCancel bool
	for _, b := range kb {
		if b["callback_data"] == "tc:203.0.113.99:a1b2c3d4" {
			cbOK = true
		}
		if b["callback_data"] == "bc:a1b2c3d4" {
			cbCancel = true
		}
	}
	if !cbOK || !cbCancel {
		t.Errorf("确认按钮应带指纹(tc/bc), 得到 %v", kb)
	}
	for _, ip := range settings.TrustedIPs {
		if ip == "203.0.113.99" {
			t.Fatal("确认前绝不能已信任该 IP")
		}
	}

	// 点确认才执行。
	*calls = (*calls)[:0]
	handleCallback(map[string]any{
		"data": "tc:203.0.113.99:a1b2c3d4",
		"id":   "cb1",
		"message": map[string]any{
			"chat":       map[string]any{"id": float64(12345)},
			"message_id": float64(9),
			"text":       "确认信任 IP 203.0.113.99 吗？",
		},
	})
	found := false
	for _, ip := range settings.TrustedIPs {
		if ip == "203.0.113.99" {
			found = true
		}
	}
	if !found {
		t.Error("点确认后应已信任该 IP")
	}
	var edited, answered bool
	for _, c := range *calls {
		if c["method"] == "editMessageText" {
			edited = true
		}
		if c["method"] == "answerCallbackQuery" {
			if p, _ := c["payload"].(map[string]any); p["text"] == "已信任" {
				answered = true
			}
		}
	}
	if !edited || !answered {
		t.Errorf("确认后应编辑原消息并应答已信任, 调用=%v", *calls)
	}

	// 他机指纹的确认按钮: 只提示, 绝不执行。
	*calls = (*calls)[:0]
	handleCallback(map[string]any{
		"data": "tc:198.51.100.77:deadbeef",
		"id":   "cb2",
		"message": map[string]any{
			"chat":       map[string]any{"id": float64(12345)},
			"message_id": float64(10),
			"text":       "确认信任 IP 198.51.100.77 吗？",
		},
	})
	for _, ip := range settings.TrustedIPs {
		if ip == "198.51.100.77" {
			t.Fatal("他机指纹回调绝不能执行信任")
		}
	}
	var warned, editedForeign bool
	for _, c := range *calls {
		if c["method"] == "answerCallbackQuery" {
			if p, _ := c["payload"].(map[string]any); p["text"] == "该操作属于另一台服务器，本服务器不会执行" {
				warned = true
			}
		}
		if c["method"] == "editMessageText" {
			editedForeign = true
		}
	}
	if !warned || editedForeign {
		t.Errorf("他机回调应只回提示、不改消息, 调用=%v", *calls)
	}
}

func TestNormalizeServerName(t *testing.T) {
	if got := normalizeServerName("  甲骨文服务器  "); got != "甲骨文服务器" {
		t.Errorf("应去首尾空格, 得到 %q", got)
	}
	long := strings.Repeat("甲", 40)
	if got := normalizeServerName(long); len([]rune(got)) != 32 {
		t.Errorf("超长应按 rune 截断到 32, 得到 %d 字", len([]rune(got)))
	}
	if got := normalizeServerName(""); got != "" {
		t.Errorf("空应保持空, 得到 %q", got)
	}
}

func TestServerIDGeneratedOnLoad(t *testing.T) {
	dir := freshInstallSetup(t)
	loadAll()
	if ok, _ := regexp.MatchString(`^[0-9a-f]{8}$`, settings.ServerID); !ok {
		t.Fatalf("首次启动应生成 8 位 hex 指纹, 得到 %q", settings.ServerID)
	}
	first := settings.ServerID
	// 写回文件且再次加载保持不变(改名不变, 重启不变)。
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil || !strings.Contains(string(b), first) {
		t.Fatalf("指纹应写回 settings.json, err=%v", err)
	}
	loadAll()
	if settings.ServerID != first {
		t.Errorf("重启后指纹应不变, 得到 %q(原 %q)", settings.ServerID, first)
	}
}

func TestSettingsPUTKeepsServerID(t *testing.T) {
	freshInstallSetup(t)
	settings.ServerID = "a1b2c3d4"
	long := strings.Repeat("乙", 40)
	body := `{"serverName":"  ` + long + `  ","serverId":""}`
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("PUT 应 200, 得到 %d(%s)", rec.Code, rec.Body.String())
	}
	if len([]rune(settings.ServerName)) != 32 {
		t.Errorf("PUT 保存时服务器名应截断到 32 字, 得到 %q", settings.ServerName)
	}
	if settings.ServerID != "a1b2c3d4" {
		t.Errorf("PUT 永不改动服务器指纹, 得到 %q", settings.ServerID)
	}
}

// TestBuildEventTextBanBtn: 拉黑/解封按钮只给仍会推送的事件类型;
// new_conn 的 banBtn 是死分支(推送已删, emit 只传 false, 代发已丢弃),
// 删掉后 new_conn 必须不再带拉黑按钮, 登录类与防火墙封禁的按钮不受影响。
func TestBuildEventTextBanBtn(t *testing.T) {
	cases := []struct {
		typ       string
		ip        string
		wantBan   bool
		wantUnban bool
	}{
		{"ssh_login", "1.2.3.4", true, false},
		{"ui_login", "1.2.3.4", true, false},
		{"ssh_login", "", false, false},
		{"new_conn", "1.2.3.4", false, false},
		{"port_flood", "1.2.3.4", false, false},
		{"portguard_ban", "1.2.3.4", false, true},
		{"autoban", "1.2.3.4", false, false},
	}
	for _, c := range cases {
		_, ban, unban := buildEventText(Event{Type: c.typ, IP: c.ip, Ts: 1700000000000, Detail: "x"})
		if ban != c.wantBan || unban != c.wantUnban {
			t.Errorf("type=%s ip=%s: ban=%v unban=%v, want ban=%v unban=%v",
				c.typ, c.ip, ban, unban, c.wantBan, c.wantUnban)
		}
	}
}
