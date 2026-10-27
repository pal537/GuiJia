package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupTGMultiTest: TG 双模式测试基座(节点身份 + 上报队列 + mock 恢复)。
func setupTGMultiTest(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	oldSettings, oldNodeIdent, oldNodeFile := settings, nodeIdent, nodeFile
	oldQueueFile, oldQueue, oldLoaded := tgHubQueueFile, hubEvQueue, hubEvLoaded
	oldAPICall := tgAPICall
	oldTestLast := tgTestLast
	hubEvRunMu.Lock()
	oldRunning := hubEvRunning
	hubEvRunning = true // 压住发送循环不启动, 队列操作纯本地可测
	hubEvRunMu.Unlock()
	settings = defaultSettings()
	settings.RunMode = "managed"
	settings.ServerName = "测试节点"
	settings.ServerID = "testnode1"
	nodeIdent = nil
	nodeFile = filepath.Join(dir, "node.json")
	tgHubQueueFile = filepath.Join(dir, "tg-hub-queue.json")
	hubEvMu.Lock()
	hubEvQueue = nil
	hubEvLoaded = false
	hubEvMu.Unlock()
	loadNodeIdentity()
	// 排空本地 TG 队列残留, 避免跨测试污染
drain:
	for {
		select {
		case <-tgQueue:
		default:
			break drain
		}
	}
	return func() {
		settings, nodeIdent, nodeFile = oldSettings, oldNodeIdent, oldNodeFile
		tgHubQueueFile = oldQueueFile
		hubEvMu.Lock()
		hubEvQueue, hubEvLoaded = oldQueue, oldLoaded
		hubEvMu.Unlock()
		hubEvRunMu.Lock()
		hubEvRunning = oldRunning
		hubEvRunMu.Unlock()
		tgAPICall = oldAPICall
		tgTestLast = oldTestLast
	}
}

func TestNodeTGModeEffective(t *testing.T) {
	defer setupTGMultiTest(t)()
	if got := nodeTGMode(); got != "hub" {
		t.Fatalf("被群控默认应走主服务器, 得到 %q", got)
	}
	mu.Lock()
	settings.NodeTGMode = "independent"
	mu.Unlock()
	if got := nodeTGMode(); got != "independent" {
		t.Fatalf("切独立后应为 independent, 得到 %q", got)
	}
	mu.Lock()
	settings.RunMode = "standalone"
	mu.Unlock()
	if got := nodeTGMode(); got != "" {
		t.Fatalf("独立机模式应为空, 得到 %q", got)
	}
}

func TestTGConfiguredModes(t *testing.T) {
	defer setupTGMultiTest(t)()
	// 被群控 + 走主服务器: 本机无 bot
	if tgConfigured() {
		t.Fatalf("走主服务器模式本机应判定未配置")
	}
	// 被群控 + 独立: 用 node.json 配置判定
	mu.Lock()
	settings.NodeTGMode = "independent"
	mu.Unlock()
	if tgConfigured() {
		t.Fatalf("独立配置未填时应判定未配置")
	}
	setNodeTGConfig(true, "tok-x", "12345")
	if !tgConfigured() {
		t.Fatalf("独立配置填好后应判定已配置")
	}
	setNodeTGConfig(false, "tok-x", "12345")
	if tgConfigured() {
		t.Fatalf("独立开关关时应判定未配置")
	}
}

func TestHubQueueRingAndPersist(t *testing.T) {
	defer setupTGMultiTest(t)()
	for i := 0; i < 205; i++ {
		enqueueHubEvent(Event{Type: "ban", IP: "1.2.3.4", Detail: "第" + itoa(i) + "条"})
	}
	if n := hubQueueLen(); n != tgHubQueueCap {
		t.Fatalf("队列应封顶 %d 条, 得到 %d", tgHubQueueCap, n)
	}
	b, err := os.ReadFile(tgHubQueueFile)
	if err != nil {
		t.Fatalf("队列应落盘: %v", err)
	}
	var q []Event
	if json.Unmarshal(b, &q) != nil || len(q) != tgHubQueueCap {
		t.Fatalf("落盘队列应为 %d 条, 得到 %d", tgHubQueueCap, len(q))
	}
	if q[0].Detail != "第5条" {
		t.Fatalf("超 cap 应丢最老的 5 条, 队首为 %q", q[0].Detail)
	}
	// 内存清空后应能从盘里重载
	hubEvMu.Lock()
	hubEvQueue = nil
	hubEvLoaded = false
	hubEvMu.Unlock()
	if n := hubQueueLen(); n != tgHubQueueCap {
		t.Fatalf("重载后应为 %d 条, 得到 %d", tgHubQueueCap, n)
	}
}

func TestNodeEventsHubMode(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	hubServers = []*hubServer{{
		Fingerprint: fp, PubKey: pubB64, Name: "节点甲", Status: "online",
		LastSeen: time.Now().Unix(), TokenHash: hashToken("tok123"), TGMode: "hub",
	}}
	settings.TGEnabled = true
	settings.TGBotToken = "hubtok"
	settings.TGChatID = "12345"
	var gotToken, gotMethod string
	var gotPayload map[string]any
	tgAPICall = func(token, method string, payload any, timeout time.Duration) (map[string]any, error) {
		gotToken, gotMethod = token, method
		b, _ := json.Marshal(payload)
		json.Unmarshal(b, &gotPayload)
		return map[string]any{"ok": true}, nil
	}
	rec := hubCall(t, handleNodeEvents, "POST", "/api/nodes/events",
		`{"type":"new_conn","ts":1700000000000,"ip":"1.2.3.4","port":22,"detail":"测试连接"}`,
		map[string]string{"X-Node-Fingerprint": fp, "X-Node-Token": "tok123"})
	out := hubCallJSON(t, rec)
	if rec.Code != 200 || out["sent"] != true {
		t.Fatalf("走主服务器模式应代发: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotToken != "hubtok" || gotMethod != "sendMessage" {
		t.Fatalf("应走主服务器 bot 发: token=%q method=%q", gotToken, gotMethod)
	}
	text, _ := gotPayload["text"].(string)
	if !strings.Contains(text, "") || !strings.Contains(text, "重点端口新连接") {
		t.Fatalf("标题应带节点名、正文应有事件名: %q", text)
	}
	markup, _ := gotPayload["reply_markup"].(map[string]any)
	kb, _ := markup["inline_keyboard"].([]any)
	row, _ := kb[0].([]any)
	btn, _ := row[0].(map[string]any)
	cb, _ := btn["callback_data"].(string)
	if cb != "ban:1.2.3.4:"+fp {
		t.Fatalf("拉黑按钮回调应带节点指纹, 得到 %q", cb)
	}
}

func TestNodeEventsIndependentDrop(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	hubServers = []*hubServer{{
		Fingerprint: fp, PubKey: pubB64, Name: "节点乙", Status: "online",
		LastSeen: time.Now().Unix(), TokenHash: hashToken("tok123"), TGMode: "independent",
	}}
	settings.TGEnabled = true
	settings.TGBotToken = "hubtok"
	settings.TGChatID = "12345"
	called := false
	tgAPICall = func(token, method string, payload any, timeout time.Duration) (map[string]any, error) {
		called = true
		return map[string]any{"ok": true}, nil
	}
	rec := hubCall(t, handleNodeEvents, "POST", "/api/nodes/events",
		`{"type":"ban","ip":"1.2.3.4","detail":"x"}`,
		map[string]string{"X-Node-Fingerprint": fp, "X-Node-Token": "tok123"})
	out := hubCallJSON(t, rec)
	if rec.Code != 200 || out["sent"] != false || out["reason"] != "independent" {
		t.Fatalf("独立模式应回绝不发: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatalf("独立模式主服务器绝不能发")
	}
}

func TestNodeEventsHubTGUnconfigured(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	hubServers = []*hubServer{{
		Fingerprint: fp, PubKey: pubB64, Name: "节点丙", Status: "online",
		LastSeen: time.Now().Unix(), TokenHash: hashToken("tok123"), TGMode: "hub",
	}}
	// 主服务器 bot 未配置
	called := false
	tgAPICall = func(token, method string, payload any, timeout time.Duration) (map[string]any, error) {
		called = true
		return map[string]any{"ok": true}, nil
	}
	rec := hubCall(t, handleNodeEvents, "POST", "/api/nodes/events",
		`{"type":"ban","ip":"1.2.3.4","detail":"x"}`,
		map[string]string{"X-Node-Fingerprint": fp, "X-Node-Token": "tok123"})
	out := hubCallJSON(t, rec)
	if out["sent"] != false || out["reason"] != "hub-tg-unconfigured" {
		t.Fatalf("主服务器 bot 未配应回绝: body=%s", rec.Body.String())
	}
	if called {
		t.Fatalf("bot 未配时绝不能发")
	}
}

func TestNodeEventsBadAuth(t *testing.T) {
	defer setupHubTest(t)()
	rec := hubCall(t, handleNodeEvents, "POST", "/api/nodes/events",
		`{"type":"ban","ip":"1.2.3.4","detail":"x"}`, nil)
	if rec.Code != 401 {
		t.Fatalf("无鉴权应 401, 得到 %d", rec.Code)
	}
}

func TestParseNodeCallback(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	hubServers = []*hubServer{{Fingerprint: fp, PubKey: pubB64, Name: "n"}}
	cases := []struct {
		in   string
		want bool
		rest string
	}{
		{"ban:1.2.3.4:" + fp, true, "ban:1.2.3.4"},
		{"bc:" + fp, true, "bc"},
		{"ban:2001:db8::1:" + fp, true, "ban:2001:db8::1"},
		{"ban:1.2.3.4:abcd1234", false, ""},
		{"ban:1.2.3.4:" + strings.Repeat("a", 64), false, ""},
		{"garbage", false, ""},
	}
	for _, c := range cases {
		gotFP, rest, ok := parseNodeCallback(c.in)
		if ok != c.want {
			t.Fatalf("parseNodeCallback(%q) ok=%v, want %v", c.in, ok, c.want)
		}
		if ok && (gotFP != fp || rest != c.rest) {
			t.Fatalf("parseNodeCallback(%q) = (%q,%q), want (%q,%q)", c.in, gotFP, rest, fp, c.rest)
		}
	}
}

func TestNodeRoutedCallback(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	hubServers = []*hubServer{{
		Fingerprint: fp, PubKey: pubB64, Name: "n", Status: "online",
		LastSeen: time.Now().Unix(), TokenHash: hashToken("tok123"),
	}}
	// 假节点命令执行器: 读命令 -> 按 ID 回结果
	wch := make(chan hubCommand, 1)
	cmdMu.Lock()
	cmdWaiters[fp] = wch
	cmdMu.Unlock()
	go func() {
		for cmd := range wch {
			cmdMu.Lock()
			ch := cmdResults[cmd.ID]
			cmdMu.Unlock()
			if ch != nil {
				status := 200
				body := json.RawMessage(`{"until":0}`)
				if cmd.Method == "DELETE" {
					body = json.RawMessage(`{"ok":true}`)
				}
				ch <- hubCmdResult{Status: status, Body: body}
			}
		}
	}()
	var answers, texts []string
	var markups []any
	answer := func(s string) { answers = append(answers, s) }
	editMarkup := func(kb any) { markups = append(markups, kb) }
	editText := func(s string) { texts = append(texts, s) }

	// ban: 应出时长键盘, 回调全带节点指纹
	handleNodeRoutedCallback(fp, "ban:5.6.7.8", 1, 2, "原消息", answer, editMarkup, editText)
	if len(markups) != 1 || len(answers) != 1 || answers[0] != "请选择拉黑时长" {
		t.Fatalf("ban 应出时长键盘: markups=%d answers=%v", len(markups), answers)
	}
	b, _ := json.Marshal(markups[0])
	if !strings.Contains(string(b), "bd:5.6.7.8:1:"+fp) || !strings.Contains(string(b), "bc:"+fp) {
		t.Fatalf("时长键盘回调应带节点指纹: %s", string(b))
	}
	// bd: 应在节点上执行拉黑并改文案
	answers, texts = nil, nil
	handleNodeRoutedCallback(fp, "bd:5.6.7.8:24", 1, 2, "原消息", answer, editMarkup, editText)
	if len(texts) != 1 || !strings.Contains(texts[0], "已拉黑(永久)") {
		t.Fatalf("bd 应改文案为已拉黑: texts=%v answers=%v", texts, answers)
	}
	// ub: 应在节点上执行解封
	answers, texts = nil, nil
	handleNodeRoutedCallback(fp, "ub:5.6.7.8", 1, 2, "原消息", answer, editMarkup, editText)
	if len(texts) != 1 || !strings.Contains(texts[0], "已解封 5.6.7.8") {
		t.Fatalf("ub 应改文案为已解封: texts=%v", texts)
	}
	// 离线节点只提示不执行
	hubServers[0].LastSeen = time.Now().Unix() - 1000
	answers, texts, markups = nil, nil, nil
	handleNodeRoutedCallback(fp, "ban:5.6.7.8", 1, 2, "原消息", answer, editMarkup, editText)
	if len(answers) != 1 || answers[0] != "节点离线，无法执行" || len(markups) != 0 {
		t.Fatalf("离线节点应只提示: answers=%v markups=%d", answers, len(markups))
	}
}

func TestTGModeEndpoint(t *testing.T) {
	defer setupTGMultiTest(t)()
	// 独立机调应 400
	mu.Lock()
	settings.RunMode = "standalone"
	mu.Unlock()
	rec := hubCall(t, handleNodeTGMode, "POST", "/api/tg/mode", `{"mode":"hub"}`, nil)
	if rec.Code != 400 {
		t.Fatalf("独立机调模式接口应 400, 得到 %d", rec.Code)
	}
	mu.Lock()
	settings.RunMode = "managed"
	mu.Unlock()
	// 非法 mode / 非法 ChatID
	rec = hubCall(t, handleNodeTGMode, "POST", "/api/tg/mode", `{"mode":"bogus"}`, nil)
	if rec.Code != 400 {
		t.Fatalf("非法 mode 应 400, 得到 %d", rec.Code)
	}
	rec = hubCall(t, handleNodeTGMode, "POST", "/api/tg/mode", `{"mode":"independent","enabled":true,"token":"tok-1","chatId":"abc"}`, nil)
	if rec.Code != 400 {
		t.Fatalf("非法 ChatID 应 400, 得到 %d", rec.Code)
	}
	// 独立但缺凭据应 400
	rec = hubCall(t, handleNodeTGMode, "POST", "/api/tg/mode", `{"mode":"independent","enabled":true}`, nil)
	if rec.Code != 400 {
		t.Fatalf("独立缺凭据应 400, 得到 %d", rec.Code)
	}
	// 正常切独立: 落盘 node.json(0600), GET 只回掩码
	rec = hubCall(t, handleNodeTGMode, "POST", "/api/tg/mode", `{"mode":"independent","enabled":true,"token":"tok-1","chatId":"12345"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("切独立应 200, 得到 %d body=%s", rec.Code, rec.Body.String())
	}
	en, tok, chat := nodeTGConfig()
	if !en || tok != "tok-1" || chat != "12345" {
		t.Fatalf("独立配置应落 node.json, 得到 enabled=%v token=%q chat=%q", en, tok, chat)
	}
	mu.Lock()
	mode := settings.NodeTGMode
	mu.Unlock()
	if mode != "independent" {
		t.Fatalf("settings 应记 independent, 得到 %q", mode)
	}
	st, _ := os.Stat(nodeFile)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("node.json 应 0600, 得到 %o", st.Mode().Perm())
	}
	b, _ := os.ReadFile(nodeFile)
	if strings.Contains(string(b), "tok-1") == false {
		t.Fatalf("node.json 应含 token")
	}
	rec = hubCall(t, handleNodeTGMode, "GET", "/api/tg/mode", "", nil)
	out := hubCallJSON(t, rec)
	if out["hasToken"] != true || out["token"] != tgTokenMask {
		t.Fatalf("GET 应只回掩码: body=%s", rec.Body.String())
	}
	// 掩码回传 = 保留旧 token
	rec = hubCall(t, handleNodeTGMode, "POST", "/api/tg/mode", `{"mode":"independent","enabled":true,"token":"********","chatId":"12345"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("掩码回传应 200, 得到 %d", rec.Code)
	}
	_, tok, _ = nodeTGConfig()
	if tok != "tok-1" {
		t.Fatalf("掩码回传应保留旧 token, 得到 %q", tok)
	}
}

func TestTGModeTestEndpoint(t *testing.T) {
	defer setupTGMultiTest(t)()
	tgTestLast = time.Time{}
	tgAPICall = func(token, method string, payload any, timeout time.Duration) (map[string]any, error) {
		if token != "tok-9" {
			t.Errorf("测试应用独立 token, 得到 %q", token)
		}
		return map[string]any{"ok": true}, nil
	}
	rec := hubCall(t, handleNodeTGModeTest, "POST", "/api/tg/mode/test", `{"token":"tok-9","chatId":"12345"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("独立测试应 200, 得到 %d body=%s", rec.Code, rec.Body.String())
	}
	// 10 秒内第二次应 429
	rec = hubCall(t, handleNodeTGModeTest, "POST", "/api/tg/mode/test", `{"token":"tok-9","chatId":"12345"}`, nil)
	if rec.Code != 429 {
		t.Fatalf("连点测试应 429, 得到 %d", rec.Code)
	}
}

func TestPingTGModeSync(t *testing.T) {
	defer setupHubTest(t)()
	_, fp, pubB64 := hubTestKey(t)
	hubServers = []*hubServer{{
		Fingerprint: fp, PubKey: pubB64, Name: "n", Status: "online",
		LastSeen: time.Now().Unix(), TokenHash: hashToken("tok123"), TGMode: "hub",
	}}
	rec := hubCall(t, handleNodePing, "POST", "/api/nodes/ping", `{"version":"0.1","tgMode":"independent"}`,
		map[string]string{"X-Node-Fingerprint": fp, "X-Node-Token": "tok123"})
	if rec.Code != 200 {
		t.Fatalf("ping 应 200, 得到 %d", rec.Code)
	}
	if hubServers[0].TGMode != "independent" {
		t.Fatalf("ping 应同步节点 TG 模式, 得到 %q", hubServers[0].TGMode)
	}
}

func TestSendEventRouting(t *testing.T) {
	defer setupTGMultiTest(t)()
	ev := Event{Type: "honeypot_hit", IP: "9.9.9.9", Geo: "测试归属地", Detail: "蜜罐命中测试"}
	// 被群控 + 走主服务器: 进上报队列, 不进本机队列
	tgSendEvent(ev)
	if n := hubQueueLen(); n != 1 {
		t.Fatalf("走主服务器模式事件应进上报队列, 队列=%d", n)
	}
	select {
	case m := <-tgQueue:
		t.Fatalf("走主服务器模式事件不应进本机队列, 得到 %+v", m)
	default:
	}
	// 切独立: 事件走本机队列(带独立配置)
	mu.Lock()
	settings.NodeTGMode = "independent"
	mu.Unlock()
	setNodeTGConfig(true, "tok-ind", "12345")
	tgSendEvent(ev)
	select {
	case m := <-tgQueue:
		if !strings.Contains(m.text, "蜜罐命中") {
			t.Fatalf("独立模式本机消息应含事件名, 得到 %q", m.text)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("独立模式事件应进本机队列")
	}
	// 上报队列仍只有原来那 1 条(独立事件不进上报队列)
	if n := hubQueueLen(); n != 1 {
		t.Fatalf("独立事件不应进上报队列, 队列=%d", n)
	}
}

func TestPostHubEventActions(t *testing.T) {
	defer setupTGMultiTest(t)()
	// 无主服务器地址 -> retry
	if got := postHubEvent(Event{Type: "ban"}); got != "retry" {
		t.Fatalf("无地址应 retry, 得到 %q", got)
	}
	// 假主服务器: 按 Detail 返回不同上报结果
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Event
		json.NewDecoder(r.Body).Decode(&ev)
		w.Header().Set("Content-Type", "application/json")
		switch ev.Detail {
		case "sent":
			w.Write([]byte(`{"ok":true,"sent":true}`))
		case "indep":
			w.Write([]byte(`{"ok":true,"sent":false,"reason":"independent"}`))
		case "gone":
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"revoked"}`))
		default:
			w.WriteHeader(500)
			w.Write([]byte(`{"error":"boom"}`))
		}
	}))
	defer srv.Close()
	mu.Lock()
	settings.HubURL = srv.URL
	mu.Unlock()
	setNodeToken("tok-x")
	if got := postHubEvent(Event{Type: "ban", Detail: "sent"}); got != "done" {
		t.Fatalf("主服务器已发应 done, 得到 %q", got)
	}
	if got := postHubEvent(Event{Type: "ban", Detail: "indep"}); got != "local" {
		t.Fatalf("独立回绝应 local, 得到 %q", got)
	}
	if got := postHubEvent(Event{Type: "ban", Detail: "gone"}); got != "done" {
		t.Fatalf("401 应 done(丢弃), 得到 %q", got)
	}
	if got := postHubEvent(Event{Type: "ban", Detail: "other"}); got != "retry" {
		t.Fatalf("500 应 retry, 得到 %q", got)
	}
}
