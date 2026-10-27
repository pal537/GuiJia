package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 10 项反馈(2026-10-27 晚 v1.0.6 实测后)的后端回归测试。

// TestTenTrustLANImplicit 第 6 项: TrustLAN 标志隐式信任四段标准私网范围,
// 列表干净时仍生效; 关闭后只认列表。
func TestTenTrustLANImplicit(t *testing.T) {
	mu.Lock()
	oldTrusted, oldLAN := settings.TrustedIPs, settings.TrustLAN
	settings.TrustedIPs = []string{"203.0.113.10"}
	settings.TrustLAN = true
	mu.Unlock()
	defer func() {
		mu.Lock()
		settings.TrustedIPs, settings.TrustLAN = oldTrusted, oldLAN
		mu.Unlock()
	}()
	for _, ip := range []string{"192.168.1.5", "10.1.2.3", "172.16.5.5", "fc00::1"} {
		if !isTrusted(ip) {
			t.Errorf("TrustLAN 开时 %s 应隐式信任", ip)
		}
	}
	if !isTrusted("203.0.113.10") {
		t.Errorf("列表条目仍应信任")
	}
	for _, ip := range []string{"203.0.113.99", "8.8.8.8", "169.254.1.1"} {
		if isTrusted(ip) {
			t.Errorf("TrustLAN 开时 %s 不应信任(不在四段与列表里)", ip)
		}
	}
	mu.Lock()
	settings.TrustLAN = false
	mu.Unlock()
	if isTrusted("192.168.1.5") {
		t.Errorf("TrustLAN 关后内网不应再隐式信任")
	}
	if !isTrusted("203.0.113.10") {
		t.Errorf("TrustLAN 关后列表条目仍应信任")
	}
}

// TestTenTrustSetLists 第 6 项: 内核信任集合来源 = 名单 + (勾选时)四段, 归一化后去重。
func TestTenTrustSetLists(t *testing.T) {
	mu.Lock()
	oldTrusted, oldLAN := settings.TrustedIPs, settings.TrustLAN
	settings.TrustedIPs = []string{"203.0.113.10", "192.168.0.0/16"}
	settings.TrustLAN = true
	mu.Unlock()
	defer func() {
		mu.Lock()
		settings.TrustedIPs, settings.TrustLAN = oldTrusted, oldLAN
		mu.Unlock()
	}()
	v4, v6 := trustSetLists()
	want4 := map[string]bool{"203.0.113.10": true, "192.168.0.0/16": true, "10.0.0.0/8": true, "172.16.0.0/12": true}
	if len(v4) != len(want4) {
		t.Fatalf("勾选时 v4 应为 %v, 实际 %v", want4, v4)
	}
	for _, ip := range v4 {
		if !want4[ip] {
			t.Errorf("勾选时 v4 不应含 %s", ip)
		}
	}
	if len(v6) != 1 || v6[0] != "fc00::/7" {
		t.Errorf("勾选时 v6 应只有 fc00::/7, 实际 %v", v6)
	}
	mu.Lock()
	settings.TrustLAN = false
	mu.Unlock()
	v4, v6 = trustSetLists()
	if len(v4) != 2 || len(v6) != 0 {
		t.Errorf("关闭后应只剩列表两条, 实际 v4=%v v6=%v", v4, v6)
	}
}

// TestTenGroupSyncVerifyState 第 2 项: 超时后核实的纯比对逻辑。
func TestTenGroupSyncVerifyState(t *testing.T) {
	// 白名单: 集合相等才算收敛。
	wbody := map[string]any{"whitelist": []string{"203.0.113.1", "203.0.113.2"}}
	if !groupSyncVerifyState("whitelist", wbody, sharedStateResp{Whitelist: []string{"203.0.113.2", "203.0.113.1"}}) {
		t.Errorf("白名单集合相等应算已应用")
	}
	if groupSyncVerifyState("whitelist", wbody, sharedStateResp{Whitelist: []string{"203.0.113.1"}}) {
		t.Errorf("白名单缺条目不应算已应用")
	}
	if groupSyncVerifyState("whitelist", wbody, sharedStateResp{Whitelist: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}}) {
		t.Errorf("白名单多条目不应算已应用")
	}
	// 黑名单: active 生效 + released 未生效 = 收敛。
	bbody := map[string]any{"blacklist": []map[string]any{
		{"ip": "203.0.113.9", "status": "active"},
		{"ip": "203.0.113.8", "status": "released"},
	}}
	okState := sharedStateResp{Blacklist: []sharedStateBan{
		{IP: "203.0.113.9", Enforced: true},
		{IP: "203.0.113.8", Enforced: false},
	}}
	if !groupSyncVerifyState("blacklist", bbody, okState) {
		t.Errorf("黑名单收敛状态应算已应用")
	}
	bad := sharedStateResp{Blacklist: []sharedStateBan{
		{IP: "203.0.113.9", Enforced: false},
		{IP: "203.0.113.8", Enforced: false},
	}}
	if groupSyncVerifyState("blacklist", bbody, bad) {
		t.Errorf("active 未生效不应算已应用")
	}
	bad.Blacklist[0].Enforced = true
	bad.Blacklist[1].Enforced = true
	if groupSyncVerifyState("blacklist", bbody, bad) {
		t.Errorf("released 仍生效不应算已应用")
	}
	// 节点本地信任的 active 条目: 应用侧合法跳过, 核实同样跳过。
	skipBody := map[string]any{"blacklist": []map[string]any{{"ip": "203.0.113.77", "status": "active"}}}
	if !groupSyncVerifyState("blacklist", skipBody, sharedStateResp{Trust: []string{"203.0.113.77"}}) {
		t.Errorf("节点本地信任的条目应合法跳过")
	}
	// 内网 active 条目: 合法跳过。
	skipBody = map[string]any{"blacklist": []map[string]any{{"ip": "10.0.0.9", "status": "active"}}}
	if !groupSyncVerifyState("blacklist", skipBody, sharedStateResp{}) {
		t.Errorf("内网条目应合法跳过")
	}
	// 节点开 TrustLAN 时的内网条目: 合法跳过。
	skipBody = map[string]any{"blacklist": []map[string]any{{"ip": "192.168.3.4", "status": "active"}}}
	if !groupSyncVerifyState("blacklist", skipBody, sharedStateResp{TrustLAN: true}) {
		t.Errorf("TrustLAN 节点的内网条目应合法跳过")
	}
	// expired 缺席即未生效。
	skipBody = map[string]any{"blacklist": []map[string]any{{"ip": "203.0.113.55", "status": "expired"}}}
	if !groupSyncVerifyState("blacklist", skipBody, sharedStateResp{}) {
		t.Errorf("expired 缺席应算已收敛")
	}
}

// TestTenSyncTimeoutVerify 第 2 项: 慢节点模拟——apply 命令故意不回(超时),
// 核实读回已收敛快照, 应报“已应用（超时后核实）”而非失败。
func TestTenSyncTimeoutVerify(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	hubMu.Lock()
	oldServers := hubServers
	hubServers = append(append([]*hubServer{}, oldServers...),
		&hubServer{Fingerprint: fp, Name: "T", LastSeen: time.Now().Unix()})
	hubMu.Unlock()
	defer func() {
		hubMu.Lock()
		hubServers = oldServers
		hubMu.Unlock()
	}()
	oldSyncWait, oldVerifyWait := syncResultWait, verifyResultWait
	syncResultWait = 100 * time.Millisecond
	verifyResultWait = 5 * time.Second
	defer func() { syncResultWait, verifyResultWait = oldSyncWait, oldVerifyWait }()
	banMu.Lock()
	oldBans := bans
	bans = []*Ban{{IP: "203.0.113.9", Source: "manual", Status: BanActive, Until: 0, CreatedAt: time.Now().Unix()}}
	banMu.Unlock()
	defer func() {
		banMu.Lock()
		bans = oldBans
		banMu.Unlock()
	}()
	mu.Lock()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = []string{"203.0.113.99"}
	mu.Unlock()
	defer func() {
		mu.Lock()
		settings.TrustedIPs = oldTrusted
		mu.Unlock()
	}()
	wch := make(chan hubCommand, 1)
	cmdMu.Lock()
	oldW, hadW := cmdWaiters[fp]
	cmdWaiters[fp] = wch
	cmdMu.Unlock()
	defer func() {
		cmdMu.Lock()
		if hadW {
			cmdWaiters[fp] = oldW
		} else {
			delete(cmdWaiters, fp)
		}
		cmdMu.Unlock()
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for cmd := range wch {
			if cmd.Path != "api/sync/shared-state" {
				continue // apply-lists 故意不回: 模拟节点应用慢到超时。
			}
			cmdMu.Lock()
			ch, ok := cmdResults[cmd.ID]
			cmdMu.Unlock()
			if !ok {
				continue
			}
			snap, _ := json.Marshal(sharedStateResp{
				Blacklist: []sharedStateBan{{IP: "203.0.113.9", Enforced: true}},
				Whitelist: []string{"203.0.113.99"},
			})
			select {
			case ch <- hubCmdResult{Status: 200, Body: snap}:
			default:
			}
		}
	}()
	defer func() { close(wch); <-done }()
	if ok, detail := syncGroupToNode("blacklist", fp); !ok || detail != "已应用（超时后核实）" {
		t.Errorf("黑名单超时后核实应报成功, 实际 ok=%v detail=%q", ok, detail)
	}
	if ok, detail := syncGroupToNode("whitelist", fp); !ok || detail != "已应用（超时后核实）" {
		t.Errorf("白名单超时后核实应报成功, 实际 ok=%v detail=%q", ok, detail)
	}
}

// TestTenSyncTimeoutVerifyFail 第 2 项: 慢节点 + 核实两次都未收敛, 最终才报失败。
func TestTenSyncTimeoutVerifyFail(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	hubMu.Lock()
	oldServers := hubServers
	hubServers = append(append([]*hubServer{}, oldServers...),
		&hubServer{Fingerprint: fp, Name: "T", LastSeen: time.Now().Unix()})
	hubMu.Unlock()
	defer func() {
		hubMu.Lock()
		hubServers = oldServers
		hubMu.Unlock()
	}()
	oldSyncWait, oldVerifyWait := syncResultWait, verifyResultWait
	syncResultWait = 100 * time.Millisecond
	verifyResultWait = 5 * time.Second
	defer func() { syncResultWait, verifyResultWait = oldSyncWait, oldVerifyWait }()
	banMu.Lock()
	oldBans := bans
	bans = []*Ban{{IP: "203.0.113.9", Source: "manual", Status: BanActive, Until: 0, CreatedAt: time.Now().Unix()}}
	banMu.Unlock()
	defer func() {
		banMu.Lock()
		bans = oldBans
		banMu.Unlock()
	}()
	wch := make(chan hubCommand, 1)
	cmdMu.Lock()
	oldW, hadW := cmdWaiters[fp]
	cmdWaiters[fp] = wch
	cmdMu.Unlock()
	defer func() {
		cmdMu.Lock()
		if hadW {
			cmdWaiters[fp] = oldW
		} else {
			delete(cmdWaiters, fp)
		}
		cmdMu.Unlock()
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for cmd := range wch {
			if cmd.Path != "api/sync/shared-state" {
				continue
			}
			cmdMu.Lock()
			ch, ok := cmdResults[cmd.ID]
			cmdMu.Unlock()
			if !ok {
				continue
			}
			snap, _ := json.Marshal(sharedStateResp{Blacklist: []sharedStateBan{}, Whitelist: []string{}})
			select {
			case ch <- hubCmdResult{Status: 200, Body: snap}:
			default:
			}
		}
	}()
	defer func() { close(wch); <-done }()
	if ok, detail := syncGroupToNode("blacklist", fp); ok || detail != "节点响应超时" {
		t.Errorf("两次核实未收敛最终应报节点响应超时, 实际 ok=%v detail=%q", ok, detail)
	}
}
func TestTenProxyErrMessage(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	if got := proxyErrMessage(fp, "notfound"); got != "没有该节点" {
		t.Errorf("notfound 应为“没有该节点”, 实际 %q", got)
	}
	if got := proxyErrMessage(fp, "offline"); got != "节点离线" {
		t.Errorf("offline 应为“节点离线”, 实际 %q", got)
	}
	hubMu.Lock()
	oldServers := hubServers
	hubServers = append(append([]*hubServer{}, oldServers...),
		&hubServer{Fingerprint: fp, Name: "T", LastSeen: time.Now().Unix()})
	hubMu.Unlock()
	pushMu.Lock()
	oldJobs := pushJobs
	pushJobs = map[string]*pushJob{}
	pushMu.Unlock()
	defer func() {
		hubMu.Lock()
		hubServers = oldServers
		hubMu.Unlock()
		pushMu.Lock()
		pushJobs = oldJobs
		pushMu.Unlock()
	}()
	if got := proxyErrMessage(fp, "nochan"); got != "节点可能正在重启，请稍后再试" {
		t.Errorf("刚在线却无通道应说可能正在重启, 实际 %q", got)
	}
	if got := proxyErrMessage(fp, "timeout"); got != "节点响应超时" {
		t.Errorf("无推送任务的超时应说响应超时, 实际 %q", got)
	}
	pushMu.Lock()
	pushJobs[fp] = &pushJob{Fingerprint: fp, State: "upgrading"}
	pushMu.Unlock()
	for _, kind := range []string{"nochan", "timeout"} {
		if got := proxyErrMessage(fp, kind); got != "节点可能正在重启（刚推送升级），请稍后再试" {
			t.Errorf("推送升级中的 %s 应说刚推送升级重启中, 实际 %q", kind, got)
		}
	}
	pushMu.Lock()
	delete(pushJobs, fp)
	pushMu.Unlock()
	hubMu.Lock()
	hubServers[len(hubServers)-1].LastSeen = time.Now().Unix() - 3600
	hubMu.Unlock()
	if got := proxyErrMessage(fp, "nochan"); got != "节点未建立命令通道" {
		t.Errorf("陈旧节点无通道应说未建立命令通道, 实际 %q", got)
	}
}

// TestTenSharedStateHandler 第 2 项: 核实读接口的内部头 guard 与快照内容。
func TestTenSharedStateHandler(t *testing.T) {
	dir := banTestSetup(t)
	oldDataDir := dataDir
	dataDir = dir
	defer func() { dataDir = oldDataDir }()
	mu.Lock()
	oldTrusted, oldLAN := settings.TrustedIPs, settings.TrustLAN
	settings.TrustedIPs = []string{"203.0.113.99", "203.0.113.100"}
	settings.TrustLAN = true
	mu.Unlock()
	defer func() {
		mu.Lock()
		settings.TrustedIPs, settings.TrustLAN = oldTrusted, oldLAN
		mu.Unlock()
	}()
	saveSharedLists(sharedLists{SharedTrust: []string{"203.0.113.99"}})
	now := time.Now().Unix()
	banMu.Lock()
	bans = []*Ban{
		{IP: "203.0.113.9", Source: "shared", Status: BanActive, Until: 0, CreatedAt: now},
		{IP: "203.0.113.8", Source: "shared", Status: "released", ReleasedAt: now, CreatedAt: now},
		{IP: "203.0.113.7", Source: "manual", Status: BanActive, Until: 0, CreatedAt: now},
	}
	banMu.Unlock()
	req := httptest.NewRequest("GET", "/api/sync/shared-state", nil)
	rec := httptest.NewRecorder()
	handleSyncSharedState(rec, req)
	if rec.Code != 403 {
		t.Fatalf("无内部头应 403, 实际 %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/sync/shared-state", nil)
	req.Header.Set("X-Guijia-Internal", "1")
	rec = httptest.NewRecorder()
	handleSyncSharedState(rec, req)
	if rec.Code != 200 {
		t.Fatalf("内部头应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var st sharedStateResp
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("快照 JSON 解析失败: %v", err)
	}
	if len(st.Blacklist) != 2 {
		t.Fatalf("快照黑名单应只有 2 条 shared, 实际 %+v", st.Blacklist)
	}
	enf := map[string]bool{}
	for _, b := range st.Blacklist {
		enf[b.IP] = b.Enforced
	}
	if !enf["203.0.113.9"] || enf["203.0.113.8"] {
		t.Errorf("生效状态不对: %+v", enf)
	}
	if len(st.Whitelist) != 1 || st.Whitelist[0] != "203.0.113.99" {
		t.Errorf("快照白名单应只有 shared 标记那条, 实际 %v", st.Whitelist)
	}
	if len(st.Trust) != 2 || !st.TrustLAN {
		t.Errorf("快照应带完整信任名单与 LAN 标志, 实际 trust=%v lan=%v", st.Trust, st.TrustLAN)
	}
}

// TestTenNodeTGTest 第 4 项: 走主服务器模式的节点连通性测试端点。
func TestTenNodeTGTest(t *testing.T) {
	fp := strings.Repeat("cd", 32)
	hubMu.Lock()
	oldServers := hubServers
	hubServers = append(append([]*hubServer{}, oldServers...),
		&hubServer{Fingerprint: fp, Name: "RN测试"})
	hubMu.Unlock()
	defer func() {
		hubMu.Lock()
		hubServers = oldServers
		hubMu.Unlock()
	}()
	oldCall := tgAPICall
	defer func() { tgAPICall = oldCall }()
	var gotText string
	tgAPICall = func(token, method string, payload any, timeout time.Duration) (map[string]any, error) {
		if m, ok := payload.(map[string]any); ok {
			gotText, _ = m["text"].(string)
		}
		return map[string]any{"ok": true}, nil
	}
	mu.Lock()
	oldTok, oldChat := settings.TGBotToken, settings.TGChatID
	settings.TGBotToken = "tok"
	settings.TGChatID = "12345"
	mu.Unlock()
	defer func() {
		mu.Lock()
		settings.TGBotToken, settings.TGChatID = oldTok, oldChat
		mu.Unlock()
	}()
	call := func(body string) *httptest.ResponseRecorder {
		tgTestMu.Lock()
		tgTestLast = time.Time{}
		tgTestMu.Unlock()
		req := httptest.NewRequest("POST", "/api/nodes/tg-test", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handleNodeTGTest(rec, req)
		return rec
	}
	rec := call(`{"fingerprint":"` + fp + `"}`)
	if rec.Code != 200 {
		t.Fatalf("已配 TG 应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(gotText, "RN测试") {
		t.Errorf("测试消息标题应带节点名, 实际 %q", gotText)
	}
	mu.Lock()
	settings.TGBotToken = ""
	mu.Unlock()
	rec = call(`{"fingerprint":"` + fp + `"}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "主服务器未配置") {
		t.Errorf("未配 TG 应 400 主服务器未配置, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	settings.TGBotToken = "tok"
	mu.Unlock()
	rec = call(`{"fingerprint":"` + strings.Repeat("ee", 32) + `"}`)
	if rec.Code != 404 {
		t.Errorf("未知指纹应 404, 实际 %d", rec.Code)
	}
}
