package main

// 11 项反馈的单元测试: 公网 IP 优先、归属地/国旗、推送任务判定、
// 共享名单落地(只增改状态不删记录、本机条目不动、内部头鉴权)、备份文件名。

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------- 第 3 项: 公网 IP 优先 ----------

func TestSelectDisplayIP(t *testing.T) {
	if got := selectDisplayIP("203.0.113.9", []string{"10.0.0.122", "192.168.1.5"}); got != "203.0.113.9" {
		t.Fatalf("公网优先失败: %q", got)
	}
	if got := selectDisplayIP("", []string{"10.0.0.122", "203.0.113.5"}); got != "203.0.113.5" {
		t.Fatalf("无公网时应取首个非私网接口 IP: %q", got)
	}
	if got := selectDisplayIP("", []string{"10.0.0.122", "172.16.0.3", "192.168.1.5"}); got != "10.0.0.122" {
		t.Fatalf("全私网时应回落首个接口 IP: %q", got)
	}
	if got := selectDisplayIP("not-an-ip", []string{"192.168.1.5"}); got != "192.168.1.5" {
		t.Fatalf("非法公网值应被忽略: %q", got)
	}
	if got := selectDisplayIP("", nil); got != "" {
		t.Fatalf("无 IP 应为空: %q", got)
	}
}

func TestFetchPublicIP(t *testing.T) {
	// 第一源返回非法体, 第二源返回合法 IP: 应回退到第二源。
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello world")) }))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9\n")) }))
	defer good.Close()
	oldURLs, oldClient := publicIPLookupURLs, publicIPHTTPClient
	publicIPLookupURLs = []string{bad.URL, good.URL}
	publicIPHTTPClient = &http.Client{Timeout: 3 * time.Second}
	defer func() { publicIPLookupURLs, publicIPHTTPClient = oldURLs, oldClient }()
	if got := fetchPublicIP(); got != "203.0.113.9" {
		t.Fatalf("应回退到第二源: %q", got)
	}
	// 全失败返回空。
	publicIPLookupURLs = []string{bad.URL}
	if got := fetchPublicIP(); got != "" {
		t.Fatalf("全失败应为空: %q", got)
	}
}

// ---------- 第 4 项: 归属地与国旗 ----------

func TestServerLocationCode(t *testing.T) {
	if got := serverLocationCode("美国", "1.2.3.4"); got != "us" {
		t.Fatalf("手动美国应得 us: %q", got)
	}
	if got := serverLocationCode("火星", "1.2.3.4"); got != "" {
		t.Fatalf("匹配不到的手动值应无旗不猜: %q", got)
	}
	// 自动路径不断言具体国家(依赖内嵌库), 只断言不返回裸大写码之外的非法值:
	// 这里用本机回环 IP: 内网无旗。
	if got := serverLocationCode("", "127.0.0.1"); got != "" {
		t.Fatalf("内网 IP 应无国旗码: %q", got)
	}
}

func TestServerLocationDisplayManualWins(t *testing.T) {
	// 手动值优先: 显示手动值本身, 绝不带自动码/自动名。
	if loc, _, _ := serverLocationDisplay("美国", "8.8.8.8"); loc != "美国" {
		t.Fatalf("手动值应原样显示: %q", loc)
	}
	if loc, _, _ := serverLocationDisplay("", "10.0.0.122"); loc != "内网" {
		t.Fatalf("私网 IP 应显示内网: %q", loc)
	}
}

// ---------- 第 1 项: 推送任务判定 ----------

func TestEvalPushJob(t *testing.T) {
	now := time.Now().Unix()
	base := &pushJob{Fingerprint: "fp1", Name: "节点", FromVersion: "v1.0.5", Target: "v1.0.6", StartedAt: now - 30}
	check := func(name, nodeVer string, gone, online bool, pState string, pAt int64, pErr string, at int64, wantState, wantSub string) {
		t.Helper()
		st, dt := evalPushJob(base, nodeVer, gone, online, pState, pAt, pErr, at)
		if st != wantState || !strings.Contains(dt, wantSub) {
			t.Fatalf("%s: 应为 %s(含 %q), 实际 %s(%q)", name, wantState, wantSub, st, dt)
		}
	}
	check("节点已移除", "", true, false, "", 0, "", now, "failed", "已移除")
	check("版本已到目标", "v1.0.6", false, true, "", 0, "", now, "done", "升级成功")
	check("已是最新", "v1.0.5", false, true, "failed", now, "当前版本已是最新", now, "done", "已是最新")
	check("节点失败透传", "v1.0.5", false, true, "failed", now, "下载失败", now, "failed", "下载失败")
	check("applying 升级中", "v1.0.5", false, true, "applying", now, "", now, "upgrading", "")
	check("宽限内离线=重启中", "v1.0.5", false, false, "", 0, "", now, "upgrading", "重启")
	check("离线超时失败", "v1.0.5", false, false, "", 0, "", now+400, "failed", "超时")
	check("在线超时失败", "v1.0.5", false, true, "", 0, "", now+400, "failed", "")
	check("陈旧 done 忽略", "v1.0.5", false, true, "done", now-100, "", now, "upgrading", "")
}

// ---------- 第 11 项: 共享名单落地 ----------

func TestSharedBanApplyRules(t *testing.T) {
	dir := banTestSetup(t)
	_ = dir
	now := time.Now().Unix()
	// 先有一条本机记录与一条 shared 记录。
	banMu.Lock()
	bans = []*Ban{
		{IP: "203.0.113.1", Source: "manual", Status: BanActive, CreatedAt: now},
		{IP: "203.0.113.2", Source: "shared", Status: BanActive, CreatedAt: now},
	}
	banMu.Unlock()
	banMu.Lock()
	added, updated, skipped := applySharedBansLocked([]syncBanEntry{
		{IP: "203.0.113.1", Status: "released"},                       // 本机条目: 跳过, 绝不动
		{IP: "203.0.113.2", Status: "released"},                       // shared: 改状态, 记录保留
		{IP: "203.0.113.3", Status: "active", Until: 0, Reason: "共享"}, // 新增
		{IP: "203.0.113.4", Status: "released"},                       // 不存在的 shared 解封: 不凭空建
	}, now)
	banMu.Unlock()
	if added != 1 || updated != 1 || skipped != 2 {
		t.Fatalf("新增/更新/跳过应为 1/1/2, 实际 %d/%d/%d", added, updated, skipped)
	}
	banMu.Lock()
	defer banMu.Unlock()
	byIP := map[string]*Ban{}
	for _, b := range bans {
		byIP[b.IP] = b
	}
	if byIP["203.0.113.1"].Status != BanActive {
		t.Fatalf("本机条目被改动: %+v", byIP["203.0.113.1"])
	}
	if byIP["203.0.113.2"].Status != BanReleased {
		t.Fatalf("shared 解封应只改状态: %+v", byIP["203.0.113.2"])
	}
	if byIP["203.0.113.3"] == nil || byIP["203.0.113.3"].Source != "shared" {
		t.Fatalf("新增 shared 记录缺失: %+v", byIP["203.0.113.3"])
	}
	if _, ok := byIP["203.0.113.4"]; ok {
		t.Fatalf("不存在的解封条目不应凭空建记录")
	}
}

func TestSyncApplyInternalHeaderRequired(t *testing.T) {
	dir := banTestSetup(t)
	oldDataDir := dataDir
	dataDir = dir
	defer func() { dataDir = oldDataDir }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()
	body := `{"blacklist":[{"ip":"203.0.113.9","status":"active","until":0,"reason":"共享"}],"whitelist":[]}`
	// 无内部头: 403, 且不落地。
	req := httptest.NewRequest("POST", "/api/sync/apply-lists", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleSyncApplyLists(rec, req)
	if rec.Code != 403 {
		t.Fatalf("无内部头应 403, 实际 %d", rec.Code)
	}
	// 有内部头: 200, 落地。
	req = httptest.NewRequest("POST", "/api/sync/apply-lists", strings.NewReader(body))
	req.Header.Set("X-Guijia-Internal", "1")
	rec = httptest.NewRecorder()
	handleSyncApplyLists(rec, req)
	if rec.Code != 200 {
		t.Fatalf("内部头应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	banMu.Lock()
	found := false
	for _, b := range bans {
		if b.IP == "203.0.113.9" && b.Source == "shared" {
			found = true
		}
	}
	banMu.Unlock()
	if !found {
		t.Fatalf("内部同步应落地 shared 记录")
	}
	// 内网 IP 经 handler 的 bannable 校验应被跳过。
	body2 := `{"blacklist":[{"ip":"10.0.0.5","status":"active","until":0}],"whitelist":[]}`
	req = httptest.NewRequest("POST", "/api/sync/apply-lists", strings.NewReader(body2))
	req.Header.Set("X-Guijia-Internal", "1")
	rec = httptest.NewRecorder()
	handleSyncApplyLists(rec, req)
	banMu.Lock()
	for _, b := range bans {
		if b.IP == "10.0.0.5" {
			banMu.Unlock()
			t.Fatalf("内网 IP 不应进共享黑名单")
		}
	}
	banMu.Unlock()
}

func TestSyncApplyGroupIsolation(t *testing.T) {
	// 回归: 单组同步绝不能动另一组。黑名单单发时白名单(设置 + 标记)纹丝不动;
	// 白名单单发时黑名单不动; 白名单显式空列表才收敛到空(缺席≠空)。
	dir := banTestSetup(t)
	oldDataDir, oldSettingFile := dataDir, settingFile
	dataDir, settingFile = dir, dir+"/settings.json"
	defer func() { dataDir, settingFile = oldDataDir, oldSettingFile }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = []string{"203.0.113.99"}
	defer func() { settings.TrustedIPs = oldTrusted }()
	saveSharedLists(sharedLists{SharedTrust: []string{"203.0.113.99"}})
	banMu.Lock()
	bans = []*Ban{{IP: "203.0.113.77", Source: "manual", Status: BanActive, CreatedAt: time.Now().Unix()}}
	banMu.Unlock()
	post := func(body string) int {
		req := httptest.NewRequest("POST", "/api/sync/apply-lists", strings.NewReader(body))
		req.Header.Set("X-Guijia-Internal", "1")
		rec := httptest.NewRecorder()
		handleSyncApplyLists(rec, req)
		return rec.Code
	}
	// 1. 只发黑名单: 白名单必须原样, 黑名单新增。
	if code := post(`{"blacklist":[{"ip":"203.0.113.55","status":"active","until":0}]}`); code != 200 {
		t.Fatalf("黑名单单发应 200, 实际 %d", code)
	}
	mu.Lock()
	trusted := append([]string{}, settings.TrustedIPs...)
	mu.Unlock()
	if len(trusted) != 1 || trusted[0] != "203.0.113.99" {
		t.Fatalf("黑名单单发后白名单应原样, 实际 %v", trusted)
	}
	if sl := loadSharedLists(); len(sl.SharedTrust) != 1 || sl.SharedTrust[0] != "203.0.113.99" {
		t.Fatalf("黑名单单发后共享标记应原样, 实际 %v", sl.SharedTrust)
	}
	// 2. 只发白名单(换一个值): 黑名单必须原样。
	if code := post(`{"whitelist":["203.0.113.100"]}`); code != 200 {
		t.Fatalf("白名单单发应 200, 实际 %d", code)
	}
	banMu.Lock()
	ips := map[string]bool{}
	for _, b := range bans {
		ips[b.IP] = true
	}
	banMu.Unlock()
	if !ips["203.0.113.55"] || !ips["203.0.113.77"] {
		t.Fatalf("白名单单发后黑名单应原样, 实际 %v", ips)
	}
	// 3. 白名单显式空列表: 收敛到空(这是“出现且为空”的正确语义)。
	if code := post(`{"whitelist":[]}`); code != 200 {
		t.Fatalf("白名单空列表应 200, 实际 %d", code)
	}
	mu.Lock()
	trusted = append([]string{}, settings.TrustedIPs...)
	mu.Unlock()
	if len(trusted) != 0 {
		t.Fatalf("白名单显式空列表应收敛到空, 实际 %v", trusted)
	}
}

func TestSharedTrustConvergence(t *testing.T) {
	dir := t.TempDir()
	oldDataDir, oldSettingFile := dataDir, settingFile
	dataDir, settingFile = dir, dir+"/settings.json"
	defer func() { dataDir, settingFile = oldDataDir, oldSettingFile }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = []string{"192.168.1.1", "203.0.113.10"}
	defer func() { settings.TrustedIPs = oldTrusted }()
	// 第一轮: 共享两条(一条已在本机, 一条新增)。
	added, removed, _, changed := applySharedTrust([]string{"192.168.1.1", "203.0.113.20"})
	if added != 1 || removed != 0 || !changed {
		t.Fatalf("第一轮应新增 1, 实际 added=%d removed=%d changed=%v", added, removed, changed)
	}
	// 第二轮: hub 列表去掉旧 shared 条目, 应收敛掉; 本机条目不动。
	added, removed, _, _ = applySharedTrust([]string{"203.0.113.30"})
	if added != 1 || removed != 1 {
		t.Fatalf("第二轮应新增 1 移除 1, 实际 added=%d removed=%d", added, removed)
	}
	mu.Lock()
	got := append([]string{}, settings.TrustedIPs...)
	mu.Unlock()
	want := map[string]bool{"192.168.1.1": true, "203.0.113.10": true, "203.0.113.30": true}
	if len(got) != 3 {
		t.Fatalf("收敛后信任名单应剩 3 条(含 2 条本机): %v", got)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Fatalf("收敛后出现不应有的条目 %q: %v", ip, got)
		}
	}
}

// ---------- 第 9 项: 备份文件名与内容标记 ----------

func TestSanitizeBackupServerName(t *testing.T) {
	if got := sanitizeBackupServerName("RN圣何塞", "abcdef12"); got != "RN圣何塞" {
		t.Fatalf("CJK 与字母应保留: %q", got)
	}
	if got := sanitizeBackupServerName("a/b\\c:d", "abcdef12"); strings.ContainsAny(got, "/\\:") {
		t.Fatalf("路径分隔符必须被替换: %q", got)
	}
	if got := sanitizeBackupServerName("", "abcdef12"); got != "abcdef12" {
		t.Fatalf("空名应回落指纹前 8: %q", got)
	}
	if got := sanitizeBackupServerName("   ", ""); got != "node" {
		t.Fatalf("空名空指纹应回落 node: %q", got)
	}
}

func TestBackupExportCarriesServerName(t *testing.T) {
	dir := banTestSetup(t)
	_ = dir
	oldName := settings.ServerName
	settings.ServerName = "节点标记-TEST123"
	defer func() { settings.ServerName = oldName }()
	// 数据备份 zip 里 bans.json 应含种子封禁(节点标记)。
	banMu.Lock()
	bans = []*Ban{{IP: "203.0.113.77", Source: "manual", Status: BanActive, CreatedAt: time.Now().Unix()}}
	banMu.Unlock()
	saveBans() // 数据备份读 bans.json 文件, 不是内存
	zb, err := buildDataBackup()
	if err != nil {
		t.Fatalf("buildDataBackup 失败: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatalf("zip 解析失败: %v", err)
	}
	found := false
	for _, f := range zr.File {
		if f.Name == "bans.json" {
			rc, _ := f.Open()
			var arr []map[string]any
			if err := json.NewDecoder(rc).Decode(&arr); err == nil {
				for _, b := range arr {
					if b["ip"] == "203.0.113.77" {
						found = true
					}
				}
			}
			rc.Close()
		}
	}
	if !found {
		t.Fatalf("数据备份 bans.json 里应有种子封禁 203.0.113.77")
	}
}
