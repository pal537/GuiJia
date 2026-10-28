package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFwBanPermanent: 防火墙封禁一律永久(Until=0), 不按时间过期。
func TestFwBanPermanent(t *testing.T) {
	dir := banTestSetup(t)
	oldEvents := eventsDir
	eventsDir = filepath.Join(dir, "events")
	os.MkdirAll(eventsDir, 0755)
	defer func() { eventsDir = oldEvents }()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()

	ip := "203.0.113.80"
	b, fresh, err := applyRuleBan(ip, "防火墙永久测试", "portguard", "gtest", [][2]int{{8443, 8443}})
	if err != nil || !fresh || b == nil {
		t.Fatalf("applyRuleBan = %v, %v, %v", b, fresh, err)
	}
	if b.Until != 0 {
		t.Fatalf("防火墙封禁必须永久(Until=0), 实际 %d", b.Until)
	}
	if !b.enforced(time.Now().AddDate(10, 0, 0).Unix()) {
		t.Fatal("永久封禁在 10 年后仍应生效")
	}
}

// TestReleaseRuleBans: 规则禁用/删除释放其封禁, 多规则并存时只摘该规则。
func TestReleaseRuleBans(t *testing.T) {
	banTestSetup(t)
	oldTrusted, oldLAN := settings.TrustedIPs, settings.TrustLAN
	settings.TrustedIPs, settings.TrustLAN = nil, false
	defer func() { settings.TrustedIPs, settings.TrustLAN = oldTrusted, oldLAN }()
	ipA, ipB := "203.0.113.81", "203.0.113.82"
	if _, _, err := applyRuleBan(ipA, "规则A", "portguard", "ruleA", [][2]int{{8443, 8443}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyRuleBan(ipB, "规则A", "portguard", "ruleA", [][2]int{{8443, 8443}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyRuleBan(ipB, "规则B", "portguard", "ruleB", [][2]int{{9000, 9000}}); err != nil {
		t.Fatal(err)
	}
	releaseRuleBans("ruleA")
	byIP := map[string]*Ban{}
	for _, b := range allBans() {
		byIP[b.IP] = b
	}
	if byIP[ipA].Status != BanReleased {
		t.Fatalf("仅归属规则A的记录应 released, 实际 %+v", byIP[ipA])
	}
	if isBanned(ipA) {
		t.Fatal("释放后 ipA 不应再封禁")
	}
	if byIP[ipB].Status != BanActive || len(byIP[ipB].Scopes) != 1 || byIP[ipB].Scopes[0].RuleID != "ruleB" {
		t.Fatalf("多规则记录应保持生效且只剩规则B: %+v", byIP[ipB])
	}
	if !isBannedFor(ipB, 9000) || isBannedFor(ipB, 8443) {
		t.Fatal("释放规则A后 ipB 应只封 9000")
	}
	// 释放不存在的规则不影响任何记录。
	releaseRuleBans("ruleX")
	if byIP[ipB].Status != BanActive {
		t.Fatal("释放无关规则不应动其他记录")
	}
}

// TestFwDisableDeleteReleaseAPI: PUT 禁用与 DELETE 经接口释放规则封禁; 重启用后下次命中再封禁。
func TestFwDisableDeleteReleaseAPI(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	oldTrusted, oldLAN := settings.TrustedIPs, settings.TrustLAN
	settings.TrustedIPs, settings.TrustLAN = nil, false
	defer func() { settings.TrustedIPs, settings.TrustLAN = oldTrusted, oldLAN }()
	pgMu.Lock()
	pgRules = []*PortGuardRule{
		{ID: "g1", PortText: "8443", Proto: "tcp", Source: FWSource{Kind: "all"}, Action: "deny", Enabled: true, ranges: [][2]int{{8443, 8443}}},
	}
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	ip := "203.0.113.83"
	if _, _, err := applyRuleBan(ip, "规则封禁", "portguard", "g1", [][2]int{{8443, 8443}}); err != nil {
		t.Fatal(err)
	}
	put := func(body string) int {
		req := httptest.NewRequest("PUT", "/api/portguard/g1", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handlePortGuardItem(rec, req)
		return rec.Code
	}
	if code := put(`{"enabled":false}`); code != 200 {
		t.Fatalf("禁用应 200, 实际 %d", code)
	}
	if isBanned(ip) {
		t.Fatal("禁用规则后其封禁应释放")
	}
	found := false
	for _, b := range allBans() {
		if b.IP == ip && b.Status == BanReleased {
			found = true
		}
	}
	if !found {
		t.Fatal("禁用释放后记录必须保留且状态为 released")
	}
	// 重启用: 不自动恢复封禁, 下次命中再封。
	if code := put(`{"enabled":true}`); code != 200 {
		t.Fatalf("启用应 200, 实际 %d", code)
	}
	if isBanned(ip) {
		t.Fatal("重启用不应自动恢复已释放的封禁")
	}
	if _, fresh, err := applyRuleBan(ip, "重命中", "portguard", "g1", [][2]int{{8443, 8443}}); err != nil || !fresh {
		t.Fatalf("重启用后下次命中应再封禁: %v %v", fresh, err)
	}
	if !isBanned(ip) {
		t.Fatal("重命中后应再次生效")
	}
	// 删除规则同样释放。
	req := httptest.NewRequest("DELETE", "/api/portguard/g1", nil)
	rec := httptest.NewRecorder()
	handlePortGuardItem(rec, req)
	if rec.Code != 200 {
		t.Fatalf("删除应 200, 实际 %d", rec.Code)
	}
	if isBanned(ip) {
		t.Fatal("删除规则后其封禁应释放")
	}
}

// TestMigrateFwBans: 升级迁移 — 现存生效防火墙封禁转永久并挂现行规则, 无覆盖的释放。
func TestMigrateFwBans(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	now := time.Now().Unix()
	future := now + 24*3600
	bansJSON, _ := json.Marshal([]*Ban{
		{IP: "203.0.113.90", Until: future, Reason: "旧拒绝命中", Source: "portguard", Status: BanActive, Scopes: []BanScope{{RuleID: "oldRule", Ranges: [][2]int{{8443, 8443}}}}},
		{IP: "203.0.113.91", Until: future, Reason: "旧允许缺省", Source: "portguard", Status: BanActive, Scopes: []BanScope{{RuleID: "oldRule", Ranges: [][2]int{{9000, 9000}}}}},
		{IP: "203.0.113.92", Until: future, Reason: "旧无覆盖", Source: "portguard", Status: BanActive, Scopes: []BanScope{{RuleID: "oldRule", Ranges: [][2]int{{9999, 9999}}}}},
		{IP: "203.0.113.93", Until: future, Reason: "旧 Ports 遗留", Source: "portguard", Status: BanActive, Ports: []int{8443}},
		{IP: "203.0.113.94", Until: now - 3600, Reason: "已过期不动", Source: "portguard", Status: BanActive},
		{IP: "203.0.113.95", Until: future, Reason: "手动拉黑不动", Source: "manual", Status: BanActive},
	})
	os.WriteFile(filepath.Join(dir, "bans.json"), bansJSON, 0644)
	loadBans()
	rulesJSON := `[{"id":"deny1","portText":"8443","proto":"tcp","source":{"kind":"all"},"action":"deny","enabled":true},{"id":"allow1","portText":"9000","proto":"tcp","source":{"kind":"all"},"action":"allow","enabled":true}]`
	os.WriteFile(filepath.Join(dir, "portguard.json"), []byte(rulesJSON), 0644)
	loadPortGuard()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()
	byIP := map[string]*Ban{}
	for _, b := range allBans() {
		byIP[b.IP] = b
	}
	// 拒绝规则覆盖: 转永久并挂拒绝规则。
	if b := byIP["203.0.113.90"]; b.Status != BanActive || b.Until != 0 || len(b.Scopes) != 1 || b.Scopes[0].RuleID != "deny1" {
		t.Fatalf("拒绝覆盖应转永久挂 deny1: %+v", b)
	}
	// 允许规则覆盖: 转永久并挂允许规则。
	if b := byIP["203.0.113.91"]; b.Status != BanActive || b.Until != 0 || len(b.Scopes) != 1 || b.Scopes[0].RuleID != "allow1" {
		t.Fatalf("允许覆盖应转永久挂 allow1: %+v", b)
	}
	// 无覆盖: 释放。
	if b := byIP["203.0.113.92"]; b.Status != BanReleased {
		t.Fatalf("无覆盖应释放: %+v", b)
	}
	// 旧 Ports: 按端口挂到拒绝规则, Ports 清掉。
	if b := byIP["203.0.113.93"]; b.Status != BanActive || b.Until != 0 || len(b.Scopes) != 1 || b.Scopes[0].RuleID != "deny1" || len(b.Ports) != 0 {
		t.Fatalf("旧 Ports 应转永久挂 deny1 且清 Ports: %+v", b)
	}
	// 已过期: 保持 expired, 不动。
	if b := byIP["203.0.113.94"]; b.Status != BanExpired {
		t.Fatalf("已过期应保持 expired: %+v", b)
	}
	// 非防火墙: 完全不动。
	if b := byIP["203.0.113.95"]; b.Status != BanActive || b.Until != future {
		t.Fatalf("手动封禁不应被迁移动: %+v", b)
	}
}

// TestAlertSaveOnlyAlertKeys: 通知配置弹窗只 PUT 报警键时, 其他设置项必须原样保留。
func TestAlertSaveOnlyAlertKeys(t *testing.T) {
	oldS := settings
	defer func() { settings = oldS }()
	settings.TGEnabled = true
	settings.BruteThreshold = 7
	settings.AlertSSHLogin = false
	body := `{"alertSshLogin":true,"alertSshBrute":true}`
	req := httptest.NewRequest("PUT", "/api/settings", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("PUT 应 200, 实际 %d", rec.Code)
	}
	if !settings.AlertSSHLogin || !settings.AlertSSHBrute {
		t.Fatal("报警键应已更新")
	}
	if !settings.TGEnabled || settings.BruteThreshold != 7 {
		t.Fatalf("非报警键必须原样保留: tg=%v thr=%d", settings.TGEnabled, settings.BruteThreshold)
	}
}

// TestFw11ModalUI: 弹窗白色、表单统一、新弹窗入口与旧平铺消失。
func TestFw11ModalUI(t *testing.T) {
	html := unifyHTML(t)
	must := []string{
		".cmcard{background:#fff",
		"#pop{position:absolute;width:320px;background:#fff",
		".cmcard .fld label{color:#3f4c5f",
		".cmcard .csub,.cmcard .fld .hint{color:#5b6b80",
		".msgbox{border:1px solid var(--line);background:#fff",
		".msel-row{display:grid;grid-template-columns:20px 1fr",
		"input:not([type=checkbox]):not([type=radio]):not([type=file]),select{height:36px",
		".statbox{display:inline-flex",
		`id="btnAlertCfg"`,
		`id="btnNodeAlertCfg"`,
		`id="btnCleanupCfg"`,
		`id="btnBackupCfg"`,
		"openAlertModal",
		"openCleanupModal",
		"openBackupModal",
		"在线节点 '+on.length+' 台",
	}
	for _, s := range must {
		if !strings.Contains(html, s) {
			t.Errorf("下发 HTML 缺 %q", s)
		}
	}
	mustNot := []string{
		".cmcard{background:color-mix",
		"#pop{background:color-mix",
		`id="alertRows"`,
		`data-clear="`,
		`id="btnDlSettings"`,
		`id="btnUpSettings"`,
		`id="fwHours"`,
		"当前 '+on.length+' 台在线节点",
	}
	for _, s := range mustNot {
		if strings.Contains(html, s) {
			t.Errorf("下发 HTML 不应再有 %q", s)
		}
	}
}
