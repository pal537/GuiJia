package main

// 防护同步回归(2026-10-28, PAPA 三点之三):
// 勾选项应用主服务器配置、未勾选项恢复本地可改、整组关闭推释放包、
// 脱离清标记、被控节点本地改已同步项被 403。

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func protSyncTestSetup(t *testing.T) string {
	t.Helper()
	dir := banTestSetup(t)
	oldData, oldSetting := dataDir, settingFile
	oldSettings := settings
	oldProt := protSyncSnapshot()
	oldIntel := intelState
	dataDir = dir
	settingFile = filepath.Join(dir, "settings.json")
	settings = defaultSettings()
	settings.TrafficAcct = false
	intelState = IntelState{UpdatesPerDay: 4, Status: "never", PublicURL: intelDefaultPublicURL}
	protSyncMu.Lock()
	protSyncState = protSyncFlags{}
	protSyncMu.Unlock()
	t.Cleanup(func() {
		dataDir, settingFile = oldData, oldSetting
		settings = oldSettings
		intelState = oldIntel
		protSyncMu.Lock()
		protSyncState = oldProt
		protSyncMu.Unlock()
	})
	return dir
}

func TestProtSyncApplyAndRelease(t *testing.T) {
	protSyncTestSetup(t)
	mu.Lock()
	settings.FloodEnabled = false
	settings.AutoBanEnabled = false
	settings.ScanEnabled = false
	mu.Unlock()

	// 勾选 flood + scan: 两项应用主服务器值, autoban/intel 标记为未同步。
	p := protSyncPayload{
		Flood:   protFloodCfg{Synced: true, Enabled: true, WindowMin: 2, DistinctIPs: 50, CloseMin: 30},
		Autoban: protAutobanCfg{Synced: false},
		Scan:    protScanCfg{Synced: true, Enabled: true, AutoBan: true, WindowMin: 3, DistinctPorts: 8},
		Intel:   protIntelCfg{Synced: false},
	}
	applied := applyProtSyncPayload(p)
	if len(applied) != 2 || applied[0] != "flood" || applied[1] != "scan" {
		t.Fatalf("应用项应为 [flood scan], 实际 %v", applied)
	}
	mu.Lock()
	fl, sc := settings.FloodEnabled, settings.ScanEnabled
	fw, fi, fc := settings.FloodWindowMin, settings.FloodDistinctIPs, settings.FloodCloseMin
	mu.Unlock()
	if !fl || fw != 2 || fi != 50 || fc != 30 || !sc {
		t.Fatalf("flood/scan 配置未按主服务器值落地: flood=%v %d/%d/%d scan=%v", fl, fw, fi, fc, sc)
	}
	flags := protSyncSnapshot()
	if !flags.Flood || flags.Autoban || !flags.Scan || flags.Intel {
		t.Fatalf("标记应为 flood+scan, 实际 %+v", flags)
	}

	// 释放包(整组关闭): 四项标记全清, 配置值不动(只恢复控制权)。
	applyProtSyncPayload(protSyncReleasePayload())
	flags = protSyncSnapshot()
	if flags.Flood || flags.Autoban || flags.Scan || flags.Intel {
		t.Fatalf("释放后标记应全清, 实际 %+v", flags)
	}
	mu.Lock()
	fl2 := settings.FloodEnabled
	mu.Unlock()
	if !fl2 {
		t.Fatal("释放包不应改动配置值, 只恢复控制权")
	}
}

func TestProtSyncApplyIntelDisabled(t *testing.T) {
	protSyncTestSetup(t)
	intelMu.Lock()
	intelState.Enabled = true
	intelMu.Unlock()
	p := protSyncPayload{Intel: protIntelCfg{Synced: true, Enabled: false, PublicURL: intelDefaultPublicURL, UpdatesPerDay: 4}}
	applied := applyProtSyncPayload(p)
	if len(applied) != 1 || applied[0] != "intel" {
		t.Fatalf("情报项应应用, 实际 %v", applied)
	}
	intelMu.Lock()
	en := intelState.Enabled
	intelMu.Unlock()
	if en {
		t.Fatal("情报同步关应落到节点")
	}
	if !protSyncSnapshot().Intel {
		t.Fatal("情报标记应为已同步")
	}
}

func TestGroupSyncProtectionSaveAndRelease(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	gsMu.Lock()
	oldCfg, oldTicker := gsCfg, gsTicker
	gsCfg = groupSyncFile{
		Blacklist:  groupSyncCfg{IntervalMin: 10},
		Whitelist:  groupSyncCfg{IntervalMin: 10},
		Protection: groupSyncCfg{IntervalMin: 10},
	}
	gsMu.Unlock()
	defer func() {
		gsMu.Lock()
		gsCfg, gsTicker = oldCfg, oldTicker
		gsMu.Unlock()
	}()

	// 保存开启 + 勾选两项: 配置落盘且 items 回显。
	req := httptest.NewRequest("POST", "/api/group-sync/settings", bytes.NewBufferString(`{"group":"protection","enabled":true,"intervalMin":10,"items":{"flood":true,"autoban":false,"scan":true,"intel":false}}`))
	rec := httptest.NewRecorder()
	handleGroupSyncSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("防护组保存应 200, 实际 %d", rec.Code)
	}
	gsMu.Lock()
	it := gsCfg.ProtItems
	gsMu.Unlock()
	if !it.Flood || it.Autoban || !it.Scan || it.Intel {
		t.Fatalf("勾选项落盘不对: %+v", it)
	}

	// 保存关闭整组: 必须立即触发释放同步(无节点时记 failed 即证明触发,
	// 不能等——关了就没有下一趟 ticker)。
	req = httptest.NewRequest("POST", "/api/group-sync/settings", bytes.NewBufferString(`{"group":"protection","enabled":false,"intervalMin":10,"items":{"flood":false,"autoban":false,"scan":false,"intel":false}}`))
	rec = httptest.NewRecorder()
	handleGroupSyncSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("防护组关闭保存应 200, 实际 %d", rec.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		gsMu.Lock()
		st := gsCfg.Protection.LastStatus
		gsMu.Unlock()
		if st != "" {
			if st != "failed" {
				t.Fatalf("无节点释放同步应记 failed, 得到 %q", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("关闭整组后 5 秒内未触发释放同步")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSettingsPutProtGuard(t *testing.T) {
	protSyncTestSetup(t)
	mu.Lock()
	settings.RunMode = "managed"
	settings.FloodEnabled = true
	settings.FloodWindowMin = 2
	mu.Unlock()
	protSyncMu.Lock()
	protSyncState = protSyncFlags{Flood: true}
	protSyncMu.Unlock()

	// 改已同步的 flood 值 -> 403 点名。
	req := httptest.NewRequest("PUT", "/api/settings", bytes.NewBufferString(`{"floodWindowMin":5}`))
	rec := httptest.NewRecorder()
	handleSettings(rec, req)
	if rec.Code != 403 {
		t.Fatalf("改已同步项应 403, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "洪峰") {
		t.Fatalf("403 应点名洪峰项, 实际 %s", rec.Body.String())
	}
	// 不改 flood、只改无关项 -> 通过。
	req = httptest.NewRequest("PUT", "/api/settings", bytes.NewBufferString(`{"logKeepDays":15}`))
	rec = httptest.NewRecorder()
	handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("无关项保存应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProtSyncedCSS(t *testing.T) {
	html := string(indexHTML)
	// 层叠断言(不只规则存在): 已同步卡片隐藏除标题与提示外的全部子元素。
	if !strings.Contains(html, ".scard.synced>:not(h3):not(.syncnote){display:none}") {
		t.Fatal("缺少已同步卡片隐藏规则 .scard.synced>:not(h3):not(.syncnote)")
	}
	for _, id := range []string{"cardFlood", "cardAutoban", "cardScan", "cardIntel"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Fatalf("缺少防护卡片 %s", id)
		}
	}
	if strings.Count(html, "已与主服务器同步") < 4 {
		t.Fatal("四张防护卡片都应有“已与主服务器同步”提示")
	}
}
