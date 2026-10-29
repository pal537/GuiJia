package main

import (
	"path/filepath"
	"testing"
)

// 弹窗式设置保存: TG/流量/日报三个弹窗只 PUT 本组键, 其余组键必须原样保留
// (弹窗关闭时控件不在页内, 前端收集会跳过, 后端 PUT 缺失键同样保留)。
func TestSettingsModalSectionPutPreservesOthers(t *testing.T) {
	authTestSetup(t)
	dir := t.TempDir()
	oldSettingFile, oldAcctState, oldPort := settingFile, acctStatePath, panelPort
	settingFile = filepath.Join(dir, "settings.json")
	acctStatePath = "" // 不碰内核开关
	panelPort = 15988
	t.Cleanup(func() { settingFile, acctStatePath, panelPort = oldSettingFile, oldAcctState, oldPort })

	mu.Lock()
	settings = defaultSettings()
	settings.TGEnabled = true
	settings.TGBotToken = "tok-orig"
	settings.TGChatID = "111"
	settings.TrafficAcct = true
	settings.LedgerKeepDays = 7
	settings.ReportEnabled = true
	settings.ReportTime = "09:00"
	settings.LogKeepDays = 30
	settings.NewSrcKeepDays = 3
	mu.Unlock()

	check := func(wantTG bool, wantTok, wantChat string, wantAcct bool, wantLedger int, wantRep bool, wantTime string, wantKeep, wantSrc int) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if settings.TGEnabled != wantTG || settings.TGBotToken != wantTok || settings.TGChatID != wantChat {
			t.Errorf("TG 组应为 %v/%q/%q, 得到 %v/%q/%q", wantTG, wantTok, wantChat, settings.TGEnabled, settings.TGBotToken, settings.TGChatID)
		}
		if settings.TrafficAcct != wantAcct || settings.LedgerKeepDays != wantLedger {
			t.Errorf("流量组应为 %v/%d, 得到 %v/%d", wantAcct, wantLedger, settings.TrafficAcct, settings.LedgerKeepDays)
		}
		if settings.ReportEnabled != wantRep || settings.ReportTime != wantTime || settings.LogKeepDays != wantKeep || settings.NewSrcKeepDays != wantSrc {
			t.Errorf("日报组应为 %v/%q/%d/%d, 得到 %v/%q/%d/%d", wantRep, wantTime, wantKeep, wantSrc, settings.ReportEnabled, settings.ReportTime, settings.LogKeepDays, settings.NewSrcKeepDays)
		}
	}

	// 只 PUT TG 组: 流量与日报键必须保留。
	rec := doJSON(t, handleSettings, "PUT", "/api/settings", `{"tgEnabled":false,"tgBotToken":"tok-new","tgChatId":"222"}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("TG 组 PUT 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	check(false, "tok-new", "222", true, 7, true, "09:00", 30, 3)

	// 只 PUT 流量组: TG 与日报键必须保留。
	rec = doJSON(t, handleSettings, "PUT", "/api/settings", `{"trafficAcct":false,"ledgerKeepDays":0}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("流量组 PUT 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	check(false, "tok-new", "222", false, 0, true, "09:00", 30, 3)

	// 只 PUT 日报组: TG 与流量键必须保留。
	rec = doJSON(t, handleSettings, "PUT", "/api/settings", `{"reportEnabled":false,"reportTime":"08:30","logKeepDays":14,"newSrcKeepDays":0}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("日报组 PUT 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	check(false, "tok-new", "222", false, 0, false, "08:30", 14, 0)
}
