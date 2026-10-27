package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// 设置保存按字段合并: UI 不再提交的键(如面板 SSL 四项)必须保持原值, 绝不清零。
func TestSettingsPutPreservesUnsubmittedSSL(t *testing.T) {
	authTestSetup(t)
	dir := t.TempDir()
	oldSettingFile, oldAcctState, oldPort := settingFile, acctStatePath, panelPort
	settingFile = filepath.Join(dir, "settings.json")
	acctStatePath = "" // restoreTrafficAcct 直接返回, 不碰内核开关
	panelPort = 15987
	t.Cleanup(func() { settingFile, acctStatePath, panelPort = oldSettingFile, oldAcctState, oldPort })

	mu.Lock()
	settings = defaultSettings()
	settings.PanelSSLMode = "port"
	settings.PanelSSLCert = "upload:x"
	settings.PanelSSLPort = 59999
	settings.PanelDomain = "old.example.com"
	settings.PanelBanThreshold = 7
	settings.TrafficAcct = false
	mu.Unlock()

	// PUT 不带 SSL 键: 只改封禁次数, SSL 四项必须原样保留(即使旧证书已不可用也不卡住)。
	rec := doJSON(t, handleSettings, "PUT", "/api/settings", `{"panelBanThreshold":9}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("PUT 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	mode, cert, port, domain, thr := settings.PanelSSLMode, settings.PanelSSLCert, settings.PanelSSLPort, settings.PanelDomain, settings.PanelBanThreshold
	mu.Unlock()
	if mode != "port" || cert != "upload:x" || port != 59999 || domain != "old.example.com" {
		t.Errorf("未提交的 SSL 字段应保持原值, 得到 mode=%q cert=%q port=%d domain=%q", mode, cert, port, domain)
	}
	if thr != 9 {
		t.Errorf("封禁次数应更新为 9, 得到 %d", thr)
	}

	// PUT 带 SSL 键: 应正常更新。
	rec = doJSON(t, handleSettings, "PUT", "/api/settings", `{"panelSslMode":"off","panelBanThreshold":5}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("带 SSL 键的 PUT 应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	mode = settings.PanelSSLMode
	mu.Unlock()
	if mode != "off" {
		t.Errorf("提交了 SSL 键时模式应更新为 off, 得到 %q", mode)
	}

	// GET 应带面板实际监听端口。
	rec = doJSON(t, handleSettings, "GET", "/api/settings", "", "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("GET 应 200, 得到 %d", rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if pp, _ := m["panelPort"].(float64); int(pp) != 15987 {
		t.Errorf("GET 应含 panelPort=15987, 得到 %v", m["panelPort"])
	}
}
