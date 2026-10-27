package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCliMainUsage(t *testing.T) {
	if code := cliMain([]string{"bogus"}); code != 2 {
		t.Errorf("未知命令应退出 2, 得到 %d", code)
	}
	if code := cliMain([]string{"unban"}); code != 2 {
		t.Errorf("unban 缺 IP 应退出 2, 得到 %d", code)
	}
	if code := cliMain([]string{"unban", "not-an-ip"}); code != 2 {
		t.Errorf("unban 非法 IP 应退出 2, 得到 %d", code)
	}
}

func TestCliCertOff(t *testing.T) {
	authTestSetup(t)
	dir := t.TempDir()
	oldSettingFile := settingFile
	settingFile = filepath.Join(dir, "settings.json")
	t.Cleanup(func() { settingFile = oldSettingFile })
	mu.Lock()
	settings = defaultSettings()
	settings.PanelSSLMode = "port"
	settings.PanelSSLCert = "upload:x"
	mu.Unlock()
	saveSettings()
	if code := cliCertOff(); code != 0 {
		t.Fatalf("cert-off 应退出 0, 得到 %d", code)
	}
	b, _ := os.ReadFile(settingFile)
	if string(b) == "" {
		t.Fatal("设置文件应写盘")
	}
	mu.Lock()
	mode := settings.PanelSSLMode
	mu.Unlock()
	if mode != "off" {
		t.Errorf("cert-off 后模式应为 off, 得到 %q", mode)
	}
}

func TestCliResetPasswordCore(t *testing.T) {
	authTestSetup(t)
	if err := cliResetPasswordCore("StrongPass1!xx", "Different2@yy"); err == nil {
		t.Error("两次不一致应报错")
	}
	if err := cliResetPasswordCore("weak", "weak"); err == nil {
		t.Error("弱密码应报错")
	}
	if err := cliResetPasswordCore("StrongPass1!xx", "StrongPass1!xx"); err != nil {
		t.Fatalf("合法密码应成功: %v", err)
	}
	authMu.Lock()
	h := auth.PassHash
	gen := auth.SessionGen
	authMu.Unlock()
	if !verifyRescuePassword("StrongPass1!xx", h) {
		t.Error("重置后的哈希应能验证新密码")
	}
	if gen != 1 {
		t.Errorf("重置应抬代次, 得到 %d", gen)
	}
}

func TestCliUnban(t *testing.T) {
	authTestSetup(t)
	if code := cliUnban("203.0.113.50"); code != 1 {
		t.Errorf("无封禁时 unban 应退出 1, 得到 %d", code)
	}
	if _, err := applyBan("203.0.113.50", "测试封禁", "manual", 24); err != nil {
		t.Fatalf("applyBan: %v", err)
	}
	if !isGloballyBanned("203.0.113.50") {
		t.Fatal("封禁应生效")
	}
	if code := cliUnban("203.0.113.50"); code != 0 {
		t.Errorf("有封禁时 unban 应退出 0, 得到 %d", code)
	}
	if isGloballyBanned("203.0.113.50") {
		t.Error("unban 后不应再是封禁态")
	}
	// 记录保留(只改状态)
	found := false
	for _, b := range allBans() {
		if b.IP == "203.0.113.50" && b.Status == BanReleased {
			found = true
		}
	}
	if !found {
		t.Error("unban 后记录应保留为已解封态, 而非删除")
	}
}
