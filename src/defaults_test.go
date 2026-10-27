package main

import (
	"os"
	"path/filepath"
	"testing"
)

// freshInstallSetup: 把 loadAll 的全部文件变量指到空临时目录，并保存/恢复全局态。
func freshInstallSetup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldDir, oldPortsFile, oldSettingFile, oldBansFile, oldPortBansFile, oldStatsFile := dataDir, portsFile, settingFile, bansFile, portBansFile, statsFile
	oldRescueFile, oldHoneypotFile, oldProxyFile, oldAuthFile := rescueFile, honeypotFile, proxyFile, authFile
	oldEventsDir, oldEventsSrcDir := eventsDir, eventsSrcDir
	oldSettings, oldPorts, oldRanges, oldIgnored, oldIgnoredRanges := settings, ports, portRanges, ignoredPorts, ignoredRanges
	oldPgRules, oldHoneypot := pgRules, honeypotCfg
	t.Cleanup(func() {
		dataDir, portsFile, settingFile, bansFile, portBansFile, statsFile = oldDir, oldPortsFile, oldSettingFile, oldBansFile, oldPortBansFile, oldStatsFile
		rescueFile, honeypotFile, proxyFile, authFile = oldRescueFile, oldHoneypotFile, oldProxyFile, oldAuthFile
		eventsDir, eventsSrcDir = oldEventsDir, oldEventsSrcDir
		settings, ports, portRanges, ignoredPorts, ignoredRanges = oldSettings, oldPorts, oldRanges, oldIgnored, oldIgnoredRanges
		pgRules, honeypotCfg = oldPgRules, oldHoneypot
	})
	dataDir = dir
	portsFile = filepath.Join(dir, "ports.json")
	settingFile = filepath.Join(dir, "settings.json")
	bansFile = filepath.Join(dir, "bans.json")
	portBansFile = filepath.Join(dir, "portbans.json")
	statsFile = filepath.Join(dir, "stats.json")
	rescueFile = filepath.Join(dir, "rescue.json")
	honeypotFile = filepath.Join(dir, "honeypot.json")
	proxyFile = filepath.Join(dir, "proxy.json")
	authFile = filepath.Join(dir, "auth.json")
	eventsDir = filepath.Join(dir, "events")
	eventsSrcDir = filepath.Join(dir, "events-src")
	settings = defaultSettings()
	ports = nil
	portRanges = nil
	ignoredPorts = map[int]bool{}
	ignoredRanges = nil
	pgRules = nil
	return dir
}

// TestFreshInstallProtectionsOff: 新装（无文件）五种防护全关。
func TestFreshInstallProtectionsOff(t *testing.T) {
	freshInstallSetup(t)
	loadAll()
	if settings.AutoBanEnabled || settings.ScanEnabled || settings.FloodEnabled {
		t.Errorf("新装五种防护应全关，得到 autoBan=%v scan=%v flood=%v",
			settings.AutoBanEnabled, settings.ScanEnabled, settings.FloodEnabled)
	}
	if honeypotCfg.Enabled {
		t.Error("新装蜜罐应默认关")
	}
	pgMu.Lock()
	n := len(pgRules)
	pgMu.Unlock()
	if n != 0 {
		t.Errorf("新装防火墙应无默认规则，得到 %d 条", n)
	}
	if settings.FloodWindowMin != 1 || settings.FloodDistinctIPs != 30 || settings.FloodCloseMin != 60 {
		t.Errorf("洪峰数值应取新默认值 1/30/60，得到 %d/%d/%d",
			settings.FloodWindowMin, settings.FloodDistinctIPs, settings.FloodCloseMin)
	}
}

// TestOldSettingsFilePreservesSwitches: 已有文件里明确为 true 的开关不被新默认值覆盖；
// 缺洪峰字段的旧文件只补数值，开关保持默认关。
func TestOldSettingsFilePreservesSwitches(t *testing.T) {
	dir := freshInstallSetup(t)
	// 旧文件：三开关明确 true，洪峰数值全 0（旧版无洪峰字段的形态）。
	if err := os.WriteFile(filepath.Join(dir, "settings.json"),
		[]byte(`{"autoBanEnabled":true,"scanEnabled":true,"floodEnabled":true,"floodWindowMin":0,"floodDistinctIps":0,"floodCloseMin":0}`), 0644); err != nil {
		t.Fatal(err)
	}
	loadAll()
	if !settings.AutoBanEnabled || !settings.ScanEnabled || !settings.FloodEnabled {
		t.Errorf("文件里明确 true 的开关应保持 true，得到 autoBan=%v scan=%v flood=%v",
			settings.AutoBanEnabled, settings.ScanEnabled, settings.FloodEnabled)
	}
	if settings.FloodWindowMin != 1 || settings.FloodDistinctIPs != 30 || settings.FloodCloseMin != 60 {
		t.Errorf("洪峰数值应回填 1/30/60，得到 %d/%d/%d",
			settings.FloodWindowMin, settings.FloodDistinctIPs, settings.FloodCloseMin)
	}

	// 旧文件：只有 autoBan true，洪峰字段全缺 → 洪峰开关保持默认关，数值取默认值。
	dir2 := freshInstallSetup(t)
	if err := os.WriteFile(filepath.Join(dir2, "settings.json"),
		[]byte(`{"autoBanEnabled":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	loadAll()
	if !settings.AutoBanEnabled {
		t.Error("文件里 autoBan true 应保持 true")
	}
	if settings.FloodEnabled {
		t.Error("缺洪峰字段的旧文件，洪峰开关应保持默认关，绝不能被回填强制写回 true")
	}
	if settings.FloodWindowMin != 1 || settings.FloodDistinctIPs != 30 || settings.FloodCloseMin != 60 {
		t.Errorf("洪峰数值应回填 1/30/60，得到 %d/%d/%d",
			settings.FloodWindowMin, settings.FloodDistinctIPs, settings.FloodCloseMin)
	}
}

// TestDefaultSettingsFiveOff: defaultSettings 本身五项全关（新装的唯一事实来源）。
func TestDefaultSettingsFiveOff(t *testing.T) {
	s := defaultSettings()
	if s.AutoBanEnabled || s.ScanEnabled || s.FloodEnabled {
		t.Errorf("defaultSettings 五种防护应全关，得到 autoBan=%v scan=%v flood=%v",
			s.AutoBanEnabled, s.ScanEnabled, s.FloodEnabled)
	}
}
