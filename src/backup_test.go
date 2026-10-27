package main

// 第 9 项回归测试: 备份与恢复(设置/数据分开、快照、版本警告、zip-slip 拒绝)。

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func backupTestSetup(t *testing.T) string {
	t.Helper()
	banTestSetup(t) // 干跑 + bansFile 重定向(后续再覆盖到本测试的数据目录)
	dir := t.TempDir()
	old := struct {
		dataDir, settingFile, portsFile, bansFile, statsFile, eventsDir, eventsSrcDir, honeypotFile, ledgerTotalFile, ledgerGenFile, ledgerDayDir string
	}{dataDir, settingFile, portsFile, bansFile, statsFile, eventsDir, eventsSrcDir, honeypotFile, ledgerTotalFile, ledgerGenFile, ledgerDayDir}
	dataDir = dir
	settingFile = filepath.Join(dir, "settings.json")
	portsFile = filepath.Join(dir, "ports.json")
	bansFile = filepath.Join(dir, "bans.json")
	statsFile = filepath.Join(dir, "stats.json")
	eventsDir = filepath.Join(dir, "events")
	eventsSrcDir = filepath.Join(dir, "events-src")
	honeypotFile = filepath.Join(dir, "honeypot.json")
	ledgerTotalFile = filepath.Join(dir, "ledger-total.json")
	ledgerGenFile = filepath.Join(dir, "ledger-gen.json")
	ledgerDayDir = filepath.Join(dir, "ledger")
	os.MkdirAll(eventsDir, 0755)
	os.MkdirAll(eventsSrcDir, 0755)
	os.MkdirAll(ledgerDayDir, 0755)
	oldStats := statsMap
	statsMap = map[string]*DayStats{}
	oldLedgerTotal, oldLedgerGen, oldLedgerDay, oldLedgerDayStr, oldLedgerDirty :=
		ledgerBankTotal, ledgerGen, ledgerBankDay, ledgerDayStr, ledgerDirty
	t.Cleanup(func() {
		dataDir, settingFile, portsFile, bansFile, statsFile, eventsDir, eventsSrcDir, honeypotFile, ledgerTotalFile, ledgerGenFile, ledgerDayDir =
			old.dataDir, old.settingFile, old.portsFile, old.bansFile, old.statsFile, old.eventsDir, old.eventsSrcDir, old.honeypotFile, old.ledgerTotalFile, old.ledgerGenFile, old.ledgerDayDir
		statsMap = oldStats
		ledgerBankTotal, ledgerGen, ledgerBankDay, ledgerDayStr, ledgerDirty =
			oldLedgerTotal, oldLedgerGen, oldLedgerDay, oldLedgerDayStr, oldLedgerDirty
	})
	return dir
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestBackupSettingsRoundTrip(t *testing.T) {
	dir := backupTestSetup(t)
	writeTestFile(t, settingFile, `{"tgEnabled":true,"tgBotToken":"TOKEN-PLACEHOLDER","tgChatId":"123","trustedIps":["203.0.113.200"],"scanEnabled":true}`)
	writeTestFile(t, portsFile, `{"ports":[{"port":443,"proto":"tcp","name":"web","star":false,"source":"manual","kind":"other"}],"ignored":[22],"ranges":[{"from":8000,"to":8010,"name":"r","star":false,"kind":"other","source":"manual"}],"ignoredRanges":[]}`)
	writeTestFile(t, honeypotFile, `{"enabled":false,"ports":[22],"autoBan":false,"alertEnabled":true,"hitThreshold":1,"banHours":24}`)
	writeTestFile(t, bansFile, `[{"ip":"203.0.113.210","status":"active"}]`)
	b, err := buildSettingsBackup()
	if err != nil {
		t.Fatal(err)
	}
	var env settingsBackup
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	if env.Kind != "settings" || env.Format != 1 || env.App != appVersion {
		t.Fatalf("信封错误: %+v", env)
	}
	if !strings.Contains(string(env.Settings), "TOKEN-PLACEHOLDER") {
		t.Fatal("设置备份应含 TG token(前端下载时警告)")
	}
	if strings.Contains(string(b), "203.0.113.210") {
		t.Fatal("设置备份绝不能含黑名单 IP(黑名单归数据备份)")
	}
	// 改掉当前状态再恢复
	mu.Lock()
	settings.TGBotToken = "CHANGED"
	settings.TrustedIPs = []string{}
	ports = []*PortWatch{}
	portRanges = []*PortRange{}
	mu.Unlock()
	honeypotMu.Lock()
	honeypotCfg.Ports = []int{3389}
	honeypotMu.Unlock()
	if _, _, err := restoreSettings(b, false); err != nil {
		t.Fatalf("恢复应成功, 实际 %v", err)
	}
	mu.Lock()
	tok, trusted, nports, nranges := settings.TGBotToken, settings.TrustedIPs, len(ports), len(portRanges)
	mu.Unlock()
	if tok != "TOKEN-PLACEHOLDER" || len(trusted) != 1 || trusted[0] != "203.0.113.200" {
		t.Fatalf("设置未恢复: token=%q trusted=%v", tok, trusted)
	}
	if nports != 1 || nranges != 1 {
		t.Fatalf("端口未恢复: ports=%d ranges=%d", nports, nranges)
	}
	honeypotMu.Lock()
	hpPorts := honeypotCfg.Ports
	honeypotMu.Unlock()
	if len(hpPorts) != 1 || hpPorts[0] != 22 {
		t.Fatalf("蜜罐配置未恢复: %v", hpPorts)
	}
	// 快照已拍
	snaps, _ := filepath.Glob(filepath.Join(dir, "snapshots", "settings-*.json"))
	if len(snaps) != 1 {
		t.Fatalf("恢复前应拍 1 份设置快照, 实际 %v", snaps)
	}
}

func TestBackupSettingsVersionWarning(t *testing.T) {
	backupTestSetup(t)
	writeTestFile(t, settingFile, `{"tgEnabled":false}`)
	writeTestFile(t, portsFile, `{"ports":[],"ignored":[]}`)
	b, err := buildSettingsBackup()
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	json.Unmarshal(b, &env)
	env["app"] = "9.9.9"
	b2, _ := json.Marshal(env)
	mu.Lock()
	settings.TGBotToken = "KEEP-ME"
	mu.Unlock()
	need, warns, err := restoreSettings(b2, false)
	if err != nil {
		t.Fatal(err)
	}
	if !need || len(warns) == 0 {
		t.Fatal("版本不匹配应返回 needConfirm + 警告, 且不应用")
	}
	mu.Lock()
	tok := settings.TGBotToken
	mu.Unlock()
	if tok != "KEEP-ME" {
		t.Fatal("未确认时不应应用恢复")
	}
	if _, _, err := restoreSettings(b2, true); err != nil {
		t.Fatalf("确认后应可恢复, 实际 %v", err)
	}
}

func TestBackupSettingsRejectsRaw(t *testing.T) {
	backupTestSetup(t)
	if _, _, err := restoreSettings([]byte(`{"tgEnabled":true}`), true); err == nil {
		t.Fatal("裸 settings.json 误传必须被拒绝(否则会清空配置)")
	}
}

func TestBackupDataRoundTrip(t *testing.T) {
	dir := backupTestSetup(t)
	writeTestFile(t, bansFile, `[{"ip":"203.0.113.220","status":"active","reason":"test"}]`)
	writeTestFile(t, statsFile, `{"2026-10-24":{"date":"2026-10-24","bans":1,"sources":{}}}`)
	writeTestFile(t, filepath.Join(eventsDir, "2026-10-24.jsonl"), "{\"type\":\"ban\",\"ip\":\"203.0.113.220\",\"detail\":\"x\"}\n")
	writeTestFile(t, filepath.Join(eventsSrcDir, "2026-10-24.jsonl"), "{\"type\":\"new_src\",\"ip\":\"203.0.113.221\",\"detail\":\"x\"}\n")
	writeTestFile(t, ledgerTotalFile, `{"203.0.113.220|443":{"rx":100,"tx":50}}`)
	writeTestFile(t, ledgerGenFile, `{}`)
	writeTestFile(t, filepath.Join(ledgerDayDir, "2026-10-24.json"), `{"203.0.113.220|443":{"rx":100,"tx":50}}`)
	b, err := buildDataBackup()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, want := range []string{"backup.json", "bans.json", "stats.json", "events/2026-10-24.jsonl", "events-src/2026-10-24.jsonl", "ledger-total.json", "ledger-gen.json", "ledger/2026-10-24.json"} {
		if !names[want] {
			t.Fatalf("数据 zip 缺少 %s, 实际 %v", want, names)
		}
	}
	// 破坏当前数据再恢复
	writeTestFile(t, bansFile, `[]`)
	os.Remove(filepath.Join(eventsDir, "2026-10-24.jsonl"))
	writeTestFile(t, ledgerTotalFile, `{}`)
	if _, _, err := restoreData(b, false); err != nil {
		t.Fatalf("数据恢复应成功, 实际 %v", err)
	}
	if got, _ := os.ReadFile(bansFile); !strings.Contains(string(got), "203.0.113.220") {
		t.Fatalf("bans.json 未恢复: %s", got)
	}
	if _, err := os.Stat(filepath.Join(eventsDir, "2026-10-24.jsonl")); err != nil {
		t.Fatal("事件文件未恢复")
	}
	if got, _ := os.ReadFile(ledgerTotalFile); !strings.Contains(string(got), "203.0.113.220") {
		t.Fatalf("账本未恢复: %s", got)
	}
	banMu.Lock()
	found := false
	for _, bn := range bans {
		if bn.IP == "203.0.113.220" {
			found = true
		}
	}
	banMu.Unlock()
	if !found {
		t.Fatal("内存黑名单未重读")
	}
	snaps, _ := filepath.Glob(filepath.Join(dir, "snapshots", "data-*.zip"))
	if len(snaps) != 1 {
		t.Fatalf("恢复前应拍 1 份数据快照, 实际 %v", snaps)
	}
}

func TestBackupDataZipSlip(t *testing.T) {
	dir := backupTestSetup(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../evil.json")
	w.Write([]byte(`{}`))
	w, _ = zw.Create("backup.json")
	w.Write([]byte(`{"format":1,"app":"` + appVersion + `","kind":"data"}`))
	zw.Close()
	if _, _, err := restoreData(buf.Bytes(), true); err == nil {
		t.Fatal("含 .. 路径的 zip 必须被拒绝")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.json")); err == nil {
		t.Fatal("zip-slip 文件不应被写出")
	}
}

func TestBackupSnapshotPrune(t *testing.T) {
	backupTestSetup(t)
	snapDir := backupSnapshotDir()
	for i := 1; i <= 7; i++ {
		writeTestFile(t, filepath.Join(snapDir, "settings-20260101-00000"+itoa(i)+".json"), `{}`)
	}
	pruneSnapshots("settings", ".json")
	files, _ := filepath.Glob(filepath.Join(snapDir, "settings-*.json"))
	if len(files) != backupSnapshotKeep {
		t.Fatalf("快照应只留 %d 份, 实际 %d", backupSnapshotKeep, len(files))
	}
	for _, f := range files {
		if strings.HasSuffix(f, "000001.json") || strings.HasSuffix(f, "000002.json") {
			t.Fatalf("最旧的两份应被清理, 残留 %s", f)
		}
	}
}

func TestBackupSettingsProxyRoundTrip(t *testing.T) {
	dir := backupTestSetup(t)
	oldProxyFile := proxyFile
	oldCfg := proxyConfigSnapshot()
	proxyFile = filepath.Join(dir, "proxy.json")
	t.Cleanup(func() {
		proxyFile = oldProxyFile
		proxyMu.Lock()
		proxyCfg = oldCfg
		proxyMu.Unlock()
	})
	proxyJSON := `{"enabled":false,"certDir":"","rules":[{"id":"r1","domain":"a.example.com","port":18080,"protocol":"http","backend":"127.0.0.1:8080","enabled":true},{"id":"r2","domain":"b.example.com","port":18443,"protocol":"https","backend":"127.0.0.1:9090","cert":"upload:web","enabled":true}]}`
	writeTestFile(t, proxyFile, proxyJSON)
	certDir := filepath.Join(dir, "certs")
	os.MkdirAll(certDir, 0755)
	writeTestFile(t, filepath.Join(certDir, "web.crt"), "DUMMY-CRT")
	writeTestFile(t, filepath.Join(certDir, "web.key"), "DUMMY-KEY")

	b, err := buildSettingsBackup()
	if err != nil {
		t.Fatal(err)
	}
	var env settingsBackup
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Proxy) == 0 {
		t.Fatal("设置备份缺少 proxy 内容")
	}
	if env.ProxyCerts["web"].Crt != "DUMMY-CRT" || env.ProxyCerts["web"].Key != "DUMMY-KEY" {
		t.Fatal("设置备份缺少上传证书对")
	}

	// 篡改当前状态后恢复, 应回到备份内容
	writeTestFile(t, proxyFile, `{"enabled":true,"rules":[]}`)
	os.Remove(filepath.Join(certDir, "web.crt"))
	os.Remove(filepath.Join(certDir, "web.key"))
	if needConfirm, _, err := restoreSettings(b, true); err != nil || needConfirm {
		t.Fatalf("恢复失败: needConfirm=%v err=%v", needConfirm, err)
	}
	restored, _ := os.ReadFile(proxyFile)
	var pc ProxyConfig
	if err := json.Unmarshal(restored, &pc); err != nil {
		t.Fatal(err)
	}
	if len(pc.Rules) != 2 || pc.Rules[0].Domain != "a.example.com" || pc.Rules[1].Domain != "b.example.com" {
		t.Fatalf("恢复后反代规则不对: %+v", pc.Rules)
	}
	if len(pc.Rules[0].Listens) != 1 || pc.Rules[0].Listens[0].Port != 18080 || pc.Rules[0].Listens[0].Protocol != "http" || len(pc.Rules[1].Listens) != 1 || pc.Rules[1].Listens[0].Port != 18443 || pc.Rules[1].Listens[0].Protocol != "https" {
		t.Fatalf("恢复后反代端口/协议不对: %+v", pc.Rules)
	}
	if crt, _ := os.ReadFile(filepath.Join(certDir, "web.crt")); string(crt) != "DUMMY-CRT" {
		t.Fatal("恢复后证书 crt 未写回")
	}
	if key, _ := os.ReadFile(filepath.Join(certDir, "web.key")); string(key) != "DUMMY-KEY" {
		t.Fatal("恢复后证书 key 未写回")
	}
	proxyMu.Lock()
	memRules := len(proxyCfg.Rules)
	proxyMu.Unlock()
	if memRules != 2 {
		t.Fatalf("恢复后内存反代规则不对: %d", memRules)
	}

	// 旧备份(无 proxy 字段)恢复时不得动反代
	writeTestFile(t, proxyFile, `{"enabled":true,"rules":[]}`)
	before, _ := os.ReadFile(proxyFile)
	oldEnv, _ := json.Marshal(settingsBackup{Format: backupFormat, App: appVersion, CreatedAt: 1, Kind: "settings", Settings: json.RawMessage(`{}`), Ports: json.RawMessage(`{}`)})
	if _, _, err := restoreSettings(oldEnv, true); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(proxyFile)
	if string(before) != string(after) {
		t.Fatal("旧备份恢复不应改动反代配置")
	}
}
