package main

// 今日拉黑新口径回归测试：今日拉黑 = 今日全部封禁动作数（ban/autoban/
// honeypot_ban/portguard_ban），蜜罐封禁是其中的明细（明细 ≤ 总数）；
// 启动时用当日事件文件重算今日封禁数与蜜罐分端口命中；退出时保存统计。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func statsRecalTestSetup(t *testing.T) (evDir string, oldStats map[string]*DayStats, oldStatsFile string) {
	t.Helper()
	evDir = t.TempDir()
	oldEv, oldSrc := eventsDir, eventsSrcDir
	eventsDir, eventsSrcDir = evDir, t.TempDir()
	oldStats, oldStatsFile = statsMap, statsFile
	statsMap = map[string]*DayStats{}
	statsFile = filepath.Join(t.TempDir(), "stats.json")
	honeypotMu.Lock()
	oldDay, oldHits := honeypotPortDay, honeypotPortHits
	honeypotPortDay, honeypotPortHits = "", map[int]int{}
	honeypotMu.Unlock()
	t.Cleanup(func() {
		eventsDir, eventsSrcDir = oldEv, oldSrc
		statsMap, statsFile = oldStats, oldStatsFile
		honeypotMu.Lock()
		honeypotPortDay, honeypotPortHits = oldDay, oldHits
		honeypotMu.Unlock()
	})
	return evDir, oldStats, oldStatsFile
}

func TestStatsOnEventBanTypes(t *testing.T) {
	_, _, _ = statsRecalTestSetup(t)
	ds := todayStats()
	statsMu.Lock()
	ds.Bans, ds.HoneypotBans, ds.SSHLogins = 0, 0, 0
	statsMu.Unlock()
	for _, typ := range []string{"ban", "autoban", "honeypot_ban", "portguard_ban"} {
		statsOnEvent(Event{Type: typ, IP: "203.0.113.1"})
	}
	// 解封与无关事件不计入今日拉黑
	statsOnEvent(Event{Type: "unban", IP: "203.0.113.1"})
	statsOnEvent(Event{Type: "ssh_login", IP: "203.0.113.1"})
	statsOnEvent(Event{Type: "port_scan", IP: "203.0.113.1"})
	statsOnEvent(Event{Type: "honeypot_hit", IP: "203.0.113.1", Port: 22})
	ds = todayStats()
	statsMu.Lock()
	bans, hp, logins := ds.Bans, ds.HoneypotBans, ds.SSHLogins
	statsMu.Unlock()
	if bans != 4 {
		t.Fatalf("四类封禁事件应各计 1 次进今日拉黑, 实际 %d", bans)
	}
	if hp != 1 {
		t.Fatalf("蜜罐封禁明细应为 1, 实际 %d", hp)
	}
	if hp > bans {
		t.Fatalf("蜜罐明细不应超过今日拉黑总数: 明细 %d, 总数 %d", hp, bans)
	}
	if logins != 1 {
		t.Fatalf("ssh_login 应只计登录数, 实际 %d", logins)
	}
}

func TestRecalibrateTodayStats(t *testing.T) {
	evDir, _, _ := statsRecalTestSetup(t)
	day := time.Now().Format("2006-01-02")
	otherDay := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	// 预置统计：今日其他字段与昨日条目在重算后必须原样不动
	statsMap[day] = &DayStats{Date: day, SSHLogins: 5, SSHFails: 3, UILogins: 2,
		Bans: 999, HoneypotBans: 999, Sources: map[string]int{"203.0.113.9": 4}}
	statsMap[otherDay] = &DayStats{Date: otherDay, Bans: 7, HoneypotBans: 2, Sources: map[string]int{}}
	lines := []string{
		`{"type":"ban","ip":"203.0.113.11"}`,
		`{"type":"autoban","ip":"203.0.113.12"}`,
		`{"type":"honeypot_ban","ip":"203.0.113.13"}`,
		`{"type":"honeypot_ban","ip":"203.0.113.14"}`,
		`{"type":"portguard_ban","ip":"203.0.113.15"}`,
		`{"type":"honeypot_hit","ip":"203.0.113.16","port":22}`,
		`{"type":"honeypot_hit","ip":"203.0.113.17","port":22}`,
		`{"type":"honeypot_hit","ip":"203.0.113.18","port":22}`,
		`{"type":"honeypot_hit","ip":"203.0.113.19","port":2222}`,
		`{"type":"honeypot_hit","ip":"203.0.113.20","port":22,"detail":"蜜罐命中(信任 IP, 不拉黑)"}`,
		`{"type":"honeypot_hit","ip":"203.0.113.21","port":0}`,
		`{"type":"ssh_login","ip":"203.0.113.22"}`,
		`{"type":"unban","ip":"203.0.113.23"}`,
		`{"type":"port_scan","ip":"203.0.113.24"}`,
		`not json at all`,
		`{"type":}`,
	}
	data := ""
	for _, l := range lines {
		data += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(evDir, day+".jsonl"), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	recalibrateTodayStats()
	ds := statsMap[day]
	statsMu.Lock()
	bans, hp, logins, fails, ui, srcs := ds.Bans, ds.HoneypotBans, ds.SSHLogins, ds.SSHFails, ds.UILogins, ds.Sources
	statsMu.Unlock()
	if bans != 5 {
		t.Fatalf("重算今日拉黑应为 5（ban+autoban+蜜罐×2+端口防护）, 实际 %d", bans)
	}
	if hp != 2 {
		t.Fatalf("重算蜜罐明细应为 2, 实际 %d", hp)
	}
	if hp > bans {
		t.Fatalf("重算后蜜罐明细不应超过总数: 明细 %d, 总数 %d", hp, bans)
	}
	if logins != 5 || fails != 3 || ui != 2 {
		t.Fatalf("重算不应动其他字段: 登录 %d/%d/%d", logins, fails, ui)
	}
	if len(srcs) != 1 || srcs["203.0.113.9"] != 4 {
		t.Fatalf("重算不应动新来源集合: %v", srcs)
	}
	od := statsMap[otherDay]
	if od.Bans != 7 || od.HoneypotBans != 2 {
		t.Fatalf("重算不应动其他日期: %d/%d", od.Bans, od.HoneypotBans)
	}
	honeypotMu.Lock()
	hits := honeypotPortHits
	daySet := honeypotPortDay
	honeypotMu.Unlock()
	if daySet != day {
		t.Fatalf("重算应把命中日期置为今日, 实际 %q", daySet)
	}
	if hits[22] != 4 {
		t.Fatalf("端口 22 命中应为 4（含信任 IP 的命中，不含端口 0 的坏行）, 实际 %d", hits[22])
	}
	if hits[2222] != 1 {
		t.Fatalf("端口 2222 命中应为 1, 实际 %d", hits[2222])
	}
	if _, bad := hits[0]; bad {
		t.Fatal("端口 0 的坏行不应计入命中")
	}
}

func TestRecalibrateNoFileNoop(t *testing.T) {
	statsRecalTestSetup(t)
	day := time.Now().Format("2006-01-02")
	statsMap[day] = &DayStats{Date: day, Bans: 3, HoneypotBans: 1, Sources: map[string]int{}}
	honeypotMu.Lock()
	honeypotPortDay, honeypotPortHits = day, map[int]int{22: 9}
	honeypotMu.Unlock()
	recalibrateTodayStats() // 当日无事件文件：不动任何数
	ds := statsMap[day]
	if ds.Bans != 3 || ds.HoneypotBans != 1 {
		t.Fatalf("无文件时重算不应改数: %d/%d", ds.Bans, ds.HoneypotBans)
	}
	honeypotMu.Lock()
	n := honeypotPortHits[22]
	honeypotMu.Unlock()
	if n != 9 {
		t.Fatalf("无文件时命中不应改: %d", n)
	}
}

func TestSaveOnExitPersistsStats(t *testing.T) {
	_, _, _ = statsRecalTestSetup(t)
	day := time.Now().Format("2006-01-02")
	statsMap[day] = &DayStats{Date: day, Bans: 6, HoneypotBans: 2, Sources: map[string]int{}}
	saveOnExit()
	b, err := os.ReadFile(statsFile)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]*DayStats
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back[day] == nil || back[day].Bans != 6 || back[day].HoneypotBans != 2 {
		t.Fatalf("退出保存应把统计落盘, 实际 %v", back[day])
	}
}
