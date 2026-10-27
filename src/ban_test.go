package main

// 黑名单硬规矩回归测试(PAPA 2026-10-24):
// 1) 记录永不丢失: 到期/解封只改状态; 2) 名单即唯一事实来源(生效中才算封);
// 3) 数据清理必须单独确认释放黑名单, 否则记录与封禁完全不碰;
// 4) 唯一删记录路径 = 清理时明确释放(wipeBans)。
// 另含 TG 通知 1970 时间 bug 的回归: emit 必须给事件打上真实时间戳。

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

func banTestSetup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldBansFile, oldDry := bansFile, dryBan
	oldBans := bans
	bansFile = filepath.Join(dir, "bans.json")
	dryBan = true
	banMu.Lock()
	bans = nil
	banMu.Unlock()
	loadBans()
	t.Cleanup(func() {
		bansFile, dryBan = oldBansFile, oldDry
		banMu.Lock()
		bans = oldBans
		banMu.Unlock()
	})
	return dir
}

func TestBanExpiryKeepsRecord(t *testing.T) {
	banTestSetup(t)
	past := time.Now().Add(-time.Hour).Unix()
	banMu.Lock()
	bans = []*Ban{{IP: "203.0.113.25", Until: past, Reason: "test", Source: "manual", CreatedAt: past - 3600}}
	banMu.Unlock()
	if got := activeBans(); len(got) != 0 {
		t.Fatalf("过期记录不应生效, activeBans=%d", len(got))
	}
	all := allBans()
	if len(all) != 1 {
		t.Fatalf("过期后记录必须保留, allBans=%d", len(all))
	}
	if all[0].Status != BanExpired {
		t.Fatalf("状态应为 expired, 实际 %q", all[0].Status)
	}
	if isBanned("203.0.113.25") {
		t.Fatal("过期 IP 不应被判为封禁中")
	}
	// 落盘后记录仍在(重启不丢)
	b2, _ := os.ReadFile(bansFile)
	if !strings.Contains(string(b2), "203.0.113.25") || !strings.Contains(string(b2), `"expired"`) {
		t.Fatalf("bans.json 应保留过期记录: %s", b2)
	}
}

func TestReleaseBanKeepsRecord(t *testing.T) {
	banTestSetup(t)
	if _, err := applyBan("203.0.113.26", "test", "manual", 24); err != nil {
		t.Fatal(err)
	}
	if !isBanned("203.0.113.26") {
		t.Fatal("拉黑后应生效")
	}
	if !releaseBan("203.0.113.26") {
		t.Fatal("releaseBan 应找到记录")
	}
	if isBanned("203.0.113.26") {
		t.Fatal("解封后不应再生效")
	}
	all := allBans()
	if len(all) != 1 || all[0].Status != BanReleased || all[0].ReleasedAt == 0 {
		t.Fatalf("解封后记录应保留且状态=released: %+v", all)
	}
	if releaseBan("203.0.113.99") {
		t.Fatal("不存在的 IP 不应报告找到")
	}
}

func TestRebanAfterReleaseReactivates(t *testing.T) {
	banTestSetup(t)
	applyBan("203.0.113.27", "first", "manual", 1)
	releaseBan("203.0.113.27")
	if _, err := applyBan("203.0.113.27", "second", "tg", 0); err != nil {
		t.Fatal(err)
	}
	all := allBans()
	if len(all) != 1 {
		t.Fatalf("同一 IP 应只有一行记录, 实际 %d", len(all))
	}
	if all[0].Status != BanActive || all[0].Reason != "second" || !isBanned("203.0.113.27") {
		t.Fatalf("重封后应生效中: %+v", all[0])
	}
}

func TestWipeBansDeletesRecords(t *testing.T) {
	banTestSetup(t)
	applyBan("203.0.113.28", "a", "manual", 0)
	applyBan("203.0.113.29", "b", "auto", 24)
	wipeBans()
	if len(allBans()) != 0 {
		t.Fatal("wipeBans 后记录应清空")
	}
	if isBanned("203.0.113.28") || isBanned("203.0.113.29") {
		t.Fatal("wipeBans 后不应再生效")
	}
}

func TestDataClearBlacklistGate(t *testing.T) {
	dir := banTestSetup(t)
	oldEv, oldSrc, oldStats := eventsDir, eventsSrcDir, statsFile
	eventsDir = filepath.Join(dir, "events")
	eventsSrcDir = filepath.Join(dir, "events-src")
	statsFile = filepath.Join(dir, "stats.json")
	os.MkdirAll(eventsDir, 0755)
	os.MkdirAll(eventsSrcDir, 0755)
	ledgerInit(filepath.Join(dir, "ledger"))
	t.Cleanup(func() { eventsDir, eventsSrcDir, statsFile = oldEv, oldSrc, oldStats })

	applyBan("203.0.113.30", "gate", "manual", 0)

	post := func(body string) int {
		req := httptest.NewRequest("POST", "/api/data/clear", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handleDataClear(rec, req)
		return rec.Code
	}
	// 清空黑名单但没明确释放 -> 拒绝, 记录不动
	if code := post(`{"scope":"bans","confirm":"YES"}`); code != 400 {
		t.Fatalf("scope=bans 未带 releaseBans 应 400, 实际 %d", code)
	}
	if len(allBans()) != 1 || !isBanned("203.0.113.30") {
		t.Fatal("未释放时黑名单必须完全不碰")
	}
	// 全部清空但不释放 -> 其他照清, 黑名单(记录+封禁)保留
	if code := post(`{"scope":"all","confirm":"YES","releaseBans":false}`); code != 200 {
		t.Fatalf("scope=all 应 200, 实际 %d", code)
	}
	if len(allBans()) != 1 || !isBanned("203.0.113.30") {
		t.Fatal("全部清空未选释放时, 黑名单必须保留且仍生效")
	}
	// 全部清空且释放 -> 唯一删记录路径
	if code := post(`{"scope":"all","confirm":"YES","releaseBans":true}`); code != 200 {
		t.Fatalf("scope=all+release 应 200, 实际 %d", code)
	}
	if len(allBans()) != 0 {
		t.Fatal("明确释放后记录才可删除")
	}
	// scope=bans 带释放 -> 清空
	applyBan("203.0.113.31", "gate2", "manual", 0)
	if code := post(`{"scope":"bans","confirm":"YES","releaseBans":true}`); code != 200 {
		t.Fatalf("scope=bans+release 应 200, 实际 %d", code)
	}
	if len(allBans()) != 0 {
		t.Fatal("scope=bans+release 后记录应清空")
	}
}

func TestEmitStampsTimestamp(t *testing.T) {
	dir := t.TempDir()
	oldEv, oldSrc := eventsDir, eventsSrcDir
	eventsDir = filepath.Join(dir, "events")
	eventsSrcDir = filepath.Join(dir, "events-src")
	os.MkdirAll(eventsDir, 0755)
	os.MkdirAll(eventsSrcDir, 0755)
	t.Cleanup(func() { eventsDir, eventsSrcDir = oldEv, oldSrc })

	before := time.Now().UnixMilli()
	emit(Event{Type: "ssh_login", IP: "203.0.113.40", Detail: "test"}, false)
	day := time.Now().Format("2006-01-02")
	b, err := os.ReadFile(filepath.Join(eventsDir, day+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var ev Event
	if err := json.Unmarshal(bytes.TrimSpace(b), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Ts < before || ev.Ts > time.Now().UnixMilli() {
		t.Fatalf("事件时间戳应为当前毫秒时间, 实际 %d", ev.Ts)
	}
	if y := time.UnixMilli(ev.Ts).Year(); y == 1970 {
		t.Fatal("时间戳不允许是 1970")
	}
}

func TestStatsUnbanNotCountedAsBan(t *testing.T) {
	// 今日拉黑只应统计拉黑动作; 解封事件(新类型 unban)不得计入,
	// 否则首页数字会大于黑名单记录数(2026-10-24 实测: 7=4 次真拉黑+3 次解封)。
	ds := todayStats()
	statsMu.Lock()
	before := ds.Bans
	statsMu.Unlock()
	statsOnEvent(Event{Type: "unban", IP: "203.0.113.99", Detail: "已解除拉黑"})
	statsOnEvent(Event{Type: "ban", IP: "203.0.113.98", Detail: "手动拉黑"})
	statsOnEvent(Event{Type: "autoban", IP: "203.0.113.97", Detail: "爆破自动拉黑"})
	statsMu.Lock()
	after := ds.Bans
	statsMu.Unlock()
	if after-before != 2 {
		t.Fatalf("解封不应计入拉黑: before=%d after=%d", before, after)
	}
	// 恢复, 不污染其他测试
	statsMu.Lock()
	ds.Bans = before
	statsMu.Unlock()
}

func TestChinaTimezone(t *testing.T) {
	// init() 应已把本地时区设为 Asia/Shanghai(UTC+8)
	_, off := time.Now().Zone()
	if off != 8*3600 {
		t.Fatalf("本地时区偏移应为 +8h, 实际 %d 秒", off)
	}
}
