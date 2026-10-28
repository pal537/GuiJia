package main

// 群控保存即同步回归: 保存开启后立即触发一次同步(不等 ticker),
// 同组异步同步不叠加, 定时器仍按新间隔走。

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGroupSyncSaveTriggersSync(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()

	gsMu.Lock()
	oldCfg, oldTicker := gsCfg, gsTicker
	gsCfg = groupSyncFile{
		Blacklist: groupSyncCfg{IntervalMin: 10},
		Whitelist: groupSyncCfg{IntervalMin: 10},
	}
	gsMu.Unlock()
	defer func() {
		gsMu.Lock()
		gsCfg, gsTicker = oldCfg, oldTicker
		gsMu.Unlock()
	}()

	// 无节点时同步立即返回(0,0), 结果记为 failed: 只要 LastStatus 从空变 failed,
	// 即证明保存触发了同步尝试(不是等 ticker)。
	req := httptest.NewRequest("POST", "/api/group-sync/settings", bytes.NewBufferString(`{"group":"blacklist","enabled":true,"intervalMin":10}`))
	rec := httptest.NewRecorder()
	handleGroupSyncSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("保存应 200, 实际 %d", rec.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		gsMu.Lock()
		st := gsCfg.Blacklist.LastStatus
		gsMu.Unlock()
		if st != "" {
			if st != "failed" {
				t.Fatalf("无节点同步应记 failed, 得到 %q", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("保存后 5 秒内未触发同步")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 保存关闭的组不触发同步: 白名单保持空状态。
	req = httptest.NewRequest("POST", "/api/group-sync/settings", bytes.NewBufferString(`{"group":"whitelist","enabled":false,"intervalMin":10}`))
	rec = httptest.NewRecorder()
	handleGroupSyncSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("保存关闭组应 200, 实际 %d", rec.Code)
	}
	time.Sleep(300 * time.Millisecond)
	gsMu.Lock()
	wl := gsCfg.Whitelist.LastStatus
	gsMu.Unlock()
	if wl != "" {
		t.Fatalf("关闭的组不应触发同步, 得到 %q", wl)
	}

	// 同组异步同步不叠加: 抢到锁后第二次触发直接跳过。
	if !tryBeginAsyncGroupSync("blacklist") {
		t.Fatal("首抢应成功")
	}
	if tryBeginAsyncGroupSync("blacklist") {
		t.Fatal("同组已有同步在跑时应跳过")
	}
	endAsyncGroupSync("blacklist")
	if !tryBeginAsyncGroupSync("blacklist") {
		t.Fatal("释放后应能再抢")
	}
	endAsyncGroupSync("blacklist")
}
