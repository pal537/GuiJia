package main

// 并集合并单测：吸入只新增、已有不动、非法/内网/信任跳过、
// 离线跳过、推回时节点本地条目不动、计数 breakdown。

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setUnionTestBansFile(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old := bansFile
	bansFile = filepath.Join(dir, "bans.json")
	t.Cleanup(func() { bansFile = old })
}

func unionFakeNode(t *testing.T, fp string, list []fullBanEntry) {
	t.Helper()
	wch := make(chan hubCommand, 4)
	cmdMu.Lock()
	oldW, hadW := cmdWaiters[fp]
	cmdWaiters[fp] = wch
	cmdMu.Unlock()
	t.Cleanup(func() {
		cmdMu.Lock()
		if hadW {
			cmdWaiters[fp] = oldW
		} else {
			delete(cmdWaiters, fp)
		}
		cmdMu.Unlock()
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for cmd := range wch {
			if cmd.Path != "api/sync/full-bans" {
				continue
			}
			cmdMu.Lock()
			ch, ok := cmdResults[cmd.ID]
			cmdMu.Unlock()
			if !ok {
				continue
			}
			body, _ := json.Marshal(map[string]any{"blacklist": list})
			select {
			case ch <- hubCmdResult{Status: 200, Body: body}:
			default:
			}
		}
	}()
	t.Cleanup(func() { close(wch); <-done })
}

// TestUnionMergeBasic 并集基本语义：只吸入主服务器没有的，
// 已有条目状态绝不动，非法/内网/信任一律不吸入。
func TestUnionMergeBasic(t *testing.T) {
	setUnionTestBansFile(t)
	now := time.Now().Unix()
	banMu.Lock()
	oldBans := bans
	bans = []*Ban{
		{IP: "203.0.113.9", Source: "manual", Status: BanActive, Until: 0, CreatedAt: now},
	}
	banMu.Unlock()
	defer func() { banMu.Lock(); bans = oldBans; banMu.Unlock() }()
	mu.Lock()
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = []string{"203.0.113.99"}
	mu.Unlock()
	defer func() { mu.Lock(); settings.TrustedIPs = oldTrusted; mu.Unlock() }()

	fp := strings.Repeat("cd", 32)
	hubMu.Lock()
	oldServers := hubServers
	hubServers = append(append([]*hubServer{}, oldServers...),
		&hubServer{Fingerprint: fp, Name: "节点A", LastSeen: time.Now().Unix()})
	hubMu.Unlock()
	defer func() { hubMu.Lock(); hubServers = oldServers; hubMu.Unlock() }()

	oldWait := unionPullWait
	unionPullWait = 5 * time.Second
	defer func() { unionPullWait = oldWait }()
	unionFakeNode(t, fp, []fullBanEntry{
		{IP: "203.0.113.9", Status: "active", Source: "manual", Until: 0},         // 主服务器已有：不动
		{IP: "203.0.113.55", Status: "active", Source: "auto", Until: now + 3600}, // 新：吸入
		{IP: "203.0.113.56", Status: "released", Source: "auto"},                  // 新：吸入（已解封态）
		{IP: "10.0.0.5", Status: "active", Source: "auto"},                        // 内网：不吸入
		{IP: "203.0.113.99", Status: "active", Source: "auto"},                    // 信任：不吸入
		{IP: "not-an-ip", Status: "active", Source: "auto"},                       // 非法：不吸入
	})

	added, total, skipped := collectBlacklistUnion()
	if added != 2 {
		t.Fatalf("应新增 2 条，实际 %d", added)
	}
	if total != 3 {
		t.Fatalf("合并后总数应为 3，实际 %d", total)
	}
	if len(skipped) != 0 {
		t.Fatalf("在线节点不应被跳过：%v", skipped)
	}
	banMu.Lock()
	defer banMu.Unlock()
	byIP := map[string]*Ban{}
	for _, b := range bans {
		byIP[b.IP] = b
	}
	if b := byIP["203.0.113.9"]; b == nil || b.Source != "manual" || b.Status != BanActive {
		t.Errorf("主服务器已有条目被改动：%+v", b)
	}
	if b := byIP["203.0.113.55"]; b == nil || b.Source != "shared" || b.Status != BanActive {
		t.Errorf("新 IP 应以 shared 生效吸入：%+v", b)
	}
	if b := byIP["203.0.113.56"]; b == nil || b.Source != "shared" || b.Status != BanReleased {
		t.Errorf("新 IP 应以 shared 已解封吸入：%+v", b)
	}
	for _, ip := range []string{"10.0.0.5", "203.0.113.99", "not-an-ip"} {
		if _, ok := byIP[ip]; ok {
			t.Errorf("不应吸入 %s", ip)
		}
	}
}

// TestUnionSkipsOffline 离线节点只记名跳过，绝不等于空集（不清空、不报错）。
func TestUnionSkipsOffline(t *testing.T) {
	setUnionTestBansFile(t)
	banMu.Lock()
	oldBans := bans
	bans = []*Ban{{IP: "203.0.113.9", Source: "manual", Status: BanActive}}
	banMu.Unlock()
	defer func() { banMu.Lock(); bans = oldBans; banMu.Unlock() }()
	fp := strings.Repeat("ef", 32)
	hubMu.Lock()
	oldServers := hubServers
	hubServers = append(append([]*hubServer{}, oldServers...),
		&hubServer{Fingerprint: fp, Name: "离线节点", LastSeen: 0})
	hubMu.Unlock()
	defer func() { hubMu.Lock(); hubServers = oldServers; hubMu.Unlock() }()
	added, total, skipped := collectBlacklistUnion()
	if added != 0 || total != 1 {
		t.Fatalf("离线节点不应改变名单：added=%d total=%d", added, total)
	}
	if len(skipped) != 1 || skipped[0] != "离线节点" {
		t.Fatalf("应跳过离线节点并记名：%v", skipped)
	}
}

// TestUnionPushbackLocalUntouched 推回时节点本地条目绝不动：
// 节点已有 manual 记录的 IP，即使主服务器推来 shared released，也跳过。
func TestUnionPushbackLocalUntouched(t *testing.T) {
	banMu.Lock()
	oldBans := bans
	bans = []*Ban{{IP: "203.0.113.55", Source: "manual", Status: BanActive, Until: 0}}
	banMu.Unlock()
	defer func() { banMu.Lock(); bans = oldBans; banMu.Unlock() }()
	banMu.Lock()
	added, updated, skipped := applySharedBansLocked([]syncBanEntry{
		{IP: "203.0.113.55", Status: "released"},
		{IP: "203.0.113.77", Status: "active"},
	}, time.Now().Unix())
	banMu.Unlock()
	if added != 1 || updated != 0 || skipped != 1 {
		t.Fatalf("应新增 1、跳过本地 1，实际 added=%d updated=%d skipped=%d", added, updated, skipped)
	}
	banMu.Lock()
	defer banMu.Unlock()
	for _, b := range bans {
		if b.IP == "203.0.113.55" && (b.Source != "manual" || b.Status != BanActive) {
			t.Fatalf("节点本地条目被改动：%+v", b)
		}
	}
}

// TestBanCounts 计数 breakdown：生效/解封/过期/全部口径。
func TestBanCounts(t *testing.T) {
	now := time.Now().Unix()
	banMu.Lock()
	oldBans := bans
	bans = []*Ban{
		{IP: "203.0.113.1", Status: BanActive, Until: now + 3600},
		{IP: "203.0.113.2", Status: BanActive, Until: 0},
		{IP: "203.0.113.3", Status: BanActive, Until: now - 10}, // 已过期的生效态
		{IP: "203.0.113.4", Status: BanReleased},
		{IP: "203.0.113.5", Status: BanExpired},
	}
	banMu.Unlock()
	defer func() { banMu.Lock(); bans = oldBans; banMu.Unlock() }()
	a, r, e, tot := banCounts()
	if a != 2 || r != 1 || e != 2 || tot != 5 {
		t.Fatalf("计数错误：active=%d released=%d expired=%d total=%d", a, r, e, tot)
	}
}

// TestUnionHandlerFullBans 完整黑名单接口：内部头可读全部记录、无头 403。
func TestUnionHandlerFullBans(t *testing.T) {
	banMu.Lock()
	oldBans := bans
	bans = []*Ban{
		{IP: "203.0.113.9", Source: "manual", Status: BanActive},
		{IP: "203.0.113.55", Source: "shared", Status: BanReleased},
	}
	banMu.Unlock()
	defer func() { banMu.Lock(); bans = oldBans; banMu.Unlock() }()
	req := httptest.NewRequest("GET", "/api/sync/full-bans", nil)
	req.Header.Set("X-Guijia-Internal", "1")
	rec := httptest.NewRecorder()
	handleSyncFullBans(rec, req)
	if rec.Code != 200 {
		t.Fatalf("内部头应返回 200，实际 %d", rec.Code)
	}
	var v struct {
		Blacklist []fullBanEntry `json:"blacklist"`
	}
	if json.NewDecoder(rec.Body).Decode(&v) != nil || len(v.Blacklist) != 2 {
		t.Fatalf("应返回全部 2 条记录，实际 %+v", v)
	}
	req2 := httptest.NewRequest("GET", "/api/sync/full-bans", nil)
	rec2 := httptest.NewRecorder()
	handleSyncFullBans(rec2, req2)
	if rec2.Code != 403 {
		t.Fatalf("无内部头应 403，实际 %d", rec2.Code)
	}
}
