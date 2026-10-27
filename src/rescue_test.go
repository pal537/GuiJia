package main

// 第 2 项回归测试: 急救超级密码哈希、锁定、关闭拦截/恢复快照、
// 网页端密码接口(哈希永不外泄、通用设置接口不得覆盖哈希)。

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

func rescueTestSetup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldRescue, oldEv, oldSrc, oldSet := rescueFile, eventsDir, eventsSrcDir, settingFile
	rescueFile = filepath.Join(dir, "rescue.json")
	eventsDir = filepath.Join(dir, "events")
	eventsSrcDir = filepath.Join(dir, "events-src")
	settingFile = filepath.Join(dir, "settings.json")
	os.MkdirAll(eventsDir, 0755)
	os.MkdirAll(eventsSrcDir, 0755)
	rescueMu.Lock()
	rescueSt = RescueState{}
	rescueMu.Unlock()
	oldSettings := settings
	t.Cleanup(func() {
		rescueFile, eventsDir, eventsSrcDir, settingFile = oldRescue, oldEv, oldSrc, oldSet
		settings = oldSettings
	})
	return dir
}

func TestRescuePasswordHash(t *testing.T) {
	h1, err := hashRescuePassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := hashRescuePassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("两次哈希应因随机盐不同")
	}
	if !strings.HasPrefix(h1, "pbkdf2-sha256$") {
		t.Fatalf("哈希格式不对: %s", h1)
	}
	if !verifyRescuePassword("correct horse", h1) {
		t.Fatal("正确密码应验证通过")
	}
	if verifyRescuePassword("wrong horse", h1) {
		t.Fatal("错误密码不应通过")
	}
	if verifyRescuePassword("correct horse", "garbage") || verifyRescuePassword("x", "") {
		t.Fatal("畸形存储串不应通过")
	}
}

func TestRescueLockout(t *testing.T) {
	rescueTestSetup(t)
	now := time.Now()
	for i := 0; i < 4; i++ {
		if rescueNoteFailure(now) {
			t.Fatalf("第 %d 次错误不应触发锁定", i+1)
		}
	}
	if rescueLockedUntil() != 0 {
		t.Fatal("4 次错误不应锁定")
	}
	if !rescueNoteFailure(now) {
		t.Fatal("第 5 次错误应触发锁定")
	}
	until := rescueLockedUntil()
	if until <= now.Add(29*time.Minute).Unix() || until > now.Add(31*time.Minute).Unix() {
		t.Fatalf("锁定应约 30 分钟, 实际截止 %v", time.Unix(until, 0))
	}
	rescueResetFailures()
	// 锁定本身不受计数清零影响(截止时间仍在), 但失败计数应归零
	rescueMu.Lock()
	fc := rescueSt.FailCount
	rescueMu.Unlock()
	if fc != 0 {
		t.Fatalf("清零后 FailCount 应为 0, 实际 %d", fc)
	}
}

func TestRescueKillAndRestore(t *testing.T) {
	dir := rescueTestSetup(t)
	_ = dir
	banTestSetup(t)
	settings.AutoBanEnabled = true
	settings.FloodEnabled = true
	applyBan("203.0.113.70", "test", "manual", 24)
	if !isBanned("203.0.113.70") {
		t.Fatal("前置: IP 应生效中")
	}
	rescueActivateKill(time.Now())
	if settings.AutoBanEnabled || settings.FloodEnabled {
		t.Fatal("关闭拦截后自动开关应全关")
	}
	if isBanned("203.0.113.70") {
		t.Fatal("关闭拦截后封禁应已释放")
	}
	if len(allBans()) != 1 || allBans()[0].Status != BanReleased {
		t.Fatal("解封只改状态, 记录必须保留")
	}
	rescueMu.Lock()
	active, snap := rescueSt.KillActive, rescueSt.Snapshot
	rescueMu.Unlock()
	if !active || snap == nil || !snap.AutoBanEnabled || !snap.FloodEnabled {
		t.Fatalf("快照应记录关闭前的开关状态: active=%v snap=%+v", active, snap)
	}
	if !rescueRestore() {
		t.Fatal("急救模式下恢复应成功")
	}
	if !settings.AutoBanEnabled || !settings.FloodEnabled {
		t.Fatal("恢复后开关应按快照还原")
	}
	if rescueRestore() {
		t.Fatal("非急救模式下恢复应失败")
	}
}

func TestRescueAutoRestore(t *testing.T) {
	rescueTestSetup(t)
	settings.AutoBanEnabled = true
	settings.FloodEnabled = true
	rescueActivateKill(time.Now().Add(-31 * time.Minute))
	// KillUntil 已是过去(30 分钟前激活 + 30 分钟有效期已过)
	rescueMu.Lock()
	rescueSt.KillUntil = time.Now().Add(-time.Minute).Unix()
	saveRescue()
	rescueMu.Unlock()
	if !rescueCheckAutoRestore(time.Now()) {
		t.Fatal("到期应自动恢复")
	}
	if !settings.AutoBanEnabled || !settings.FloodEnabled {
		t.Fatal("自动恢复后开关应还原")
	}
}

func TestRescuePasswordAPI(t *testing.T) {
	rescueTestSetup(t)
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		switch path {
		case "/api/rescue/password":
			handleRescuePassword(rec, req)
		case "/api/settings":
			handleSettings(rec, req)
		}
		return rec
	}
	// 太短拒绝
	if rec := post("/api/rescue/password", `{"password":"123"}`); rec.Code != 400 {
		t.Fatalf("短密码应 400, 实际 %d", rec.Code)
	}
	// 设置成功: 存的是哈希不是明文
	if rec := post("/api/rescue/password", `{"password":"super-secret-1"}`); rec.Code != 200 {
		t.Fatalf("设密码应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	hash := settings.RescuePassHash
	mu.Unlock()
	if hash == "" || strings.Contains(hash, "super-secret-1") {
		t.Fatal("应存哈希, 绝不能存明文")
	}
	if !verifyRescuePassword("super-secret-1", hash) {
		t.Fatal("存入的哈希应能验证")
	}
	// GET settings 不得外泄哈希
	req := httptest.NewRequest("GET", "/api/settings", nil)
	rec := httptest.NewRecorder()
	handleSettings(rec, req)
	var m map[string]any
	json.Unmarshal(rec.Body.Bytes(), &m)
	if _, ok := m["rescuePassHash"]; ok {
		t.Fatal("GET settings 不得包含 rescuePassHash")
	}
	// 通用 PUT 不得覆盖哈希(即使 body 里没带)
	oldHash := hash
	req2 := httptest.NewRequest("PUT", "/api/settings", bytes.NewBufferString(`{"tgEnabled":false}`))
	rec2 := httptest.NewRecorder()
	handleSettings(rec2, req2)
	mu.Lock()
	after := settings.RescuePassHash
	mu.Unlock()
	if after != oldHash {
		t.Fatal("通用 PUT 不得覆盖超级密码哈希")
	}
	// 清除密码
	if rec := post("/api/rescue/password", `{"password":""}`); rec.Code != 200 {
		t.Fatalf("清除密码应 200, 实际 %d", rec.Code)
	}
	mu.Lock()
	if settings.RescuePassHash != "" {
		t.Fatal("空密码应清除哈希")
	}
	mu.Unlock()
}
