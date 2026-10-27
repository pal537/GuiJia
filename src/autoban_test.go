package main

// 第 1 项回归测试: 自动封禁递进阶梯(首次 1 小时、再次 24 小时、累犯永久)。
// 手动/TG 拉黑不碰 Offenses 计数, 不影响阶梯。

import (
	"testing"
	"time"
)

func TestAutoBanLadder(t *testing.T) {
	banTestSetup(t)
	ip := "203.0.113.60"
	b, err := applyAutoBan(ip, "SSH 爆破自动拉黑")
	if err != nil {
		t.Fatal(err)
	}
	if b.Offenses != 1 || b.Until <= 0 {
		t.Fatalf("首次应为 1 小时封禁: %+v", b)
	}
	if d := time.Until(time.Unix(b.Until, 0)); d < 50*time.Minute || d > 70*time.Minute {
		t.Fatalf("首次时长应约 1 小时, 实际 %v", d)
	}
	// 模拟到期: 状态翻为已过期后再次触发 -> 24 小时
	banMu.Lock()
	b.Until = time.Now().Add(-time.Hour).Unix()
	banMu.Unlock()
	_ = activeBans() // 归一化状态
	b, err = applyAutoBan(ip, "SSH 爆破自动拉黑")
	if err != nil {
		t.Fatal(err)
	}
	if b.Offenses != 2 {
		t.Fatalf("第二次 Offenses 应为 2, 实际 %d", b.Offenses)
	}
	if d := time.Until(time.Unix(b.Until, 0)); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("第二次时长应约 24 小时, 实际 %v", d)
	}
	// 第三次 -> 永久
	banMu.Lock()
	b.Until = time.Now().Add(-time.Hour).Unix()
	banMu.Unlock()
	_ = activeBans()
	b, err = applyAutoBan(ip, "SSH 爆破自动拉黑")
	if err != nil {
		t.Fatal(err)
	}
	if b.Offenses != 3 || b.Until != 0 || b.Status != BanActive {
		t.Fatalf("第三次应为永久封禁: %+v", b)
	}
	// 第四次仍永久, 计数继续
	releaseBan(ip)
	b, err = applyAutoBan(ip, "SSH 爆破自动拉黑")
	if err != nil {
		t.Fatal(err)
	}
	if b.Offenses != 4 || b.Until != 0 {
		t.Fatalf("第四次应仍为永久: %+v", b)
	}
}

func TestManualBanDoesNotAffectLadder(t *testing.T) {
	banTestSetup(t)
	ip := "203.0.113.61"
	if _, err := applyBan(ip, "手动", "manual", 24); err != nil {
		t.Fatal(err)
	}
	releaseBan(ip)
	b, err := applyAutoBan(ip, "SSH 爆破自动拉黑")
	if err != nil {
		t.Fatal(err)
	}
	if b.Offenses != 1 {
		t.Fatalf("手动拉黑不应计入自动次数, Offenses 实际 %d", b.Offenses)
	}
	if d := time.Until(time.Unix(b.Until, 0)); d < 50*time.Minute || d > 70*time.Minute {
		t.Fatalf("手动后首次自动应仍为 1 小时, 实际 %v", d)
	}
}

func TestAutoBanHoursTable(t *testing.T) {
	if got := autoBanHours(1); got != 1 {
		t.Fatalf("offenses=1 应为 1 小时, 实际 %d", got)
	}
	if got := autoBanHours(2); got != 24 {
		t.Fatalf("offenses=2 应为 24 小时, 实际 %d", got)
	}
	for _, n := range []int{3, 4, 100} {
		if got := autoBanHours(n); got != 0 {
			t.Fatalf("offenses=%d 应为永久(0), 实际 %d", n, got)
		}
	}
}
