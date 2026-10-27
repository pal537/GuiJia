package main

// 第 3 项回归测试: nft 超时兜底(永久封禁 30 天内核超时; 定时封禁剩余秒数;
// 集合 flags 解析)。

import (
	"testing"
	"time"
)

func TestBanKernelTimeout(t *testing.T) {
	now := time.Now().Unix()
	// 永久封禁 -> 30 天兜底
	if got := banKernelTimeout(&Ban{IP: "203.0.113.80", Until: 0}, now); got != permBanBackstopSec {
		t.Fatalf("永久封禁应为 30 天兜底(%d 秒), 实际 %d", permBanBackstopSec, got)
	}
	if permBanBackstopSec != 30*24*3600 {
		t.Fatalf("兜底应为 30 天, 实际 %d 秒", permBanBackstopSec)
	}
	// 定时封禁 -> 剩余秒数
	if got := banKernelTimeout(&Ban{IP: "203.0.113.81", Until: now + 3600}, now); got != 3600 {
		t.Fatalf("定时封禁应为剩余 3600 秒, 实际 %d", got)
	}
	// 已过期(边界) -> 至少 1 秒, 不为 0(0 会被当成无超时)
	if got := banKernelTimeout(&Ban{IP: "203.0.113.82", Until: now - 10}, now); got < 1 {
		t.Fatalf("过期边界应至少 1 秒, 实际 %d", got)
	}
}

func TestParseSetFlagsJSON(t *testing.T) {
	with := `{"nftables":[{"set":{"name":"block4","table":"connwatch","family":"inet","type":"ipv4_addr","flags":["timeout"],"elem":[]}}]}`
	flags := parseSetFlagsJSON(with)
	found := false
	for _, f := range flags {
		if f == "timeout" {
			found = true
		}
	}
	if !found {
		t.Fatalf("带 timeout 的集合应解析出标志, 实际 %v", flags)
	}
	without := `{"nftables":[{"set":{"name":"block4","table":"connwatch","family":"inet","type":"ipv4_addr","elem":[]}}]}`
	if flags := parseSetFlagsJSON(without); len(flags) != 0 {
		t.Fatalf("无 flags 的集合应解析为空, 实际 %v", flags)
	}
	if flags := parseSetFlagsJSON(`not json`); flags != nil {
		t.Fatalf("畸形 JSON 应返回 nil, 实际 %v", flags)
	}
}

func TestPermanentBanGetsBackstop(t *testing.T) {
	// 端到端(干跑): 永久拉黑写入的内核元素应带 30 天超时, 而非无超时。
	// 干跑模式下 nft 命令只打印, 这里验证 upsert 路径算出的超时值。
	banTestSetup(t)
	b, err := applyBan("203.0.113.83", "test", "manual", 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Until != 0 {
		t.Fatal("永久封禁 Until 应为 0")
	}
	if got := banKernelTimeout(b, time.Now().Unix()); got != permBanBackstopSec {
		t.Fatalf("永久封禁写入内核时应带 30 天超时, 实际 %d", got)
	}
}
