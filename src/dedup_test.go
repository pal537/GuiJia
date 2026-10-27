package main

// 第 8 项回归测试: TG 新连接提醒去重。
// 同一 (IP, 端口) 自然日内只推一次; 跨端口照常提醒; 已拉黑 IP 不再推。

import (
	"testing"
	"time"
)

func TestNewConnAlertDedup(t *testing.T) {
	newConnAlertDay = map[string]string{}
	day1a := time.Date(2026, 10, 24, 10, 0, 0, 0, time.Local)
	day1b := time.Date(2026, 10, 24, 23, 59, 0, 0, time.Local)
	day2 := time.Date(2026, 10, 25, 0, 1, 0, 0, time.Local)
	if !newConnAlertAllowed("203.0.113.51", 45167, day1a) {
		t.Fatal("当日首次应允许推送")
	}
	if newConnAlertAllowed("203.0.113.51", 45167, day1b) {
		t.Fatal("同一 (IP, 端口) 当日重复不应再推")
	}
	if !newConnAlertAllowed("203.0.113.51", 45168, day1b) {
		t.Fatal("同一 IP 不同端口应照常提醒(扫描信号)")
	}
	if !newConnAlertAllowed("203.0.113.52", 45167, day1b) {
		t.Fatal("不同 IP 应照常提醒")
	}
	if !newConnAlertAllowed("203.0.113.51", 45167, day2) {
		t.Fatal("次日应重新允许推送")
	}
}

func TestNewConnAlertBannedSuppressed(t *testing.T) {
	banTestSetup(t)
	oldAlert := settings.AlertNewConnStar
	settings.AlertNewConnStar = true
	t.Cleanup(func() { settings.AlertNewConnStar = oldAlert })
	newConnAlertDay = map[string]string{}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.Local)
	if _, err := applyBan("203.0.113.53", "test", "manual", 24); err != nil {
		t.Fatal(err)
	}
	if newConnAlert("203.0.113.53", 45167, now) {
		t.Fatal("已拉黑 IP 不应再推新连接提醒")
	}
	if !newConnAlert("203.0.113.54", 45167, now) {
		t.Fatal("未拉黑 IP 当日首次应允许推送")
	}
	settings.AlertNewConnStar = false
	if newConnAlert("203.0.113.54", 45168, now) {
		t.Fatal("开关关闭时不应推送")
	}
}
