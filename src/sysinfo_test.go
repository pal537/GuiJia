package main

// 第 7 项回归测试: /proc/uptime 解析与开机时长读取。

import (
	"runtime"
	"testing"
)

func TestParseUptimeSeconds(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"12345.67 23456.78\n", 12345},
		{"0.00 0.00\n", 0},
		{"86400.00 0.00\n", 86400},
		{"90.9\n", 90},
		{"", 0},
		{"abc def\n", 0},
		{"-5.0 0.0\n", 0},
	}
	for _, c := range cases {
		if got := parseUptimeSeconds(c.in); got != c.want {
			t.Errorf("parseUptimeSeconds(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSysUptimeSecLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("仅 Linux 有 /proc/uptime")
	}
	if got := sysUptimeSec(); got <= 0 {
		t.Errorf("sysUptimeSec() = %d, want > 0", got)
	}
}
