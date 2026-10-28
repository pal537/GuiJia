package main

import (
	"strings"
	"testing"
)

// TestFloodPortListed: 手动洪峰端口集合只认手动列表, 不自动包含其他端口;
// 空列表不对任何端口触发; 解析失败 fail-closed(空集)。
func TestFloodPortListed(t *testing.T) {
	oldS := settings
	oldRaw, oldSet := floodPortsRaw, floodPortsSet
	defer func() {
		settings = oldS
		floodPortsMu.Lock()
		floodPortsRaw, floodPortsSet = oldRaw, oldSet
		floodPortsMu.Unlock()
	}()
	settings.FloodPorts = "22, 443，8000-8010 / 3005"
	if !floodPortListed(22) || !floodPortListed(443) || !floodPortListed(8005) || !floodPortListed(3005) {
		t.Fatal("手动列表内的端口(单个/范围/混合分隔)都应命中")
	}
	if floodPortListed(80) || floodPortListed(8011) || floodPortListed(59188) {
		t.Fatal("列表外的端口(哪怕是面板端口)都不应自动命中")
	}
	// 文本变化时缓存重建
	settings.FloodPorts = "9000"
	if floodPortListed(22) || !floodPortListed(9000) {
		t.Fatal("列表文本变化后应按新列表判定")
	}
	// 空列表: 不对任何端口触发
	settings.FloodPorts = ""
	if floodPortListed(22) || floodPortListed(9000) {
		t.Fatal("空列表时洪峰防护不对任何端口触发")
	}
	// 非法文本: 解析失败 = 空集, 不触发
	settings.FloodPorts = "22;abc"
	if floodPortListed(22) {
		t.Fatal("解析失败时应 fail-closed, 不触发任何端口")
	}
}

// TestSplitPortTokens: 统一分隔符(逗号/中文逗号/斜杠/反斜杠/顿号/空白),
// 短横线两侧空白归一; 非法符号由调用方报错, 这里只验分段。
func TestSplitPortTokens(t *testing.T) {
	cases := map[string][]string{
		"80,443":        {"80", "443"},
		"80，443":        {"80", "443"},
		"80 443":        {"80", "443"},
		"80\t443\n8000": {"80", "443", "8000"},
		"80/443\\22、33": {"80", "443", "22", "33"},
		"80,,  443":     {"80", "443"},
		"80 - 90":       {"80-90"},
		"8000-8010":     {"8000-8010"},
	}
	for in, want := range cases {
		got := splitPortTokens(in)
		if len(got) != len(want) {
			t.Fatalf("splitPortTokens(%q) = %v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("splitPortTokens(%q) = %v, want %v", in, got, want)
			}
		}
	}
}

// TestParsePortRangesIllegalSymbol: 非法符号报错文案保持 PAPA 原话。
func TestParsePortRangesIllegalSymbol(t *testing.T) {
	for _, in := range []string{"8080;8443", "8080|8443", "80,abc", "80-90-100"} {
		if _, err := parsePortRanges(in); err == nil || !strings.Contains(err.Error(), "不对，不可以") && !strings.Contains(err.Error(), "格式不对") {
			t.Fatalf("parsePortRanges(%q) 应报错, 实际 %v", in, err)
		}
	}
	if _, err := parsePortRanges("80;443"); !strings.Contains(err.Error(), "符号 ';' 不对，不可以") {
		t.Fatalf("分号报错应点名符号, 实际 %v", err)
	}
}
