package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestConnFwField: 总览首页按 fw 分流的唯一事实来源——连接响应的 fw 字段
// 必须等于 fwCoversPort(端口, 协议)。上一轮 API 脚本只验了"每条连接有 fw
// 键", 沙箱里连接列表为空时该断言恒真; 这里注入两条真实连接条目, 逐条
// 断言 fw 值, 并覆盖协议过滤与禁用规则不生效两种边界。
func TestConnFwField(t *testing.T) {
	pgMu.Lock()
	oldRules := pgRules
	pgRules = []*PortGuardRule{
		{ID: "t1", PortText: "18080", Proto: "tcp", Action: "deny",
			Source: FWSource{Kind: "all"}, Enabled: true, ranges: [][2]int{{18080, 18080}}},
		{ID: "t2", PortText: "18082", Proto: "all", Action: "allow",
			Source: FWSource{Kind: "all"}, Enabled: false, ranges: [][2]int{{18082, 18082}}},
	}
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = oldRules; pgMu.Unlock() }()

	// fwCoversPort 本体: 协议过滤 + 禁用规则不生效。
	if !fwCoversPort(18080, "tcp") {
		t.Errorf("18080/tcp 应被规则覆盖")
	}
	if fwCoversPort(18080, "udp") {
		t.Errorf("18080/udp 不应被仅 TCP 规则覆盖")
	}
	if fwCoversPort(18081, "tcp") {
		t.Errorf("18081 不应被任何规则覆盖")
	}
	if fwCoversPort(18082, "tcp") || fwCoversPort(18082, "udp") {
		t.Errorf("禁用的规则不应覆盖任何端口")
	}

	// 端点级: 注入两条连接, 一条在规则端口、一条不在, 断言响应 fw 值。
	connMu.Lock()
	oldConns := liveConns
	liveConns = map[string]*Conn{
		"203.0.113.201|18080|tcp": {SrcIP: "203.0.113.201", SrcPort: 40000, DstPort: 18080, Proto: "tcp", Since: 1700000000},
		"203.0.113.202|18081|tcp": {SrcIP: "203.0.113.202", SrcPort: 40001, DstPort: 18081, Proto: "tcp", Since: 1700000000},
	}
	connMu.Unlock()
	defer func() { connMu.Lock(); liveConns = oldConns; connMu.Unlock() }()

	req := httptest.NewRequest("GET", "/api/connections", nil)
	rec := httptest.NewRecorder()
	handleConnections(rec, req)
	if rec.Code != 200 {
		t.Fatalf("connections 应 200, 得到 %d: %s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("connections 应为 JSON 列表: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("应返回注入的 2 条连接, 实际 %d 条: %s", len(out), rec.Body.String())
	}
	want := map[float64]bool{18080: true, 18081: false}
	for _, c := range out {
		port, _ := c["port"].(float64)
		fw, ok := c["fw"].(bool)
		if !ok {
			t.Errorf("端口 %v 的连接缺 fw 布尔字段: %v", port, c)
			continue
		}
		if fw != want[port] {
			t.Errorf("端口 %v 的 fw 应为 %v, 得到 %v", port, want[port], fw)
		}
	}
}
