package main

// TG 急救全网化 + 主服务器身份识别回归(2026-10-28, PAPA 三点之一、二):
// 节点侧急救接口只认内部头; 主服务器判定含待添加; 被控节点禁设本地密码。

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestRescueNodeEndpointsRequireInternal(t *testing.T) {
	banTestSetup(t)
	// 无内部头: 面板代理调它只能拿到 403。
	req := httptest.NewRequest("POST", "/api/rescue/unban-node", nil)
	rec := httptest.NewRecorder()
	handleRescueNodeUnbanAll(rec, req)
	if rec.Code != 403 {
		t.Fatalf("无内部头应 403, 实际 %d", rec.Code)
	}
	// 有内部头、IP 非法: 400(说明已放行到业务层, 不是一律挡)。
	req = httptest.NewRequest("POST", "/api/rescue/trust-node", bytes.NewBufferString(`{"ip":"not-an-ip"}`))
	req.Header.Set("X-Guijia-Internal", "1")
	rec = httptest.NewRecorder()
	handleRescueNodeTrust(rec, req)
	if rec.Code != 400 {
		t.Fatalf("非法 IP 应 400, 实际 %d", rec.Code)
	}
}

func TestHubHasNodesIncludesPending(t *testing.T) {
	hubMu.Lock()
	oldServers, oldPending := hubServers, hubPending
	hubServers, hubPending = nil, nil
	hubMu.Unlock()
	defer func() {
		hubMu.Lock()
		hubServers, hubPending = oldServers, oldPending
		hubMu.Unlock()
	}()
	if hubHasNodes() {
		t.Fatal("无登记、无待添加时不应是主服务器")
	}
	hubMu.Lock()
	hubPending = []*hubPendingEntry{{Fingerprint: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"}}
	hubMu.Unlock()
	if !hubHasNodes() {
		t.Fatal("仅待添加也应算主服务器, 否则接入按钮会误现、待添加节点被孤儿化")
	}
	hubMu.Lock()
	hubPending = nil
	hubServers = []*hubServer{{Fingerprint: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", Name: "测试节点"}}
	hubMu.Unlock()
	if !hubHasNodes() {
		t.Fatal("已登记时应是主服务器")
	}
}

func TestRescuePasswordManagedGuard(t *testing.T) {
	protSyncTestSetup(t)
	mu.Lock()
	settings.RunMode = "managed"
	mu.Unlock()
	req := httptest.NewRequest("POST", "/api/rescue/password", bytes.NewBufferString(`{"password":"123456"}`))
	rec := httptest.NewRecorder()
	handleRescuePassword(rec, req)
	if rec.Code != 403 {
		t.Fatalf("被控节点设本地超级密码应 403, 实际 %d", rec.Code)
	}
}

func TestRescueScopeSuffix(t *testing.T) {
	hubMu.Lock()
	oldServers := hubServers
	hubServers = nil
	hubMu.Unlock()
	defer func() {
		hubMu.Lock()
		hubServers = oldServers
		hubMu.Unlock()
	}()
	if rescueScopeSuffix() != "" {
		t.Fatal("无在线节点时菜单不应带作用范围后缀, 单机行为须完全一致")
	}
}
