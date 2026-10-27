package main

// 第 7 项回归测试: 端口范围(解析/互斥切开/星标自排除/位图/多段重叠/接口)。

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func rangeTestSetup(t *testing.T) {
	t.Helper()
	banTestSetup(t)
	mu.Lock()
	oldPorts, oldRanges, oldIgn, oldIgnR := ports, portRanges, ignoredPorts, ignoredRanges
	ports = []*PortWatch{}
	portRanges = []*PortRange{}
	ignoredPorts = map[int]bool{}
	ignoredRanges = []PortRange{}
	rebuildPortIndex()
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		ports, portRanges, ignoredPorts, ignoredRanges = oldPorts, oldRanges, oldIgn, oldIgnR
		rebuildPortIndex()
		mu.Unlock()
	})
}

func mustSegs(t *testing.T, spec string) []rangeSeg {
	t.Helper()
	segs, err := parsePortSpec(spec)
	if err != nil {
		t.Fatalf("解析 %q 应成功, 实际 %v", spec, err)
	}
	return segs
}

func TestParsePortSpec(t *testing.T) {
	if segs := mustSegs(t, "443"); len(segs) != 1 || segs[0] != (rangeSeg{443, 443}) {
		t.Fatalf("单个解析错误: %+v", segs)
	}
	if segs := mustSegs(t, "8000-8010"); len(segs) != 1 || segs[0] != (rangeSeg{8000, 8010}) {
		t.Fatalf("范围解析错误: %+v", segs)
	}
	if segs := mustSegs(t, "80,443,8000-8010"); len(segs) != 3 {
		t.Fatalf("组合解析应得 3 段, 实际 %+v", segs)
	}
	for _, bad := range []string{"", "0", "65536", "8000-7999", "abc", "80,,443", "80-"} {
		if _, err := parsePortSpec(bad); err == nil {
			t.Fatalf("非法输入 %q 应报错", bad)
		}
	}
	if _, err := parsePortSpec("80,abc"); !strings.Contains(err.Error(), "第 2 段") {
		t.Fatalf("错误信息应点名段号, 实际 %v", err)
	}
}

func TestPlanPlainOverStar(t *testing.T) {
	rangeTestSetup(t)
	mu.Lock()
	ports = []*PortWatch{{Port: 5000, Proto: "tcp", Star: true, Source: "manual", Kind: "other"}}
	rebuildPortIndex()
	plan := planRangeAdd(mustSegs(t, "4000-6000"), false, "测试", "other")
	mu.Unlock()
	if len(plan.ToAdd) != 2 || plan.ToAdd[0].From != 4000 || plan.ToAdd[0].To != 4999 || plan.ToAdd[1].From != 5001 || plan.ToAdd[1].To != 6000 {
		t.Fatalf("普通撞星标应切开为两段, 实际 %+v", plan.ToAdd)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].From != 5000 {
		t.Fatalf("应跳过已星标的 5000, 实际 %+v", plan.Skipped)
	}
	if len(plan.Cut) != 0 {
		t.Fatalf("加普通不应切已有条目, 实际 %+v", plan.Cut)
	}
	mu.Lock()
	applyRangeAddPlan(plan)
	mu.Unlock()
	if p := lookupPort(5000); p == nil || !p.Star {
		t.Fatal("5000 应保持星标")
	}
	if p := lookupPort(4000); p == nil || p.Star {
		t.Fatal("4000 应为普通监控")
	}
	if c, s := coverCounts(); c != 2001 || s != 1 {
		t.Fatalf("覆盖数应为 2001/星标 1, 实际 %d/%d", c, s)
	}
}

func TestPlanStarOverPlain(t *testing.T) {
	rangeTestSetup(t)
	mu.Lock()
	portRanges = []*PortRange{{From: 4000, To: 6000, Star: false, Source: "manual", Kind: "other"}}
	rebuildPortIndex()
	plan := planRangeAdd(mustSegs(t, "5000"), true, "测试", "other")
	mu.Unlock()
	if len(plan.ToAdd) != 1 || plan.ToAdd[0].From != 5000 || !plan.ToAdd[0].Star {
		t.Fatalf("星标单个应独立, 实际 %+v", plan.ToAdd)
	}
	if len(plan.Cut) != 1 || plan.Cut[0].From != 4000 || len(plan.Cut[0].Remain) != 2 {
		t.Fatalf("普通范围应切开为两段, 实际 %+v", plan.Cut)
	}
	mu.Lock()
	applyRangeAddPlan(plan)
	mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if len(portRanges) != 2 || portRanges[0].From != 4000 || portRanges[0].To != 4999 || portRanges[1].From != 5001 || portRanges[1].To != 6000 {
		t.Fatalf("应用后普通范围应剩两段, 实际 %+v", portRanges)
	}
	if p := findPort(5000); p == nil || !p.Star {
		t.Fatal("5000 应为星标单个")
	}
}

func TestPlanStarOverPlainSingle(t *testing.T) {
	rangeTestSetup(t)
	mu.Lock()
	ports = []*PortWatch{{Port: 5000, Proto: "tcp", Star: false, Source: "manual", Kind: "other"}}
	rebuildPortIndex()
	plan := planRangeAdd(mustSegs(t, "5000"), true, "测试", "other")
	applyRangeAddPlan(plan)
	mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if len(ports) != 1 || !ports[0].Star || ports[0].Port != 5000 {
		t.Fatalf("星标单个应顶掉普通单个, 实际 %+v", ports)
	}
}

func TestPlanContained(t *testing.T) {
	rangeTestSetup(t)
	mu.Lock()
	defer mu.Unlock()
	portRanges = []*PortRange{{From: 4000, To: 6000, Star: false, Source: "manual", Kind: "other"}}
	rebuildPortIndex()
	plan := planRangeAdd(mustSegs(t, "5000"), false, "测试", "other")
	if len(plan.ToAdd) != 0 || len(plan.Skipped) == 0 {
		t.Fatalf("已包含的单个应无新增、有跳过, 实际 %+v", plan)
	}
}

func TestPlanStarSelfExclusion(t *testing.T) {
	rangeTestSetup(t)
	t.Setenv("GUIJIA_PORT", "18790")
	mu.Lock()
	defer mu.Unlock()
	rebuildPortIndex()
	plan := planRangeAdd(mustSegs(t, "18790-18795"), true, "测试", "other")
	if len(plan.ExcludedSelf) != 2 || plan.ExcludedSelf[0] != 18790 || plan.ExcludedSelf[1] != 18793 {
		t.Fatalf("星标范围应排除 18790 与 18793, 实际 %v", plan.ExcludedSelf)
	}
	if len(plan.ToAdd) != 2 || plan.ToAdd[0].From != 18791 || plan.ToAdd[0].To != 18792 || plan.ToAdd[1].From != 18794 || plan.ToAdd[1].To != 18795 {
		t.Fatalf("排除自身端口后应剩两段, 实际 %+v", plan.ToAdd)
	}
	// 只监控不排除
	plan = planRangeAdd(mustSegs(t, "18790-18795"), false, "测试", "other")
	if len(plan.ExcludedSelf) != 0 {
		t.Fatalf("只监控时不应排除自身端口, 实际 %v", plan.ExcludedSelf)
	}
}

func TestPlanMultiSegmentOverlap(t *testing.T) {
	rangeTestSetup(t)
	mu.Lock()
	defer mu.Unlock()
	rebuildPortIndex()
	// 同请求内段重叠: 后段已被前段覆盖, 不重复存
	plan := planRangeAdd(mustSegs(t, "4000-6000,5000"), false, "测试", "other")
	if len(plan.ToAdd) != 1 || plan.ToAdd[0].From != 4000 || plan.ToAdd[0].To != 6000 {
		t.Fatalf("重叠段应只存一次, 实际 %+v", plan.ToAdd)
	}
	// 星标多段连环切: 先切出 5000, 再整段星标化
	portRanges = []*PortRange{{From: 4000, To: 6000, Star: false, Source: "manual", Kind: "other"}}
	rebuildPortIndex()
	plan = planRangeAdd(mustSegs(t, "5000,4000-6000"), true, "测试", "other")
	applyRangeAddPlan(plan)
	if c, s := coverCounts(); c != 2001 || s != 2001 {
		t.Fatalf("连环切后应全为星标 2001, 实际覆盖 %d/星标 %d", c, s)
	}
	for _, r := range portRanges {
		if !r.Star {
			t.Fatalf("不应残留普通范围, 实际 %+v", portRanges)
		}
	}
}

func TestRangeHTTPCycle(t *testing.T) {
	rangeTestSetup(t)
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/ports", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handlePorts(rec, req)
		return rec
	}
	// 先加普通范围
	if rec := post(`{"spec":"4000-6000","name":"测试","kind":"other"}`); rec.Code != 200 {
		t.Fatalf("加普通范围应成功, 实际 %d %s", rec.Code, rec.Body.String())
	}
	// 再加星标单个撞上: 预览(未确认不应用)
	rec := post(`{"spec":"5000","star":true,"name":"测试","kind":"other"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "needConfirm") {
		t.Fatalf("撞上普通范围应先返回预览, 实际 %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	if len(portRanges) != 1 {
		t.Fatalf("预览阶段不应已应用, 实际 %+v", portRanges)
	}
	mu.Unlock()
	// 确认后应用: 范围切开 + 星标单个
	if rec := post(`{"spec":"5000","star":true,"name":"测试","kind":"other","confirm":true}`); rec.Code != 200 {
		t.Fatalf("确认后应成功, 实际 %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	if len(portRanges) != 2 || findPort(5000) == nil || !findPort(5000).Star {
		t.Fatalf("确认后应切开并立星标, ranges=%+v ports=%+v", portRanges, ports)
	}
	mu.Unlock()
	// 范围里的端口走单个接口应 404 指明范围
	req := httptest.NewRequest("PUT", "/api/ports/4001", strings.NewReader(`{"name":"x"}`))
	rec2 := httptest.NewRecorder()
	handlePortItem(rec2, req)
	if rec2.Code != 404 || !strings.Contains(rec2.Body.String(), "4000-4999") {
		t.Fatalf("范围端口单个接口应 404 指明范围, 实际 %d %s", rec2.Code, rec2.Body.String())
	}
	// 删范围条目
	req = httptest.NewRequest("DELETE", "/api/ports", strings.NewReader(`{"from":4000,"to":4999}`))
	rec3 := httptest.NewRecorder()
	handlePorts(rec3, req)
	if rec3.Code != 200 {
		t.Fatalf("删范围应成功, 实际 %d %s", rec3.Code, rec3.Body.String())
	}
	// 星标范围开关: 把剩余普通范围翻成星标
	req = httptest.NewRequest("POST", "/api/ports/range/star", strings.NewReader(`{"from":5001,"to":6000,"star":true}`))
	rec4 := httptest.NewRecorder()
	handleRangeStar(rec4, req)
	if rec4.Code != 200 {
		t.Fatalf("范围星标开关应成功, 实际 %d %s", rec4.Code, rec4.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, r := range portRanges {
		if r.From == 5001 && !r.Star {
			t.Fatalf("5001-6000 应已翻成星标, 实际 %+v", portRanges)
		}
	}
}
