package main

// 1.8.9 通知统一化 + 端口防护规则编辑的回归测试。

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewConnAlertSSHGate(t *testing.T) {
	dir := banTestSetup(t)
	cfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfg, []byte("Port 16722\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUIJIA_SSHD_CONFIG", cfg)

	oldS := settings
	oldDay := newConnAlertDay
	defer func() { settings = oldS; newConnAlertDay = oldDay }()
	newConnAlertDay = map[string]string{}
	settings.AlertNewConnStar = true
	settings.AlertSSHConn = false
	now := time.Now()

	if newConnAlert("203.0.113.10", 16722, now) {
		t.Fatal("SSH 连接开关关时, SSH 端口的新连接不应推送")
	}
	if !newConnAlert("203.0.113.10", 3005, now) {
		t.Fatal("SSH 连接开关关时, 非 SSH 重点端口的新连接应照常推送")
	}
	settings.AlertSSHConn = true
	if !newConnAlert("203.0.113.11", 16722, now) {
		t.Fatal("SSH 连接开关开时, SSH 端口的新连接应推送")
	}
}

func TestPortGuardItemEdit(t *testing.T) {
	dir := banTestSetup(t)
	oldData := dataDir
	dataDir = dir
	defer func() { dataDir = oldData }()
	pgMu.Lock()
	pgRules = []*PortGuardRule{
		{ID: "g1", PortText: "3005", Proto: "all", Source: FWSource{Kind: "custom_cn", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}, Action: "allow", BanHours: 24, Enabled: true, ranges: [][2]int{{3005, 3005}}},
		{ID: "g2", PortText: "4000", Proto: "all", Source: FWSource{Kind: "custom_cn", Locations: []GuardLocation{{Kind: "province", Name: "浙江"}}}, Action: "allow", BanHours: 24, Enabled: true, ranges: [][2]int{{4000, 4000}}},
	}
	pgMu.Unlock()
	defer func() { pgMu.Lock(); pgRules = nil; pgMu.Unlock() }()

	put := func(id, body string) int {
		req := httptest.NewRequest("PUT", "/api/portguard/"+id, bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handlePortGuardItem(rec, req)
		return rec.Code
	}
	// 整条编辑: 端口 + 省市(时长已废弃: 传了也忽略, 存量随编辑归一化为永久 0)
	if code := put("g1", `{"portText":"3006","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"banHours":48}`); code != 200 {
		t.Fatalf("编辑应 200, 实际 %d", code)
	}
	pgMu.Lock()
	r := pgRules[0]
	pgMu.Unlock()
	if r.PortText != "3006" || len(r.ranges) != 1 || r.ranges[0] != [2]int{3006, 3006} || r.BanHours != 0 {
		t.Fatalf("编辑未生效(时长应归一化为永久 0): %+v", r)
	}
	// 与另一条规则完全相同 -> 400, 且原规则不动
	if code := put("g1", `{"portText":"4000","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"浙江"}]},"banHours":24}`); code != 400 {
		t.Fatalf("完全相同规则应 400, 实际 %d", code)
	}
	pgMu.Lock()
	if pgRules[0].PortText != "3006" {
		t.Fatalf("重复失败后规则不应被改: %+v", pgRules[0])
	}
	pgMu.Unlock()
	// 只撞端口、来源不同 -> 200(同动作重叠按并集, 不冲突)
	if code := put("g1", `{"portText":"4000","source":{"kind":"custom_cn","locations":[{"kind":"province","name":"江苏"}]},"banHours":24}`); code != 200 {
		t.Fatalf("来源不同的同端口规则应 200, 实际 %d", code)
	}
	// 旧的纯开关切换仍可用
	if code := put("g1", `{"enabled":false}`); code != 200 {
		t.Fatalf("开关切换应 200, 实际 %d", code)
	}
	pgMu.Lock()
	if pgRules[0].Enabled {
		t.Fatal("开关切换未生效")
	}
	pgMu.Unlock()
	// 不存在的规则 -> 404
	if code := put("gx", `{"enabled":true}`); code != 404 {
		t.Fatalf("不存在的规则应 404, 实际 %d", code)
	}
}

func TestHoneypotAlertMirror(t *testing.T) {
	dir := banTestSetup(t)
	oldData, oldSetting, oldHp := dataDir, settingFile, honeypotFile
	dataDir = dir
	settingFile = filepath.Join(dir, "settings.json")
	honeypotFile = filepath.Join(dir, "honeypot.json")
	defer func() { dataDir, settingFile, honeypotFile = oldData, oldSetting, oldHp }()

	honeypotMu.Lock()
	honeypotCfg.AlertEnabled = true
	honeypotMu.Unlock()

	// 蜜罐保存不传 alertEnabled -> 沿用现值(true), 不许静默关掉
	req := httptest.NewRequest("POST", "/api/honeypot", bytes.NewBufferString(`{"enabled":false,"ports":[],"autoBan":false,"hitThreshold":1,"banHours":24}`))
	rec := httptest.NewRecorder()
	handleHoneypot(rec, req)
	if rec.Code != 200 {
		t.Fatalf("蜜罐保存应 200, 实际 %d", rec.Code)
	}
	honeypotMu.Lock()
	kept := honeypotCfg.AlertEnabled
	honeypotMu.Unlock()
	if !kept {
		t.Fatal("蜜罐保存缺 alertEnabled 时应沿用现值, 不应静默关掉")
	}

	// 设置页 PUT alertHoneypotHit=false -> 写回蜜罐配置
	oldS := settings
	defer func() { settings = oldS }()
	body, _ := json.Marshal(map[string]any{
		"tgEnabled": false, "alertHoneypotHit": false,
		"bruteWindowMin": 10, "bruteThreshold": 5, "floodWindowMin": 1,
		"floodDistinctIps": 30, "floodCloseMin": 60, "logKeepDays": 30,
		"newSrcKeepDays": 7, "ledgerKeepDays": 7, "reportTime": "09:00",
	})
	req = httptest.NewRequest("PUT", "/api/settings", bytes.NewBuffer(body))
	rec = httptest.NewRecorder()
	handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("设置保存应 200, 实际 %d", rec.Code)
	}
	honeypotMu.Lock()
	after := honeypotCfg.AlertEnabled
	honeypotMu.Unlock()
	if after {
		t.Fatal("设置页关蜜罐命中报警后, 蜜罐配置应同步关掉")
	}

	// 设置页 GET 应镜像出 alertHoneypotHit=false
	req = httptest.NewRequest("GET", "/api/settings", nil)
	rec = httptest.NewRecorder()
	handleSettings(rec, req)
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if v, _ := m["alertHoneypotHit"].(bool); v {
		t.Fatal("设置页 GET 应镜像蜜罐命中报警=false")
	}
}
