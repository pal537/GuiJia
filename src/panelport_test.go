package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWritePanelEnvPort(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guijia")
	orig := "# comment\nGUIJIA_DATA_DIR=/srv/x\nGUIJIA_PORT=59188\nOTHER=1\n"
	if err := os.WriteFile(p, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePanelEnvPort(p, 60001); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, want := range []string{"GUIJIA_PORT=60001", "GUIJIA_DATA_DIR=/srv/x", "# comment", "OTHER=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("改写后应保留 %q, 得到:\n%s", want, s)
		}
	}
	if strings.Contains(s, "59188") {
		t.Errorf("旧端口应被替换, 得到:\n%s", s)
	}
	// 不存在的文件: 新建, 只有 PORT 行。
	p2 := filepath.Join(dir, "new")
	if err := writePanelEnvPort(p2, 60002); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p2)
	if !strings.Contains(string(b), "GUIJIA_PORT=60002") {
		t.Errorf("新建文件应含新端口, 得到 %q", string(b))
	}
	// 已有文件但无 PORT 行: 追加, 不动已有行。
	p3 := filepath.Join(dir, "noport")
	if err := os.WriteFile(p3, []byte("GUIJIA_DATA_DIR=/srv/y\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePanelEnvPort(p3, 60003); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p3)
	if !strings.Contains(string(b), "GUIJIA_DATA_DIR=/srv/y") || !strings.Contains(string(b), "GUIJIA_PORT=60003") {
		t.Errorf("追加后两行都应有, 得到 %q", string(b))
	}
}

func TestProbePortFree(t *testing.T) {
	// 通配符监听占用时, 探测应失败。
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if err := probePortFree(port); err == nil {
		t.Errorf("被占端口 %d 探测应失败", port)
	}
	if err := probePortFree(freePort(t)); err != nil {
		t.Errorf("空闲端口探测应通过: %v", err)
	}
}

func TestHandlePanelPort(t *testing.T) {
	dir := t.TempDir()
	oldEnv, oldPort, oldRestart := panelEnvFile, panelPort, panelRestartFunc
	panelEnvFile = filepath.Join(dir, "guijia")
	panelPort = 15987
	restarted := make(chan struct{}, 1)
	panelRestartFunc = func() { restarted <- struct{}{} }
	t.Cleanup(func() { panelEnvFile, panelPort, panelRestartFunc = oldEnv, oldPort, oldRestart })

	for _, bad := range []string{`{"port":0}`, `{"port":70000}`, `{"port":-1}`} {
		rec := doJSON(t, handlePanelPort, "POST", "/api/panel/port", bad, "203.0.113.9:1234")
		if rec.Code != 400 {
			t.Errorf("非法端口 %s 应 400, 得到 %d", bad, rec.Code)
		}
	}
	// 相同端口: 不重启, 只同步文件。
	rec := doJSON(t, handlePanelPort, "POST", "/api/panel/port", `{"port":15987}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("相同端口应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	var same struct {
		Restart string `json:"restart"`
	}
	json.NewDecoder(rec.Body).Decode(&same)
	if same.Restart != "none" {
		t.Errorf("相同端口 restart 应为 none, 得到 %q", same.Restart)
	}
	b, _ := os.ReadFile(panelEnvFile)
	if !strings.Contains(string(b), "GUIJIA_PORT=15987") {
		t.Errorf("相同端口也应同步文件, 得到 %q", string(b))
	}
	// 改端口: 探活 + 写文件 + 回包 restart 字段; auto 时重启回调应触发。
	p := freePort(t)
	rec = doJSON(t, handlePanelPort, "POST", "/api/panel/port", fmt.Sprintf(`{"port":%d}`, p), "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("改端口应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	var chg struct {
		Restart string `json:"restart"`
		Port    int    `json:"port"`
	}
	json.NewDecoder(rec.Body).Decode(&chg)
	if chg.Port != p {
		t.Errorf("回包端口应为 %d, 得到 %d", p, chg.Port)
	}
	if chg.Restart != "auto" && chg.Restart != "manual" {
		t.Fatalf("改端口 restart 应为 auto 或 manual, 得到 %q", chg.Restart)
	}
	b, _ = os.ReadFile(panelEnvFile)
	if !strings.Contains(string(b), fmt.Sprintf("GUIJIA_PORT=%d", p)) {
		t.Errorf("改端口后文件应含新端口, 得到 %q", string(b))
	}
	if chg.Restart == "auto" {
		select {
		case <-restarted:
		case <-time.After(3 * time.Second):
			t.Error("auto 重启时重启回调应在 3 秒内触发")
		}
	}
}
