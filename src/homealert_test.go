package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupHomeAlertTest(t *testing.T) (func(), string) {
	t.Helper()
	restore := setupHubTest(t)
	dir := t.TempDir()
	oldSeenFile, oldSeen := homeSeenFile, homeSeen
	homeSeenFile = filepath.Join(dir, "home-seen.json")
	homeSeen = map[string]bool{}
	return func() {
		homeSeenFile, homeSeen = oldSeenFile, oldSeen
		restore()
	}, dir
}

func callHomeAlerts(t *testing.T) []string {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/nodes/home-alerts", nil)
	rec := httptest.NewRecorder()
	handleNodeHomeAlerts(rec, req)
	if rec.Code != 200 {
		t.Fatalf("alerts status = %d, want 200", rec.Code)
	}
	var out struct {
		New []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"new"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("alerts decode: %v", err)
	}
	fps := []string{}
	for _, n := range out.New {
		fps = append(fps, n.Fingerprint)
	}
	return fps
}

func callHomeAck(t *testing.T, body string) int {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/nodes/home-ack", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleNodeHomeAck(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ack status = %d, want 200", rec.Code)
	}
	var out struct {
		Acked int `json:"acked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("ack decode: %v", err)
	}
	return out.Acked
}

func TestHomeAlertsAckFlow(t *testing.T) {
	restore, dir := setupHomeAlertTest(t)
	defer restore()
	fpA := strings.Repeat("a", 64)
	fpB := strings.Repeat("b", 64)
	hubServers = []*hubServer{
		{Fingerprint: fpA, Name: "节点A", Status: "online", CreatedAt: 1000},
		{Fingerprint: fpB, Name: "节点B", Status: "offline", LastSeen: 2000, CreatedAt: 2000},
	}
	// 初始: 两台都是新设备。
	if got := callHomeAlerts(t); len(got) != 2 {
		t.Fatalf("alerts = %v, want 2", got)
	}
	// 确认一台: 只剩另一台; 非法指纹与未登记指纹不计入。
	if n := callHomeAck(t, `{"fingerprints":["`+fpA+`","xyz","`+strings.Repeat("c", 64)+`"]}`); n != 1 {
		t.Fatalf("acked = %d, want 1", n)
	}
	if got := callHomeAlerts(t); len(got) != 1 || got[0] != fpB {
		t.Fatalf("alerts after ack = %v, want [%s]", got, fpB)
	}
	// 落盘 0600, 且重启重载后仍有效。
	st, err := os.Stat(filepath.Join(dir, "home-seen.json"))
	if err != nil {
		t.Fatalf("home-seen.json missing: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("home-seen.json perm = %o, want 0600", st.Mode().Perm())
	}
	homeSeen = map[string]bool{}
	loadHomeSeen()
	if got := callHomeAlerts(t); len(got) != 1 || got[0] != fpB {
		t.Fatalf("alerts after reload = %v, want [%s]", got, fpB)
	}
	// 确认第二台: 不再提醒; 重复确认计 0。
	if n := callHomeAck(t, `{"fingerprints":["`+fpB+`"]}`); n != 1 {
		t.Fatalf("acked2 = %d, want 1", n)
	}
	if got := callHomeAlerts(t); len(got) != 0 {
		t.Fatalf("alerts final = %v, want empty", got)
	}
	if n := callHomeAck(t, `{"fingerprints":["`+fpB+`"]}`); n != 0 {
		t.Fatalf("acked dup = %d, want 0", n)
	}
	// 方法校验。
	req := httptest.NewRequest("POST", "/api/nodes/home-alerts", nil)
	rec := httptest.NewRecorder()
	handleNodeHomeAlerts(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("alerts POST status = %d, want 405", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/nodes/home-ack", nil)
	rec = httptest.NewRecorder()
	handleNodeHomeAck(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("ack GET status = %d, want 405", rec.Code)
	}
}

func TestHomeAlertsNewNodeReappears(t *testing.T) {
	restore, _ := setupHomeAlertTest(t)
	defer restore()
	fpA := strings.Repeat("a", 64)
	fpB := strings.Repeat("b", 64)
	hubServers = []*hubServer{{Fingerprint: fpA, Name: "节点A", Status: "online", CreatedAt: 1000}}
	if n := callHomeAck(t, `{"fingerprints":["`+fpA+`"]}`); n != 1 {
		t.Fatalf("acked = %d, want 1", n)
	}
	if got := callHomeAlerts(t); len(got) != 0 {
		t.Fatalf("alerts = %v, want empty", got)
	}
	// 再接一台新节点: 提醒再次出现, 且只含新节点。
	hubServers = append(hubServers, &hubServer{Fingerprint: fpB, Name: "节点B", Status: "online", CreatedAt: 3000})
	if got := callHomeAlerts(t); len(got) != 1 || got[0] != fpB {
		t.Fatalf("alerts after new node = %v, want [%s]", got, fpB)
	}
}
