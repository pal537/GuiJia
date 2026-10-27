package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDNS01RecordNameAndValue(t *testing.T) {
	if got := dns01RecordName("example.com"); got != "_acme-challenge.example.com" {
		t.Errorf("record name = %q", got)
	}
	// 通配符与根域名共用一条记录名。
	if got := dns01RecordName("*.example.com"); got != "_acme-challenge.example.com" {
		t.Errorf("wildcard record name = %q", got)
	}
	// 硬编码向量：SHA256("tok-123.thumb-abc") 的 base64url。
	if got := dns01TXTValue("tok-123", "thumb-abc"); got != "q6ANNrte6PendxF1F8n-k7Za8OPhzgoXYH7xPiBPpYs" {
		t.Errorf("txt value = %q", got)
	}
}

// mockCF: 最小 Cloudflare API v4 模拟（zones + dns_records）。
type mockCF struct {
	mu      sync.Mutex
	zones   []map[string]string
	records map[string]map[string]string // id -> {zoneID, name, content}
	nextID  int
}

func newMockCF(t *testing.T) (*mockCF, *httptest.Server) {
	t.Helper()
	m := &mockCF{
		zones:   []map[string]string{{"id": "zone-1", "name": "example.com"}, {"id": "zone-2", "name": "sub.example.com"}},
		records: map[string]map[string]string{},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		write := func(v any) { json.NewEncoder(w).Encode(v) }
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			m.mu.Lock()
			zs := m.zones
			m.mu.Unlock()
			write(map[string]any{"success": true, "result": zs})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/dns_records"):
			var in struct {
				Type, Name, Content string
			}
			json.NewDecoder(r.Body).Decode(&in)
			m.mu.Lock()
			m.nextID++
			id := "rec-" + itoa(m.nextID)
			zoneID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/zones/"), "/dns_records")
			m.records[id] = map[string]string{"zoneID": zoneID, "name": in.Name, "content": in.Content}
			m.mu.Unlock()
			write(map[string]any{"success": true, "result": map[string]string{"id": id}})
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/dns_records/"):
			parts := strings.Split(r.URL.Path, "/")
			id := parts[len(parts)-1]
			m.mu.Lock()
			delete(m.records, id)
			m.mu.Unlock()
			write(map[string]any{"success": true, "result": map[string]string{"id": id}})
		default:
			w.WriteHeader(404)
			write(map[string]any{"success": false, "errors": []map[string]string{{"message": "not found"}}})
		}
	}))
	t.Cleanup(srv.Close)
	return m, srv
}

func TestCFClientZonesCreateDelete(t *testing.T) {
	m, srv := newMockCF(t)
	old := cfAPIBase
	cfAPIBase = srv.URL
	t.Cleanup(func() { cfAPIBase = old })
	c := newCFClient("test-token")
	// 最长匹配：a.sub.example.com 应落到 sub.example.com 的 zone-2。
	z, err := c.findZoneID("a.sub.example.com")
	if err != nil || z != "zone-2" {
		t.Fatalf("findZoneID = %q, %v", z, err)
	}
	if z, err := c.findZoneID("example.com"); err != nil || z != "zone-1" {
		t.Fatalf("findZoneID example.com = %q, %v", z, err)
	}
	if _, err := c.findZoneID("other.org"); err == nil {
		t.Error("未托管域名应报错")
	}
	id, err := c.createTXT("zone-1", "_acme-challenge.example.com", "v123")
	if err != nil || id == "" {
		t.Fatalf("createTXT: %v %q", err, id)
	}
	m.mu.Lock()
	n := len(m.records)
	m.mu.Unlock()
	if n != 1 {
		t.Fatalf("应有 1 条记录，实际 %d", n)
	}
	if err := c.deleteTXT("zone-1", id); err != nil {
		t.Fatalf("deleteTXT: %v", err)
	}
	m.mu.Lock()
	n = len(m.records)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("删除后应无记录，实际 %d", n)
	}
	// API success=false 应 surfacing 为错误。
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]string{{"message": "bad token"}}})
	}))
	t.Cleanup(bad.Close)
	cfAPIBase = bad.URL
	if _, err := newCFClient("x").findZoneID("example.com"); err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Errorf("API 错误应透传，得到 %v", err)
	}
}

func TestCFWaitTXT(t *testing.T) {
	// DoH 模拟：值被拆成两段引号字符串返回，验证拼接逻辑。
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := "q6ANNrte6PendxF1F8n-k7Za8OPhzgoXYH7xPiBPpYs"
		half := len(v) / 2
		json.NewEncoder(w).Encode(map[string]any{
			"Answer": []map[string]string{{"data": `"` + v[:half] + `" "` + v[half:] + `"`}},
		})
	}))
	t.Cleanup(doh.Close)
	oldBase, oldEvery, oldTimeout := cfDoHBase, cfDoHPollEvery, cfDoHTimeout
	cfDoHBase, cfDoHPollEvery, cfDoHTimeout = doh.URL, 10*time.Millisecond, 5*time.Second
	t.Cleanup(func() { cfDoHBase, cfDoHPollEvery, cfDoHTimeout = oldBase, oldEvery, oldTimeout })
	if err := cfWaitTXT("_acme-challenge.example.com", "q6ANNrte6PendxF1F8n-k7Za8OPhzgoXYH7xPiBPpYs"); err != nil {
		t.Fatalf("分段 TXT 应判定生效: %v", err)
	}
	// 一直无记录应超时。
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"Answer": []any{}})
	}))
	t.Cleanup(empty.Close)
	cfDoHBase, cfDoHTimeout = empty.URL, 50*time.Millisecond
	if err := cfWaitTXT("_acme-challenge.example.com", "nope"); err == nil {
		t.Error("无记录应超时报错")
	}
}

func TestCFTokenStorageAndHandler(t *testing.T) {
	dir := t.TempDir()
	old := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = old })
	if cfTokenConfigured() {
		t.Error("初始应未配置")
	}
	// GET 未配置。
	rec := httptest.NewRecorder()
	handleCFToken(rec, httptest.NewRequest("GET", "/api/certs/cf-token", nil))
	var g struct {
		Configured bool   `json:"configured"`
		Token      string `json:"token"`
	}
	json.NewDecoder(rec.Body).Decode(&g)
	if g.Configured || g.Token != "" {
		t.Errorf("未配置时 GET = %+v", g)
	}
	// POST 保存：文件 0600、内容为原值。
	req := httptest.NewRequest("POST", "/api/certs/cf-token", strings.NewReader(`{"token":"cf-abc-123"}`))
	rec = httptest.NewRecorder()
	handleCFToken(rec, req)
	if rec.Code != 200 {
		t.Fatalf("POST 保存应 200，实际 %d", rec.Code)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "certs", "cf-token"))
	if string(b) != "cf-abc-123" {
		t.Errorf("Token 文件内容 = %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "certs", "cf-token")); fi.Mode().Perm() != 0600 {
		t.Errorf("Token 文件权限应 0600，实际 %o", fi.Mode().Perm())
	}
	// GET 已配置：只返回星号，绝不明文。
	rec = httptest.NewRecorder()
	handleCFToken(rec, httptest.NewRequest("GET", "/api/certs/cf-token", nil))
	json.NewDecoder(rec.Body).Decode(&g)
	if !g.Configured || g.Token != tgTokenMask {
		t.Errorf("已配置时 GET 应只返回星号，实际 %+v", g)
	}
	// POST 星号 = 未改动，文件内容不变。
	req = httptest.NewRequest("POST", "/api/certs/cf-token", strings.NewReader(`{"token":"********"}`))
	rec = httptest.NewRecorder()
	handleCFToken(rec, req)
	b, _ = os.ReadFile(filepath.Join(dir, "certs", "cf-token"))
	if string(b) != "cf-abc-123" {
		t.Errorf("星号提交不应覆盖，实际 %q", b)
	}
	// POST 空 = 清除。
	req = httptest.NewRequest("POST", "/api/certs/cf-token", strings.NewReader(`{"token":""}`))
	rec = httptest.NewRecorder()
	handleCFToken(rec, req)
	if cfTokenConfigured() {
		t.Error("空 Token 应清除配置")
	}
}
