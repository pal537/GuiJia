package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseIntelList(t *testing.T) {
	raw := "# FireHOL level1 sample\n" +
		"1.2.3.0/24\n" +
		"1.2.3.0/24\n" + // 重复去重, 不计 skipped
		"5.6.7.8\n" +
		"5.6.7.8 \n" + // 尾空格 + 重复
		"2001:db8::/32\n" + // 文档段, 保留段, 滤掉
		"2001:db8::1\n" + // 文档段内裸 IP, 滤掉
		"not-an-ip\n" +
		"999.1.1.1\n" +
		"11.0.0.5/24 extra-field\n" + // 首字段为准, 归一化为网段地址
		"127.0.0.0/8\n" + // 回环, 保留段
		"127.0.0.1\n" +
		"10.1.2.0/24\n" + // 私网
		"192.168.1.1\n" +
		"126.0.0.0/7\n" + // 超网含 127/8, 照样滤掉
		"::1\n" + // v6 回环
		"fe80::1\n" + // v6 链路本地
		"\n"
	v4, v6, skipped := parseIntelList([]byte(raw))
	// v4=3(1.2.3.0/24, 5.6.7.8, 11.0.0.0/24); v6=0(两个 v6 条目都是
	// 保留段); skipped=11(2 非法 + 2 文档段 + 7 保留段)。
	if len(v4) != 3 || len(v6) != 0 || skipped != 11 {
		t.Fatalf("v4=%v v6=%v skipped=%d, want 3/0/11", v4, v6, skipped)
	}
	want4 := map[string]bool{"1.2.3.0/24": true, "5.6.7.8": true, "11.0.0.0/24": true}
	for _, ip := range v4 {
		if !want4[ip] {
			t.Fatalf("unexpected v4 %q", ip)
		}
	}
}

func TestIntelOverlapsReserved(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"127.0.0.0/8", true},
		{"127.0.0.1", true},
		{"126.0.0.0/7", true}, // 含 127/8 的超网
		{"10.0.0.0/8", true},
		{"172.16.0.0/12", true},
		{"192.168.0.0/16", true},
		{"169.254.0.0/16", true},
		{"100.64.0.0/10", true},
		{"0.0.0.0/8", true},
		{"224.0.0.0/4", true},
		{"::1", true},
		{"::1/128", true},
		{"fe80::/10", true},
		{"fc00::/7", true},
		{"2001:db8::/32", true},
		{"8.8.8.8", false},
		{"1.2.3.0/24", false},
		{"2001:4860:4860::8888", false},
		{"9.9.9.9", false},
	}
	for _, c := range cases {
		if got := intelOverlapsReserved(c.in); got != c.want {
			t.Errorf("intelOverlapsReserved(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestChainHasLoopbackAccept(t *testing.T) {
	with := "chain input {\n\t\ttype filter hook input priority -100; policy accept;\n\t\tiif \"lo\" accept\n\t\tip saddr @intel4 drop\n\t}\n"
	without := "chain input {\n\t\ttype filter hook input priority -100; policy accept;\n\t\tip saddr @intel4 drop\n\t}\n"
	if !chainHasLoopbackAccept(with) {
		t.Errorf("should detect loopback accept")
	}
	if chainHasLoopbackAccept(without) {
		t.Errorf("should not detect loopback accept")
	}
}

func TestValidateIntelInput(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https ok", "https://example.com/list.txt", false},
		{"http ok", "http://example.com/list.txt", false},
		{"bad scheme", "ftp://example.com/list.txt", true},
		{"garbage", "not-a-url", true},
		{"empty", "", true},
	}
	for _, c := range cases {
		if err := validateIntelInput(c.url); (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestChunkStrings(t *testing.T) {
	var ips []string
	for i := 0; i < 4500; i++ {
		ips = append(ips, "10.0.0.1")
	}
	chunks := chunkStrings(ips, 2000)
	if len(chunks) != 3 || len(chunks[0]) != 2000 || len(chunks[1]) != 2000 || len(chunks[2]) != 500 {
		t.Fatalf("chunks sizes wrong: %v", []int{len(chunks), len(chunks[0]), len(chunks[1]), len(chunks[2])})
	}
	if len(chunkStrings(nil, 2000)) != 0 {
		t.Fatalf("empty input must give no chunks")
	}
}

func TestNormalizeTrustEntry(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4/24", "1.2.3.0/24", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"2001:db8::1/64", "2001:db8::/64", true},
		{"  9.9.9.9  ", "9.9.9.9", true},
		{"", "", false},
		{"nope", "", false},
		{"1.2.3.4/33", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeTrustEntry(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("normalizeTrustEntry(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestIntelSaveValidation(t *testing.T) {
	oldDir, oldDry, oldState := dataDir, dryBan, intelState
	dataDir = t.TempDir()
	dryBan = true
	intelState = IntelState{UpdatesPerDay: 4, Status: "never", PublicURL: intelDefaultPublicURL}
	defer func() {
		dataDir, dryBan, intelState = oldDir, oldDry, oldState
	}()

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/intel/save", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		handleIntelSave(w, req)
		return w
	}
	if w := post(`{"enabled":true,"publicUrl":"ftp://example.com/x.txt"}`); w.Code != 400 {
		t.Fatalf("enabled with bad scheme: code=%d, want 400", w.Code)
	}
	if w := post(`{"enabled":false,"publicUrl":"https://example.com/x.txt","updatesPerDay":6}`); w.Code != 200 {
		t.Fatalf("disabled save: code=%d, want 200", w.Code)
	}
	intelMu.Lock()
	saved := intelState
	intelMu.Unlock()
	if saved.Enabled || saved.PublicURL != "https://example.com/x.txt" || saved.UpdatesPerDay != 6 {
		t.Fatalf("saved state wrong: %+v", saved)
	}
	if w := post(`{"enabled":false,"publicUrl":""}`); w.Code != 200 {
		t.Fatalf("disabled save with empty url: code=%d, want 200", w.Code)
	}
	intelMu.Lock()
	saved = intelState
	intelMu.Unlock()
	if saved.PublicURL != intelDefaultPublicURL {
		t.Fatalf("empty url should default to FireHOL, got %q", saved.PublicURL)
	}

	req := httptest.NewRequest("GET", "/api/intel", nil)
	w := httptest.NewRecorder()
	handleIntelStatus(w, req)
	if w.Code != 200 {
		t.Fatalf("status code=%d, want 200", w.Code)
	}
	var st map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("status body not json: %v", err)
	}
	if _, ok := st["source"]; ok {
		t.Fatalf("status body must not contain source: %v", st)
	}
	if st["publicUrl"] != intelDefaultPublicURL || st["status"] != "未开启" {
		t.Fatalf("status body wrong: %v", st)
	}
	_ = http.StatusOK
}
