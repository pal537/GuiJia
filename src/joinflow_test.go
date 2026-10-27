package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 加入失败回退：清模式与凭据、记 JoinError、HubURL 保留供加入页回填。
func TestRollbackJoin(t *testing.T) {
	defer setupNodeTest(t)()
	loadNodeIdentity()
	settings.RunMode = "managed"
	settings.HubURL = "https://hub.example.com"
	settings.HubName = "主服务器"
	settings.HubID = "hub12345"
	setNodeToken("dead-token")
	setNodePairingCode("old-code")
	rollbackJoin("rejected")
	if settings.RunMode != "" || settings.JoinError != "rejected" {
		t.Fatalf("回退后模式应空且 JoinError=rejected, 得到 mode=%q joinError=%q", settings.RunMode, settings.JoinError)
	}
	if settings.HubName != "" || settings.HubID != "" {
		t.Fatalf("回退后主服务器名/ID 应清空, 得到 %q/%q", settings.HubName, settings.HubID)
	}
	if settings.HubURL != "https://hub.example.com" {
		t.Fatalf("回退后 HubURL 应保留供回填, 得到 %q", settings.HubURL)
	}
	if nodeToken() != "" || nodePairingCode() != "" {
		t.Fatalf("回退后 token 与码应清掉, 得到 token=%q code=%q", nodeToken(), nodePairingCode())
	}
	// 已是未定状态时回退不应改写 JoinError
	rollbackJoin("revoked")
	if settings.JoinError != "rejected" {
		t.Fatalf("二次回退不应改写 JoinError, 得到 %q", settings.JoinError)
	}
}

// 拨号器 hello 明确被拒（403）应回 errLinkRejected，不再是重试文案。
func TestLinkHelloRejected(t *testing.T) {
	defer setupLinkTest(t)()
	loadNodeIdentity()
	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"配对码无效或已过期"}`))
	}))
	defer hubSrv.Close()
	settings.HubURL = hubSrv.URL
	setNodePairingCode("bad-code")
	err := linkSession()
	if !errors.Is(err, errLinkRejected) {
		t.Fatalf("hello 403 应回 errLinkRejected, 得到 %v", err)
	}
}

// 加入被拒时的回退原因：有 token = 曾配对成功、主服务器删了记录；无 token = 码被拒。
func TestRejectReason(t *testing.T) {
	defer setupNodeTest(t)()
	loadNodeIdentity()
	clearNodeToken()
	if rejectReason() != "rejected" {
		t.Fatalf("无 token 应为 rejected")
	}
	setNodeToken("old-token")
	if rejectReason() != "revoked" {
		t.Fatalf("有 token 应为 revoked")
	}
}

// 群控状态页只给已配对成功（持有 token）的节点；managed 但无 token 一律走加入页。
func TestUseManagedPage(t *testing.T) {
	defer setupNodeTest(t)()
	loadNodeIdentity()
	cases := []struct {
		mode, token string
		want        bool
	}{
		{"managed", "tok", true},
		{"managed", "", false},
		{"standalone", "tok", false},
		{"", "", false},
	}
	for _, c := range cases {
		settings.RunMode = c.mode
		if c.token != "" {
			setNodeToken(c.token)
		} else {
			clearNodeToken()
		}
		if useManagedPage() != c.want {
			t.Fatalf("mode=%q token=%q 应为 %v", c.mode, c.token, c.want)
		}
	}
}

// 配对成功后的状态页只剩一行大字，不含任何信息行、错误与 hub-code 提示。
func TestManagedHTMLSingleLine(t *testing.T) {
	s := string(managedHTML)
	if !strings.Contains(s, "本机已被主服务器群控") {
		t.Fatalf("状态页应含一行大字")
	}
	for _, bad := range []string{"fName", "fHub", "fEngine", "fLink", "fLast", "fFp", "fNote",
		"hub-code", "最近错误", "api/node/status", "fetch(", "<script",
		"管理操作请去主服务器面板", "防护引擎", "最后联系", "节点指纹"} {
		if strings.Contains(s, bad) {
			t.Fatalf("状态页不应含 %q", bad)
		}
	}
}

// 加入页等待态与回退提示元素齐全；提交加入不再 reload（错码留在加入页）。
func TestJoinPageWaitingUI(t *testing.T) {
	s := string(indexHTML)
	for _, want := range []string{
		`id="joinPending"`, `id="modeBtns"`,
		"已发送加入请求，等待主服务器确认",
		"function showChoice(joinError)", "function showJoinPending()",
		"加入请求被拒绝，请用新配对码重输",
		"已被主服务器移除，请用新配对码重新配对",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("加入页应含 %q", want)
		}
	}
	start := strings.Index(s, "$('#btnJoin').onclick=async()=>{")
	end := strings.Index(s, "$('#btnLogin').onclick")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("加入提交处理块定位失败")
	}
	if strings.Contains(s[start:end], "location.reload()") {
		t.Fatalf("加入提交成功后不应 reload，应进等待态")
	}
}
