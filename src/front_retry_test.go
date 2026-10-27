package main

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// closeFront80Test: 关掉测试里起的 80 前置并复位全局量。
func closeFront80Test(t *testing.T) {
	t.Helper()
	frontMu.Lock()
	srv := front80
	front80 = nil
	port80OK = false
	frontMu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

// closeFront443Test: 关掉测试里起的 443 前置并复位全局量。
func closeFront443Test(t *testing.T) {
	t.Helper()
	front443Mu.Lock()
	srv := front443Srv
	front443Srv = nil
	front443On = false
	front443Err = ""
	front443Mu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

func TestFrontEnsure80Retry(t *testing.T) {
	p := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	occ, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if frontEnsure80(addr) {
		t.Error("端口被占时补起应失败")
	}
	if frontPort80OK() {
		t.Error("端口被占时 port80OK 应为 false")
	}
	occ.Close()
	if !frontEnsure80(addr) {
		t.Error("占用释放后补起应成功")
	}
	if !frontPort80OK() {
		t.Error("补起后 port80OK 应为 true")
	}
	// 幂等: 再补一次仍是同一台在跑, 不重复绑定。
	if !frontEnsure80(addr) {
		t.Error("已在跑时补起应直接返回 true")
	}
	closeFront80Test(t)
	if frontPort80OK() {
		t.Error("清理后 port80OK 应为 false")
	}
}

func TestFrontEnsure443Retry(t *testing.T) {
	frontTestCfg(t, []*ProxyRule{
		{ID: "r1", Domain: "example.com", Listens: []ProxyListen{{Port: 443, Protocol: "https"}}, Cert: "auto", Backend: "127.0.0.1:8080", Enabled: true},
	})
	p := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	occ, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if frontEnsure443(addr) {
		t.Error("端口被占时补起应失败")
	}
	if on, _ := front443Status(); on {
		t.Error("端口被占时 443 应为未起")
	}
	occ.Close()
	if !frontEnsure443(addr) {
		t.Error("占用释放后补起应成功")
	}
	if on, _ := front443Status(); !on {
		t.Error("补起后 443 应为在跑")
	}
	// 无需求时补起即停掉。
	proxyMu.Lock()
	proxyCfg = ProxyConfig{}
	proxyMu.Unlock()
	if frontEnsure443(addr) {
		t.Error("无需求时补起应返回 false")
	}
	if on, _ := front443Status(); on {
		t.Error("无需求时 443 应停掉")
	}
	closeFront443Test(t)
}

func TestPanelInHTTPFallback(t *testing.T) {
	panelSrvMu.Lock()
	oldMode, oldSrv := panelSrvMode, panelSrv
	panelSrvMu.Unlock()
	t.Cleanup(func() {
		panelSrvMu.Lock()
		panelSrvMode, panelSrv = oldMode, oldSrv
		panelSrvMu.Unlock()
	})
	set := func(mode string, srv *http.Server) {
		panelSrvMu.Lock()
		panelSrvMode, panelSrv = mode, srv
		panelSrvMu.Unlock()
	}
	set("domain", &http.Server{})
	if !panelInHTTPFallback() {
		t.Error("域名模式 + 有 HTTP 监听 = 回落态")
	}
	set("domain", nil)
	if panelInHTTPFallback() {
		t.Error("域名模式 + 443 前置在跑(panelSrv nil)不是回落态")
	}
	set("port", &http.Server{})
	if panelInHTTPFallback() {
		t.Error("端口模式不是回落态")
	}
	set("off", nil)
	if panelInHTTPFallback() {
		t.Error("off 模式不是回落态")
	}
}

// TestFrontRetryLoopAddrs: 循环本身端到端——占位时失败、释放后自动接管, 无需重启。
func TestFrontRetryLoopAddrs(t *testing.T) {
	oldEvery := frontRetryEvery
	frontRetryEvery = 50 * time.Millisecond
	t.Cleanup(func() { frontRetryEvery = oldEvery })
	frontTestCfg(t, []*ProxyRule{
		{ID: "r1", Domain: "example.com", Listens: []ProxyListen{{Port: 443, Protocol: "https"}}, Cert: "auto", Backend: "127.0.0.1:8080", Enabled: true},
	})
	p80 := freePort(t)
	p443 := freePort(t)
	addr80 := fmt.Sprintf("127.0.0.1:%d", p80)
	addr443 := fmt.Sprintf("127.0.0.1:%d", p443)
	occ80, err := net.Listen("tcp", addr80)
	if err != nil {
		t.Fatal(err)
	}
	occ443, err := net.Listen("tcp", addr443)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go frontRetryLoopAddrs(done, addr80, addr443)
	t.Cleanup(func() {
		close(done)
		closeFront80Test(t)
		closeFront443Test(t)
	})
	// 先等两轮重试跑过, 确认被占时确实没起来。
	time.Sleep(150 * time.Millisecond)
	if frontPort80OK() {
		t.Error("80 被占时循环不应把它标成已起")
	}
	if on, _ := front443Status(); on {
		t.Error("443 被占时循环不应把它标成已起")
	}
	occ80.Close()
	occ443.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if frontPort80OK() {
			if on, _ := front443Status(); on {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("占用释放后循环应在 3 秒内把 80 与 443 都接管回来")
}
