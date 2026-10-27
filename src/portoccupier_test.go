package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// TestPortOccupier: 自绑一个临时端口，查询必须返回非空进程名；
// 关闭监听后该端口不再有 LISTEN 项，查询返回空。
func TestPortOccupier(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if name := portOccupier(port); name == "" {
		t.Errorf("占用中的端口 %d 应查到进程名", port)
	}
	ln.Close()
	if name := portOccupier(port); name != "" {
		t.Errorf("空闲端口 %d 应查不到进程，得到 %q", port, name)
	}
}

// TestBindErrText: 非绑定错误原样回落；空闲端口的绑定错误也原样回落
// （查不到占用进程时绝不编造进程名）。
func TestBindErrText(t *testing.T) {
	other := errors.New("some other error")
	if got := bindErrText(18080, other); got != other.Error() {
		t.Errorf("非绑定错误应原样，得到 %q", got)
	}
	// 找一个空闲端口：先绑再关，关后无 LISTEN 项。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	bindErr := errors.New("listen tcp 127.0.0.1:" + itoa(port) + ": bind: address already in use")
	if got := bindErrText(port, bindErr); got != bindErr.Error() {
		t.Errorf("查不到占用进程时应回落原始错误，得到 %q", got)
	}
	if !strings.Contains(bindErrText(443, errors.New("listen tcp :443: bind: address already in use")), "address already in use") {
		t.Error("回落文案应保留原始错误")
	}
}
