package main

// 第 7 项回归测试: 节点 IP 以 hub 观测为准(拨入优先于自报, 按地址族分别决策),
// 公网判断排除私网段, hubServerPublic 输出 ip6 与 uptime。

import (
	"net"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"10.20.30.40", false},
		{"172.16.0.5", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"fd00::1", false},
		{"2001:4860:4860::8888", true},
		{"2606:4700:4700::1111", true},
		{"", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := isPublicIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isPublicIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestResolveNodeIP(t *testing.T) {
	cases := []struct {
		remote, self, self6, pub, want4, want6 string
	}{
		// 甲骨文场景: 拨入公网 v4 纠正自报私网
		{"203.0.113.10:54321", "10.20.30.40", "", "", "203.0.113.10", ""},
		// 拨入优先于自报公网
		{"203.0.113.10:54321", "198.51.100.20", "", "", "203.0.113.10", ""},
		// 拨入私网(局域网节点)时自报公网可用
		{"10.0.0.1:1234", "198.51.100.20", "", "", "198.51.100.20", ""},
		// 都拿不到公网: 返回空, 调用方保留公网旧值、清掉私网旧值
		{"", "10.20.30.40", "", "", "", ""},
		{"", "", "fc00::1", "", "", ""},
		// 自报公网可用
		{"", "198.51.100.20", "", "", "198.51.100.20", ""},
		// 按族独立: 拨入 v6 + 自报 v4 公网, 两族各取其一
		{"[2606:4700:4700::1111]:1234", "198.51.100.20", "2001:4860:4860::8888", "", "198.51.100.20", "2606:4700:4700::1111"},
		// 拨入 v4 + 自报 v6 公网
		{"203.0.113.10:54321", "", "2606:4700:4700::1111", "", "203.0.113.10", "2606:4700:4700::1111"},
		// RemoteAddr 不带端口也能解析
		{"203.0.113.10", "10.0.0.1", "", "", "203.0.113.10", ""},
		// 自报 ULA 不采纳
		{"", "", "fd00::5", "", "", ""},
		// 甲骨文新场景: IPv6 拨入 + 自报私网 v4 + 探测公网 v4, 探测补上 v4
		{"[2606:4700:4700::1111]:1234", "10.20.30.40", "2001:4860:4860::8888", "203.0.113.10", "203.0.113.10", "2606:4700:4700::1111"},
		// 探测优先于自报公网
		{"", "198.51.100.20", "", "203.0.113.10", "203.0.113.10", ""},
		// 拨入优先于探测
		{"203.0.113.10:54321", "", "", "198.51.100.20", "203.0.113.10", ""},
		// 探测私网不采纳
		{"", "", "", "10.20.30.40", "", ""},
		// 探测 v6 可用
		{"", "", "", "2606:4700:4700::1111", "", "2606:4700:4700::1111"},
	}
	for _, c := range cases {
		got4, got6 := resolveNodeIP(c.remote, c.self, c.self6, c.pub)
		if got4 != c.want4 || got6 != c.want6 {
			t.Errorf("resolveNodeIP(%q, %q, %q, %q) = (%q, %q), want (%q, %q)",
				c.remote, c.self, c.self6, c.pub, got4, got6, c.want4, c.want6)
		}
	}
}

// applyNodeIP: 有新公网就覆盖; 某族拿不到新公网时公网旧值保留、私网旧值清掉。
func TestApplyNodeIP(t *testing.T) {
	// 私网旧值: 私网 v4 + 公网 v6, 拿不到新值时 v4 清掉、v6 保留
	s := &hubServer{IP: "10.20.30.40", IPv6: "2606:4700:4700::1111"}
	applyNodeIP(s, "", "")
	if s.IP != "" {
		t.Errorf("私网旧 v4 应清掉, 实际 %q", s.IP)
	}
	if s.IPv6 != "2606:4700:4700::1111" {
		t.Errorf("公网旧 v6 应保留, 实际 %q", s.IPv6)
	}
	// 公网旧 v4 保留(防拨入地址族抖动)
	s = &hubServer{IP: "203.0.113.10"}
	applyNodeIP(s, "", "")
	if s.IP != "203.0.113.10" {
		t.Errorf("公网旧 v4 应保留, 实际 %q", s.IP)
	}
	// 有新值就覆盖
	s = &hubServer{IP: "10.20.30.40"}
	applyNodeIP(s, "203.0.113.10", "")
	if s.IP != "203.0.113.10" {
		t.Errorf("新 v4 应覆盖, 实际 %q", s.IP)
	}
	// 私网 v6 旧值清掉、非法旧值清掉
	s = &hubServer{IPv6: "fd00::5"}
	applyNodeIP(s, "", "")
	if s.IPv6 != "" {
		t.Errorf("私网旧 v6 应清掉, 实际 %q", s.IPv6)
	}
	s = &hubServer{IP: "not-an-ip"}
	applyNodeIP(s, "", "")
	if s.IP != "" {
		t.Errorf("非法旧 IP 应清掉, 实际 %q", s.IP)
	}
}

func TestHubServerPublicIP6Uptime(t *testing.T) {
	s := &hubServer{
		Fingerprint: "testfp", Name: "甲骨文一号", Status: "online",
		LastSeen: time.Now().Unix(), Version: "v1.0.18",
		IP: "203.0.113.10", IPv6: "2606:4700:4700::1111", UptimeSec: 90061,
		Location: "手动测试地",
	}
	m := hubServerPublic(s)
	if m["ip"] != "203.0.113.10" {
		t.Errorf("ip = %v, want 203.0.113.10", m["ip"])
	}
	if m["ip6"] != "2606:4700:4700::1111" {
		t.Errorf("ip6 = %v, want 2606:4700:4700::1111", m["ip6"])
	}
	if m["uptime"] != int64(90061) {
		t.Errorf("uptime = %v, want 90061", m["uptime"])
	}
	// 无 IPv6 时 ip6 为空, 前端不显示第二行
	s2 := &hubServer{
		Fingerprint: "testfp2", Name: "节点乙", Status: "online",
		LastSeen: time.Now().Unix(), Version: "v1.0.18",
		IP: "198.51.100.20", Location: "手动测试地",
	}
	if hubServerPublic(s2)["ip6"] != "" {
		t.Errorf("无 IPv6 时 ip6 应为空, 实际 %v", hubServerPublic(s2)["ip6"])
	}
}
