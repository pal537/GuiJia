package main

// 节点上报给主服务器的本机信息: IP、操作系统、架构, 供首页卡片展示。
// 老版本节点不上报这些字段时, 主服务器一律显示“未知”, 不猜不补。

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// osPrettyName 从 /etc/os-release 取 NAME + VERSION_ID, 如 Debian 13;
// 读不到时回落 runtime.GOOS。
func osPrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	defer f.Close()
	var name, ver string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			ver = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	if name == "" {
		return runtime.GOOS
	}
	if ver != "" {
		return name + " " + ver
	}
	return name
}

// archDisplay 架构展示名: amd64 -> x86_64, arm64 保持, 其余原样。
func archDisplay() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	default:
		return runtime.GOARCH
	}
}

// isPublicIP 真公网地址: 全局单播且不在私网段。
// 注意 IsGlobalUnicast 包含私网段(10/8、172.16/12、192.168/16、ULA),
// 故必须再排除 IsPrivate; 回环/链路本地/组播已由 IsGlobalUnicast 排除。
func isPublicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// primaryIP 本机主 IP: 优先第一个真正公网 IPv4;
// 无公网时回落第一个非回环 IPv4(私网, 如 NAT 机), 都没有返回 ""。
func primaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	fallback := ""
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			if isPublicIP(ip) {
				return ip.String()
			}
			if fallback == "" {
				fallback = ip.String()
			}
		}
	}
	return fallback
}

// primaryIPv6 本机主公网 IPv6: 第一个公网 GUA 地址(排除 ULA、链路本地、回环);
// 没有时返回 ""(调用方不显示 IPv6 行)。
func primaryIPv6() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() != nil {
				continue
			}
			if isPublicIP(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

// parseUptimeSeconds 解析 /proc/uptime 内容: 首字段为开机秒数(可带小数)。
func parseUptimeSeconds(content string) int64 {
	f := strings.Fields(content)
	if len(f) == 0 {
		return 0
	}
	sec, err := strconv.ParseFloat(f[0], 64)
	if err != nil || sec < 0 {
		return 0
	}
	return int64(sec)
}

// sysUptimeSec 系统开机时长(秒): 读 /proc/uptime; 非 Linux 或读不到返回 0,
// 调用方不拿进程运行时长冒充(见 api overview 的 uptimeSec, 那是面板进程时长)。
func sysUptimeSec() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	return parseUptimeSeconds(string(b))
}

// nodeSysInfo 节点上报三件套: 主 IP、操作系统、架构。
func nodeSysInfo() (ip, osName, arch string) {
	return primaryIP(), osPrettyName(), archDisplay()
}
