package main

// 节点上报给主服务器的本机信息: IP、操作系统、架构, 供首页卡片展示。
// 老版本节点不上报这些字段时, 主服务器一律显示“未知”, 不猜不补。

import (
	"bufio"
	"net"
	"os"
	"runtime"
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

// primaryIP 本机主 IP: 取第一个启用、非回环的全局单播 IPv4;
// 没有时返回 ""(调用方显示未知)。
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
			if ip.IsGlobalUnicast() {
				return ip.String()
			}
			if fallback == "" {
				fallback = ip.String()
			}
		}
	}
	return fallback
}

// nodeSysInfo 节点上报三件套: 主 IP、操作系统、架构。
func nodeSysInfo() (ip, osName, arch string) {
	return primaryIP(), osPrettyName(), archDisplay()
}
