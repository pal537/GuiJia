package main

// 公网 IP 查询(本机卡片用): Oracle 这类 NAT 机的接口 IP 是私网, 本地
// 看不到公网 IP, 必须问外网回显服务。查询绝不阻塞面板: 只读缓存, 缓存
// 过期时后台刷新一次; 查不到时调用方回退到接口 IP。

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	publicIPMu       sync.Mutex
	publicIPCache    string
	publicIPFetched  time.Time
	publicIPFetching bool
)

// publicIPCacheTTL 缓存有效期: 公网 IP 很少变, 1 小时一刷足够。
const publicIPCacheTTL = time.Hour

// publicIPLookupURLs 回显服务(按序尝试, 可注入测试)。
var publicIPLookupURLs = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
}

// publicIPHTTPClient 回显请求客户端(3 秒超时, 可注入测试)。
var publicIPHTTPClient = &http.Client{Timeout: 3 * time.Second}

// fetchPublicIP 同步查一次公网 IP(按序试两个回显源, 返回 "" 表示都失败)。
func fetchPublicIP() string {
	for _, u := range publicIPLookupURLs {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		resp, err := publicIPHTTPClient.Do(req)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// publicIPCached 读缓存的公网 IP: 缓存新鲜直接返回; 过期时后台刷新一次
// (只起一个刷新 goroutine), 本次仍返回旧缓存(可能为空), 绝不阻塞。
func publicIPCached() string {
	publicIPMu.Lock()
	cached, fresh := publicIPCache, time.Since(publicIPFetched) < publicIPCacheTTL
	fetching := publicIPFetching
	if fresh || fetching {
		publicIPMu.Unlock()
		return cached
	}
	publicIPFetching = true
	publicIPMu.Unlock()
	go func() {
		ip := fetchPublicIP()
		publicIPMu.Lock()
		if ip != "" {
			publicIPCache, publicIPFetched = ip, time.Now()
		}
		publicIPFetching = false
		publicIPMu.Unlock()
	}()
	return cached
}

// selectDisplayIP 本机卡片 IP 选择(纯函数, 供测试):
// 公网 IP 优先; 其次首个非私网接口 IPv4; 最后首个接口 IPv4(可能是私网,
// 调用方届时仍打“内网”标签); 都没有返回 ""。
func selectDisplayIP(public string, ips []string) string {
	if public != "" {
		// 仅接受合法 IP(非法值不进卡片, 退到接口 IP)。
		if ip := net.ParseIP(public); ip != nil {
			return public
		}
	}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			return s
		}
	}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return s
		}
	}
	return ""
}

// localInterfaceIPs 本机全部启用、非回环接口的 IPv4(供选择函数用)。
func localInterfaceIPs() []string {
	out := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
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
			if ip == nil || ip.To4() == nil {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// localDisplayIP 本机卡片用 IP: 公网优先, 回退到接口 IP。
// 节点上报仍用 primaryIP()(不动), 节点卡片继续用 hub 观测的 ping 来源。
func localDisplayIP() string {
	return selectDisplayIP(publicIPCached(), localInterfaceIPs())
}
