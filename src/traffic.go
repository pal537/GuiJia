package main

// 实时流量: 每 2 秒读 /proc/net/dev 计算各物理网卡的收发速率, 供总览页顶部展示。
// 只展示物理网卡: /sys/class/net/<name>/device 存在(PCI/USB 物理设备才有),
// 且状态为 up; 排除 -ovs 镜像口(与物理口是同一块网卡的重复计数)。
// Docker 网桥/veth/lo/雷池虚拟口等都没有 device 链接, 天然被排除。

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var sysNetDir = "/sys/class/net" // 测试可注入
var procNetDev = "/proc/net/dev" // 测试可注入

type IfaceTraffic struct {
	Name  string `json:"name"`
	Addr  string `json:"addr"` // 首个 IPv4 地址, 无则空
	RxBps int64  `json:"rxBps"`
	TxBps int64  `json:"txBps"`
	RxTot uint64 `json:"rxTotal"`
	TxTot uint64 `json:"txTotal"`
}

type devSample struct {
	rx, tx uint64
	at     time.Time
}

var (
	trafMu   sync.Mutex
	trafPrev = map[string]devSample{}
	trafCur  = map[string]IfaceTraffic{}
)

// parseNetDev 解析 /proc/net/dev: 每行 "name: rxBytes rxPkts ... txBytes ..."
func parseNetDev(content string) map[string][2]uint64 {
	out := map[string][2]uint64{}
	for _, line := range strings.Split(content, "\n") {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		f := strings.Fields(line[i+1:])
		if name == "" || len(f) < 16 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[name] = [2]uint64{rx, tx}
	}
	return out
}

func isPhysicalNIC(name string) bool {
	if name == "lo" || strings.HasSuffix(name, "-ovs") {
		return false
	}
	if _, err := os.Stat(filepath.Join(sysNetDir, name, "device")); err != nil {
		return false
	}
	st, err := os.ReadFile(filepath.Join(sysNetDir, name, "operstate"))
	if err != nil || strings.TrimSpace(string(st)) != "up" {
		return false
	}
	return true
}

func ifaceAddrs() map[string]string {
	out := map[string]string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil {
					out[ifc.Name] = ip4.String()
					break
				}
			}
		}
	}
	// OVS 场景下, 物理口的 IP 挂在同名 -ovs 内部口上:
	// 物理口自身没地址时借 -ovs 口的地址展示(就是这条线路的地址)
	for _, ifc := range ifs {
		if out[ifc.Name] == "" {
			if a := out[ifc.Name+"-ovs"]; a != "" {
				out[ifc.Name] = a
			}
		}
	}
	return out
}

func trafficTick() {
	b, err := os.ReadFile(procNetDev)
	if err != nil {
		return
	}
	now := time.Now()
	addrs := ifaceAddrs()
	trafMu.Lock()
	defer trafMu.Unlock()
	seen := map[string]bool{}
	for name, c := range parseNetDev(string(b)) {
		if !isPhysicalNIC(name) {
			continue
		}
		seen[name] = true
		cur := IfaceTraffic{Name: name, Addr: addrs[name], RxTot: c[0], TxTot: c[1]}
		if prev, ok := trafPrev[name]; ok {
			dt := now.Sub(prev.at).Seconds()
			if dt > 0 {
				if c[0] >= prev.rx {
					cur.RxBps = int64(float64(c[0]-prev.rx) / dt)
				}
				if c[1] >= prev.tx {
					cur.TxBps = int64(float64(c[1]-prev.tx) / dt)
				}
			}
		}
		trafCur[name] = cur
		trafPrev[name] = devSample{rx: c[0], tx: c[1], at: now}
	}
	// 网卡消失(拔线/改名)时清掉陈旧条目
	for name := range trafCur {
		if !seen[name] {
			delete(trafCur, name)
			delete(trafPrev, name)
		}
	}
}

func trafficLoop() {
	trafficTick() // 先建基线, 第二拍起才有速率
	t := time.NewTicker(2 * time.Second)
	for range t.C {
		trafficTick()
	}
}

func trafficSnapshot() []IfaceTraffic {
	trafMu.Lock()
	defer trafMu.Unlock()
	out := []IfaceTraffic{}
	for _, v := range trafCur {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
