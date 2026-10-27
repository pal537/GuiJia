package main

// ip2region xdb 离线归属地查询 (v2 格式, 自实现读取器, 无第三方依赖)
// 数据文件: ip2region.xdb (IPv4, 内嵌) / ip2region_v6.xdb (IPv6, 首次运行下载到数据目录)
// 地区字符串格式(现行数据): 国家|省份|城市|ISP|国家代码, "0" 表示未知

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type xdbReader struct {
	data      []byte
	ipLen     int // 4 或 16
	segLen    int // 段索引条目长度: v4=14, v6=38
	headerLen int // 256
}

func openXDB(path string, ipLen int) (*xdbReader, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return openXDBBytes(b, ipLen)
}

func openXDBBytes(b []byte, ipLen int) (*xdbReader, error) {
	if len(b) < 256 {
		return nil, fmt.Errorf("xdb 文件过小")
	}
	segLen := 14
	if ipLen == 16 {
		segLen = 38
	}
	return &xdbReader{data: b, ipLen: ipLen, segLen: segLen, headerLen: 256}, nil
}

func (r *xdbReader) search(ipBytes []byte) (string, error) {
	if len(ipBytes) != r.ipLen {
		return "", fmt.Errorf("ip 长度不符")
	}
	vecIdx := (int(ipBytes[0]) << 8) | int(ipBytes[1])
	vecOff := r.headerLen + vecIdx*8
	if vecOff+8 > len(r.data) {
		return "", fmt.Errorf("向量索引越界")
	}
	sPtr := binary.LittleEndian.Uint32(r.data[vecOff:])
	ePtr := binary.LittleEndian.Uint32(r.data[vecOff+4:])
	if sPtr >= ePtr {
		return "", nil
	}
	count := int(ePtr-sPtr) / r.segLen
	lo, hi := 0, count-1
	for lo <= hi {
		mid := (lo + hi) / 2
		off := int(sPtr) + mid*r.segLen
		if off+r.segLen > len(r.data) {
			return "", fmt.Errorf("段索引越界")
		}
		seg := r.data[off : off+r.segLen]
		sip := seg[:r.ipLen]
		eip := seg[r.ipLen : r.ipLen*2]
		if bytes.Compare(ipBytes, sip) < 0 {
			hi = mid - 1
			continue
		}
		if bytes.Compare(ipBytes, eip) > 0 {
			lo = mid + 1
			continue
		}
		dataLen := int(binary.LittleEndian.Uint16(seg[r.ipLen*2:]))
		dataPtr := int(binary.LittleEndian.Uint32(seg[r.ipLen*2+2:]))
		if dataPtr+dataLen > len(r.data) {
			return "", fmt.Errorf("数据越界")
		}
		return string(r.data[dataPtr : dataPtr+dataLen]), nil
	}
	return "", nil
}

// ---------- 归属地服务 ----------

type GeoInfo struct {
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
	ISP      string `json:"isp"`
	Code     string `json:"code"` // 国家代码(数据第 5 段, 如 US), 供卡片国旗图用
	Text     string `json:"text"` // 展示用: 中国 江苏省 南京市 · 联通 / 美国 · xx
	Private  bool   `json:"private"`
}

var (
	geoMu      sync.RWMutex
	geoV4      *xdbReader
	geoV6      *xdbReader
	geoCache   = map[string]GeoInfo{}
	geoCacheMu sync.Mutex
)

func geoLoadV4Embedded() {
	r, err := openXDBBytes(embeddedXDBv4, 4)
	if err == nil {
		geoMu.Lock()
		geoV4 = r
		geoMu.Unlock()
	}
}

// geoLoadV4File 从数据目录文件加载 IPv4 库(探针校验通过才换掉当前库)。
func geoLoadV4File(path string) bool {
	r, err := openXDB(path, 4)
	if err != nil {
		return false
	}
	probe := net.ParseIP("114.114.114.114")
	if probe == nil {
		return false
	}
	raw, err := r.search([]byte(probe.To4()))
	if err != nil || !strings.Contains(raw, "|") {
		return false
	}
	geoMu.Lock()
	geoV4 = r
	geoMu.Unlock()
	return true
}

// geoV4FromFile 当前 IPv4 库是否来自数据目录下载文件(否则为内嵌)。
func geoV4FromFile() bool {
	if _, err := os.Stat(geoV4Path); err == nil {
		return true
	}
	return false
}

func geoLoadV6(path string) bool {
	r, err := openXDB(path, 16)
	if err != nil {
		return false
	}
	// 探针校验: 文件被截断/损坏时查找会失败或为空, 宁可不加载
	probe := net.ParseIP("2001:4860:4860::8888")
	if probe == nil {
		return false
	}
	raw, err := r.search([]byte(probe.To16()))
	if err != nil || !strings.Contains(raw, "|") {
		return false
	}
	geoMu.Lock()
	geoV6 = r
	geoMu.Unlock()
	return true
}

func geoV6Loaded() bool {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return geoV6 != nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	return ip.IsPrivate()
}

func geoLookup(ipStr string) GeoInfo {
	geoCacheMu.Lock()
	if g, ok := geoCache[ipStr]; ok {
		geoCacheMu.Unlock()
		return g
	}
	geoCacheMu.Unlock()

	g := GeoInfo{Text: "未知"}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return g
	}
	if isPrivateIP(ip) {
		g = GeoInfo{Country: "内网", Text: "内网", Private: true}
		geoCacheStore(ipStr, g)
		return g
	}
	var raw string
	geoMu.RLock()
	r4, r6 := geoV4, geoV6
	geoMu.RUnlock()
	if v4 := ip.To4(); v4 != nil {
		if r4 != nil {
			raw, _ = r4.search([]byte(v4))
		}
	} else if r6 != nil {
		b := ip.To16()
		// ::ffff:a.b.c.d 形式先尝试 v4
		if v4 := ip.To4(); v4 != nil && r4 != nil {
			raw, _ = r4.search([]byte(v4))
		} else {
			raw, _ = r6.search([]byte(b))
		}
	}
	if raw != "" {
		parts := strings.Split(raw, "|")
		get := func(i int) string {
			if i < len(parts) && parts[i] != "0" {
				return parts[i]
			}
			return ""
		}
		// 现行 ip2region 数据格式: 国家|省份|城市|ISP|国家代码
		g.Country = get(0)
		g.Province = get(1)
		g.City = get(2)
		g.ISP = get(3)
		g.Code = get(4)
		var loc []string
		if g.Country != "" {
			loc = append(loc, g.Country)
		}
		if g.Province != "" && g.Province != g.Country {
			loc = append(loc, g.Province)
		}
		if g.City != "" && g.City != g.Province {
			loc = append(loc, g.City)
		}
		g.Text = strings.Join(loc, " ")
		if g.ISP != "" {
			if g.Text != "" {
				g.Text += " · " + g.ISP
			} else {
				g.Text = g.ISP
			}
		}
		if g.Text == "" {
			g.Text = "未知"
		}
	}
	geoCacheStore(ipStr, g)
	return g
}

func geoCacheStore(ip string, g GeoInfo) {
	geoCacheMu.Lock()
	if len(geoCache) > 4096 {
		geoCache = map[string]GeoInfo{}
	}
	geoCache[ip] = g
	geoCacheMu.Unlock()
}
