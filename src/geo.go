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
	"sort"
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
		geoCountriesInvalidate()
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
	geoCountriesInvalidate()
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
	geoCountriesInvalidate()
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

// ---------- 国家枚举(防火墙自定义位置的国家多选数据源) ----------

var (
	geoCountriesCache []string
	geoCountriesMu    sync.Mutex
)

func geoCountriesInvalidate() {
	geoCountriesMu.Lock()
	geoCountriesCache = nil
	geoCountriesMu.Unlock()
	geoCitiesInvalidate()
}

// geoCountries: 库里全部国家字符串(去重排序, 排除 "0"、空与 Reserved)。
// v4 内嵌库必有; v6 库已下载时一并枚举。结果缓存, 换库时失效。
// 港澳台在库里是省份不是国家, 不在此列, 前端另加三个国家级选项。
func geoCountries() []string {
	geoMu.RLock()
	r4, r6 := geoV4, geoV6
	geoMu.RUnlock()
	if r4 == nil {
		geoLoadV4Embedded()
		geoMu.RLock()
		r4, r6 = geoV4, geoV6
		geoMu.RUnlock()
	}
	geoCountriesMu.Lock()
	defer geoCountriesMu.Unlock()
	if geoCountriesCache != nil {
		return geoCountriesCache
	}
	set := map[string]bool{}
	geoWalkCountries(r4, set)
	geoWalkCountries(r6, set)
	list := []string{}
	for c := range set {
		list = append(list, c)
	}
	sort.Strings(list)
	geoCountriesCache = list
	return list
}

func geoWalkCountries(r *xdbReader, set map[string]bool) {
	if r == nil {
		return
	}
	for idx := 0; idx < 65536; idx++ {
		vo := r.headerLen + idx*8
		if vo+8 > len(r.data) {
			continue
		}
		sPtr := binary.LittleEndian.Uint32(r.data[vo:])
		ePtr := binary.LittleEndian.Uint32(r.data[vo+4:])
		if sPtr >= ePtr {
			continue
		}
		for off := int(sPtr); off+r.segLen <= int(ePtr); off += r.segLen {
			seg := r.data[off : off+r.segLen]
			dlen := int(binary.LittleEndian.Uint16(seg[r.ipLen*2:]))
			dptr := int(binary.LittleEndian.Uint32(seg[r.ipLen*2+2:]))
			if dptr+dlen > len(r.data) {
				continue
			}
			raw := string(r.data[dptr : dptr+dlen])
			if i := strings.IndexByte(raw, '|'); i >= 0 {
				c := raw[:i]
				if c != "" && c != "0" && c != "Reserved" {
					set[c] = true
				}
			}
		}
	}
}

// ---------- 中国省市枚举(自定义位置(中国)的数据源) ----------
// 直接走库段索引枚举, 与归属地判定同源: 只取国家=中国、省份不在港澳台的
// 行, 省市一律归一化, display 用库原字段机械拼接, 不编造。港澳台不进
// 中国选择器(走海外地区级选项)。结果缓存, 换库时随 geoCountries 一并失效。

type geoCitiesData struct {
	Provinces []Region `json:"provinces"`
	Cities    []Region `json:"cities"`
}

var (
	geoCitiesCache *geoCitiesData
	geoCitiesMu    sync.Mutex
)

func geoCitiesInvalidate() {
	geoCitiesMu.Lock()
	geoCitiesCache = nil
	geoCitiesMu.Unlock()
}

func geoCities() *geoCitiesData {
	geoMu.RLock()
	r4, r6 := geoV4, geoV6
	geoMu.RUnlock()
	if r4 == nil {
		geoLoadV4Embedded()
		geoMu.RLock()
		r4, r6 = geoV4, geoV6
		geoMu.RUnlock()
	}
	geoCitiesMu.Lock()
	defer geoCitiesMu.Unlock()
	if geoCitiesCache != nil {
		return geoCitiesCache
	}
	provRaw := map[string]string{}
	citySet := map[string]Region{}
	// 两遍走库: 第一遍只收省份原字段(供城市 display 拼接), 第二遍收城市,
	// 避免先见到的怪省行(如广州市)导致城市 display 缺省份后缀。
	walk := func(r *xdbReader, cities bool) {
		if r == nil {
			return
		}
		for idx := 0; idx < 65536; idx++ {
			vo := r.headerLen + idx*8
			if vo+8 > len(r.data) {
				continue
			}
			sPtr := binary.LittleEndian.Uint32(r.data[vo:])
			ePtr := binary.LittleEndian.Uint32(r.data[vo+4:])
			if sPtr >= ePtr {
				continue
			}
			for off := int(sPtr); off+r.segLen <= int(ePtr); off += r.segLen {
				seg := r.data[off : off+r.segLen]
				dlen := int(binary.LittleEndian.Uint16(seg[r.ipLen*2:]))
				dptr := int(binary.LittleEndian.Uint32(seg[r.ipLen*2+2:]))
				if dptr+dlen > len(r.data) {
					continue
				}
				parts := strings.Split(string(r.data[dptr:dptr+dlen]), "|")
				if len(parts) < 3 || parts[0] != "中国" {
					continue
				}
				normProv := normRegionName(parts[1])
				if normProv == "" {
					continue
				}
				quirk := false
				if q, ok := quirkProvMap[normProv]; ok {
					normProv = q
					quirk = true
				}
				if normProv == "香港" || normProv == "澳门" || normProv == "台湾" {
					continue
				}
				if !cities {
					if !quirk {
						if _, ok := provRaw[normProv]; !ok && parts[1] != "" && parts[1] != "0" {
							provRaw[normProv] = parts[1]
						}
					}
					continue
				}
				normCity := normRegionName(parts[2])
				if normCity == "" {
					continue
				}
				key := normProv + "|" + normCity
				if _, ok := citySet[key]; !ok {
					disp := parts[2]
					if disp == "" || disp == "0" {
						disp = normCity
					}
					if pr, ok := provRaw[normProv]; ok && pr != "" {
						disp = disp + "（" + pr + "）"
					}
					citySet[key] = Region{Kind: "city", Name: normCity, Province: normProv, Display: disp}
				}
			}
		}
	}
	walk(r4, false)
	walk(r6, false)
	walk(r4, true)
	walk(r6, true)
	// 省份顺序沿用 chinaRegions 的标准顺序, 其余按名排序。
	provOrder := map[string]int{}
	for i, r := range chinaRegions {
		if r.Kind == "province" {
			provOrder[r.Name] = i
		}
	}
	provs := []Region{}
	for name, raw := range provRaw {
		provs = append(provs, Region{Kind: "province", Name: name, Display: raw})
	}
	sort.Slice(provs, func(i, j int) bool {
		oi, oki := provOrder[provs[i].Name]
		oj, okj := provOrder[provs[j].Name]
		if oki && okj {
			return oi < oj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return provs[i].Name < provs[j].Name
	})
	cities := []Region{}
	for _, c := range citySet {
		cities = append(cities, c)
	}
	sort.Slice(cities, func(i, j int) bool {
		oi, oki := provOrder[cities[i].Province]
		oj, okj := provOrder[cities[j].Province]
		if oki && okj && oi != oj {
			return oi < oj
		}
		if cities[i].Province != cities[j].Province {
			return cities[i].Province < cities[j].Province
		}
		return cities[i].Name < cities[j].Name
	})
	geoCitiesCache = &geoCitiesData{Provinces: provs, Cities: cities}
	return geoCitiesCache
}
