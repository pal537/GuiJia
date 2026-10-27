package main

// 端口防护(第 9 项): 按省/市限制指定端口的访问。
// 一条规则 = 多个端口 + 多个白名单省市(省和市可混选, 任一命中即放行)。
// 封禁走黑名单记录(作用域 = 规则的端口列表), 因此 TG 解封、应用解封、
// 记录永不删、数据清理单独问黑名单等硬规矩全部自动适用。

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// GuardLocation 白名单里的一个省或市。Name/Province 一律存归一化形式
// (去省/市/自治区等后缀, 如 江苏、南京、内蒙古), 匹配时与归一化后的
// 归属地字段直接比对, 数据库里是"南京"还是"南京市"都能对上。
type GuardLocation struct {
	Kind     string `json:"kind"` // province | city
	Name     string `json:"name"`
	Province string `json:"province,omitempty"` // 市所属的省(归一化); 省条目为空
}

type PortGuardRule struct {
	ID        string          `json:"id"`
	Ports     []int           `json:"ports"`
	Locations []GuardLocation `json:"locations"`
	BanHours  int             `json:"banHours"` // 封禁时长(小时); 0=永久
	Enabled   bool            `json:"enabled"`
}

var (
	pgMu    sync.Mutex
	pgRules []*PortGuardRule
)

func portGuardFile() string { return dataDir + "/portguard.json" }

func loadPortGuard() {
	pgMu.Lock()
	defer pgMu.Unlock()
	pgRules = nil
	if b, err := os.ReadFile(portGuardFile()); err == nil {
		json.Unmarshal(b, &pgRules)
	}
	if pgRules == nil {
		pgRules = []*PortGuardRule{}
	}
}

func savePortGuardLocked() { saveJSON(portGuardFile(), pgRules) }

// normRegionName 归一化省/市名: 去空格, 去省/市/自治区类后缀(长后缀优先)。
// "0"/空 = 未知, 归一为空, 永不命中白名单(默认拦)。
func normRegionName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return ""
	}
	for _, suf := range []string{"特别行政区", "维吾尔自治区", "壮族自治区", "回族自治区", "自治区", "省", "市"} {
		if strings.HasSuffix(s, suf) {
			s = strings.TrimSuffix(s, suf)
			break
		}
	}
	return strings.TrimSpace(s)
}

// parsePortList 解析端口列表: 分隔符支持英文逗号、中文逗号、正反斜杠、顿号,
// 空格只做修剪不做分隔。重复自动去重并升序。出错时返回带问题片段的报错,
// 其中含非法符号的按 PAPA 原话提示"符号不对, 不可以"。
func parsePortList(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("请填写端口")
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == '/' || r == '\\' || r == '、'
	})
	seen := map[int]bool{}
	out := []int{}
	for _, f := range fields {
		t := strings.TrimSpace(f)
		if t == "" {
			continue
		}
		for _, r := range t {
			if !unicode.IsDigit(r) {
				return nil, fmt.Errorf("符号 '%c' 不对，不可以", r)
			}
		}
		n := 0
		for _, r := range t {
			n = n*10 + int(r-'0')
			if n > 65535 {
				break
			}
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("端口 %s 超出范围(1-65535)", t)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("请填写端口")
	}
	sort.Ints(out)
	return out, nil
}

// quirkProvMap: 库里个别 Cloudflare 中国 IP 把市写进了省份字段(省=广州/武汉),
// 匹配前先归属到真实省份, 否则广东/武汉规则匹配不上这些 IP。
var quirkProvMap = map[string]string{"广州": "广东", "武汉": "湖北"}

// guardLocationAllowed 白名单判定: 任一位置命中即放行。省条目比省份字段,
// 市条目比城市字段 + 所属省(防同名市)。空 allowlist 默认拦( fail closed )。
func guardLocationAllowed(locs []GuardLocation, geo GeoInfo) bool {
	prov := normRegionName(geo.Province)
	if q, ok := quirkProvMap[prov]; ok {
		prov = q
	}
	city := normRegionName(geo.City)
	if prov == "" && city == "" {
		return false
	}
	for _, l := range locs {
		switch l.Kind {
		case "province":
			if l.Name != "" && prov == l.Name {
				return true
			}
		case "city":
			if l.Name != "" && city == l.Name && (l.Province == "" || prov == l.Province) {
				return true
			}
		}
	}
	return false
}

// guardRuleForPort 返回覆盖该端口的启用规则(一条端口只归属一条规则, 后建的优先)。
func guardRuleForPort(port int) *PortGuardRule {
	pgMu.Lock()
	defer pgMu.Unlock()
	for i := len(pgRules) - 1; i >= 0; i-- {
		r := pgRules[i]
		if !r.Enabled {
			continue
		}
		for _, p := range r.Ports {
			if p == port {
				return r
			}
		}
	}
	return nil
}

// guardPorts 返回全部启用规则覆盖的端口(供采集循环纳入 eff, 不受 ignoredPorts 影响)。
func guardPorts() map[int]bool {
	pgMu.Lock()
	defer pgMu.Unlock()
	out := map[int]bool{}
	for _, r := range pgRules {
		if !r.Enabled {
			continue
		}
		for _, p := range r.Ports {
			out[p] = true
		}
	}
	return out
}

// ---------- 省市清单校验与展示 ----------

var regionProvSet, regionCitySet map[string]bool

func init() {
	regionProvSet = map[string]bool{}
	regionCitySet = map[string]bool{}
	for _, r := range chinaRegions {
		if r.Kind == "province" {
			regionProvSet[r.Name] = true
		} else if r.Kind == "city" {
			regionCitySet[r.Name+"|"+r.Province] = true
		}
	}
}

func validGuardLocation(l GuardLocation) bool {
	if l.Kind == "province" {
		return regionProvSet[l.Name]
	}
	if l.Kind == "city" {
		return regionCitySet[l.Name+"|"+l.Province]
	}
	return false
}

// guardDisplay 白名单展示名(用清单里的 Display, 如 江苏省、南京市（江苏省）)。
func guardDisplay(locs []GuardLocation) string {
	parts := []string{}
	for _, l := range locs {
		d := ""
		for _, r := range chinaRegions {
			if r.Kind == l.Kind && r.Name == l.Name && (l.Kind != "city" || r.Province == l.Province) {
				d = r.Display
				break
			}
		}
		if d == "" {
			d = l.Name
		}
		parts = append(parts, d)
	}
	return strings.Join(parts, "、")
}

// ---------- 按端口 nft 集合 ----------

var pgLinkOK bool

func pgSetName(port int, v6 bool) string {
	if v6 {
		return "pg6_" + itoa(port)
	}
	return "pg4_" + itoa(port)
}

func pgSetNameFor(ip string, port int) string {
	if pip := net.ParseIP(ip); pip != nil && pip.To4() == nil {
		return pgSetName(port, true)
	}
	return pgSetName(port, false)
}

// ensurePortGuardSet 为某端口建集合 + TCP/UDP 两条 drop 规则(幂等)。
// 规则只丢"来源在集合里 且 目标端口是本端口"的包, 不影响该 IP 的其他端口。
func ensurePortGuardSet(port int) bool {
	if dryBan {
		pgLinkOK = true
		return true
	}
	ok := true
	for _, s := range []struct{ name, typ string }{{pgSetName(port, false), "ipv4_addr"}, {pgSetName(port, true), "ipv6_addr"}} {
		if _, err := nft("add", "set", "inet", nftTable, s.name, "{", "type", s.typ, ";", "flags", "timeout", ";", "}"); err != nil {
			if _, lerr := nft("list", "set", "inet", nftTable, s.name); lerr != nil {
				ok = false
			}
		}
	}
	out, err := nft("list", "chain", "inet", nftTable, "input")
	if err != nil {
		return false
	}
	for _, rl := range []struct{ fam, proto, set string }{
		{"ip", "tcp", pgSetName(port, false)}, {"ip", "udp", pgSetName(port, false)},
		{"ip6", "tcp", pgSetName(port, true)}, {"ip6", "udp", pgSetName(port, true)},
	} {
		needle := "@" + rl.set + " " + rl.proto + " dport " + itoa(port) + " drop"
		if strings.Contains(out, needle) {
			continue
		}
		if _, err := nft("add", "rule", "inet", nftTable, "input", rl.fam, "saddr", "@"+rl.set, rl.proto, "dport", itoa(port), "drop"); err != nil {
			ok = false
		}
	}
	return ok
}

// ensurePortGuardSets 为全部规则端口 + 全部按端口封禁记录的端口建集合与规则。
func ensurePortGuardSets() {
	if dryBan {
		pgLinkOK = true
		return
	}
	ports := map[int]bool{}
	pgMu.Lock()
	for _, r := range pgRules {
		for _, p := range r.Ports {
			ports[p] = true
		}
	}
	pgMu.Unlock()
	banMu.Lock()
	for _, b := range bans {
		for _, p := range b.Ports {
			ports[p] = true
		}
	}
	banMu.Unlock()
	ok := true
	for p := range ports {
		if !ensurePortGuardSet(p) {
			ok = false
		}
	}
	pgLinkOK = ok
}

func pgAddElement(ip string, port, timeoutSec int) {
	set := pgSetNameFor(ip, port)
	elem := ip
	if timeoutSec > 0 && setSupportsTimeout(set) {
		elem = ip + " timeout " + itoa(timeoutSec) + "s"
	}
	nft("delete", "element", "inet", nftTable, set, "{", ip, "}")
	nft("add", "element", "inet", nftTable, set, "{", elem, "}")
}

func pgDelElement(ip string, port int) {
	nft("delete", "element", "inet", nftTable, pgSetNameFor(ip, port), "{", ip, "}")
}

// reconcilePortGuard 按端口集合与按端口记录对齐: 生效中必封、非生效中必不在集合。
func reconcilePortGuard() {
	if dryBan {
		return
	}
	now := time.Now().Unix()
	desired := map[int]map[string]*Ban{}
	for _, b := range activeBans() {
		if len(b.Ports) == 0 {
			continue
		}
		for _, p := range b.Ports {
			if desired[p] == nil {
				desired[p] = map[string]*Ban{}
			}
			desired[p][b.IP] = b
		}
	}
	ports := map[int]bool{}
	for p := range desired {
		ports[p] = true
	}
	banMu.Lock()
	for _, b := range bans {
		for _, p := range b.Ports {
			ports[p] = true
		}
	}
	banMu.Unlock()
	for port := range ports {
		for _, v6 := range []bool{false, true} {
			set := pgSetName(port, v6)
			actual, err := nftListSet(set)
			if err != nil {
				continue // 集合缺失或读失败时本轮跳过, ensure 会重建
			}
			for ip := range actual {
				if _, want := desired[port][ip]; !want {
					nft("delete", "element", "inet", nftTable, set, "{", ip, "}")
				}
			}
			for ip, b := range desired[port] {
				if pgSetNameFor(ip, port) != set || actual[ip] {
					continue
				}
				pgAddElement(ip, port, banKernelTimeout(b, now))
			}
		}
	}
}

// ----------  enforcement ----------

// portGuardCheck 新连接的端口防护检查(采集循环调用): 命中规则、白名单外、
// 非内网非信任且未全局封禁的, 按规则时长按端口封禁并事件 + TG 报警(带解封按钮)。
func portGuardCheck(srcIP string, dstPort int) {
	rule := guardRuleForPort(dstPort)
	if rule == nil {
		return
	}
	pip := net.ParseIP(srcIP)
	if pip == nil || pip.IsLoopback() || isPrivateIP(pip) {
		return
	}
	if isTrusted(srcIP) || isGloballyBanned(srcIP) {
		return
	}
	if isBannedFor(srcIP, dstPort) {
		return
	}
	geo := geoLookup(srcIP)
	if guardLocationAllowed(rule.Locations, geo) {
		return
	}
	prov := geo.Province + geo.City
	if prov == "" {
		prov = "未知归属地"
	}
	reason := "端口防护：仅允许" + guardDisplay(rule.Locations) + "，来源" + prov
	_, fresh, err := applyScopedBan(srcIP, reason, "portguard", rule.BanHours, rule.Ports)
	if err != nil || !fresh {
		return
	}
	emit(Event{Type: "portguard_ban", IP: srcIP, Port: dstPort, Detail: reason}, settings.AlertPortGuardBan)
}

// ---------- API ----------

func newPortGuardRuleID() string {
	var b [6]byte
	rand.Read(b[:])
	return "g" + hex.EncodeToString(b[:])
}

// parseGuardRuleInput 校验一条端口防护规则的输入(POST 新增与 PUT 编辑共用):
// 端口表解析、省市归一化+合法性、去重、时长钳制。返回可直接落库的端口、省市、时长。
func parseGuardRuleInput(portsText string, locs []GuardLocation, banHours int) (ports []int, out []GuardLocation, hours int, err error) {
	ports, err = parsePortList(portsText)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(locs) == 0 {
		return nil, nil, 0, fmt.Errorf("请至少选择一个省或市")
	}
	for i := range locs {
		locs[i].Name = normRegionName(locs[i].Name)
		locs[i].Province = normRegionName(locs[i].Province)
		if locs[i].Kind == "province" {
			locs[i].Province = ""
		}
		if !validGuardLocation(locs[i]) {
			return nil, nil, 0, fmt.Errorf("白名单中含未知省市: %s", locs[i].Name)
		}
	}
	// 归一化后写回(去重: 同 kind+name+province 只留一条)
	seen := map[string]bool{}
	out = []GuardLocation{}
	for _, l := range locs {
		k := l.Kind + "|" + l.Name + "|" + l.Province
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	hours = banHours
	if hours < 0 {
		return nil, nil, 0, fmt.Errorf("封禁时长不能为负")
	}
	if hours > 8760 {
		hours = 8760
	}
	return ports, out, hours, nil
}

func handlePortGuard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		pgMu.Lock()
		out := append([]*PortGuardRule{}, pgRules...)
		pgMu.Unlock()
		if out == nil {
			out = []*PortGuardRule{}
		}
		writeJSON(w, 200, map[string]any{"rules": out})
	case "POST":
		var in struct {
			PortsText string          `json:"portsText"`
			Locations []GuardLocation `json:"locations"`
			BanHours  int             `json:"banHours"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		ports, locs, hours, err := parseGuardRuleInput(in.PortsText, in.Locations, in.BanHours)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		pgMu.Lock()
		for _, r := range pgRules {
			for _, p := range r.Ports {
				for _, np := range ports {
					if p == np {
						pgMu.Unlock()
						errJSON(w, 400, "端口 "+itoa(np)+" 已在另一条端口防护规则中")
						return
					}
				}
			}
		}
		rule := &PortGuardRule{ID: newPortGuardRuleID(), Ports: ports, Locations: locs, BanHours: hours, Enabled: true}
		pgRules = append(pgRules, rule)
		savePortGuardLocked()
		pgMu.Unlock()
		ensurePortGuardSets()
		writeJSON(w, 200, rule)
	default:
		errJSON(w, 405, "method")
	}
}

func handlePortGuardItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/portguard/")
	switch r.Method {
	case "PUT":
		// 开关切换只传 enabled；整条编辑传 portsText(+locations+banHours)，两者可同传。
		var in struct {
			Enabled   *bool           `json:"enabled"`
			PortsText *string         `json:"portsText"`
			Locations []GuardLocation `json:"locations"`
			BanHours  *int            `json:"banHours"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || (in.Enabled == nil && in.PortsText == nil) {
			errJSON(w, 400, "请求无效")
			return
		}
		pgMu.Lock()
		var rule *PortGuardRule
		for _, x := range pgRules {
			if x.ID == id {
				rule = x
				break
			}
		}
		if rule == nil {
			pgMu.Unlock()
			errJSON(w, 404, "规则不存在")
			return
		}
		if in.Enabled != nil {
			rule.Enabled = *in.Enabled
		}
		if in.PortsText != nil {
			hours := rule.BanHours
			if in.BanHours != nil {
				hours = *in.BanHours
			}
			ports, locs, hours2, err := parseGuardRuleInput(*in.PortsText, in.Locations, hours)
			if err != nil {
				pgMu.Unlock()
				errJSON(w, 400, err.Error())
				return
			}
			for _, r := range pgRules {
				if r.ID == id {
					continue
				}
				for _, p := range r.Ports {
					for _, np := range ports {
						if p == np {
							pgMu.Unlock()
							errJSON(w, 400, "端口 "+itoa(np)+" 已在另一条端口防护规则中")
							return
						}
					}
				}
			}
			rule.Ports = ports
			rule.Locations = locs
			rule.BanHours = hours2
		}
		savePortGuardLocked()
		pgMu.Unlock()
		if rule.Enabled {
			ensurePortGuardSets()
		}
		writeJSON(w, 200, rule)
	case "DELETE":
		pgMu.Lock()
		found := false
		kept := []*PortGuardRule{}
		for _, x := range pgRules {
			if x.ID == id {
				found = true
				continue
			}
			kept = append(kept, x)
		}
		if !found {
			pgMu.Unlock()
			errJSON(w, 404, "规则不存在")
			return
		}
		pgRules = kept
		savePortGuardLocked()
		pgMu.Unlock()
		// 注意: 删除规则不自动解封其已封禁(封禁记录独立管理, 到期或 TG/应用解封)。
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		errJSON(w, 405, "method")
	}
}

func handleGeoRegions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	writeJSON(w, 200, map[string]any{"regions": chinaRegions})
}
