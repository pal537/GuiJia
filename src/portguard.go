package main

// 防火墙(原端口防护, 2026-10-27 PAPA 拍板改名并重做)。
//
// 一条规则 = 端口(单个/逗号分隔/范围) + 通信协议(全部/TCP/UDP) +
// 来源范围 + 动作(允许/拒绝) + 生效/禁用 + 封禁时长(小时, 0=永久,
// 留空=24 小时)。来源范围单选其一: 自定义 IP / 全部 IPv4 / 全部 IPv6 /
// 中国大陆境内 / 中国大陆境外 / 自定义位置 / 全部 IP。
//
// 执行语义(与 DESIGN.md 一致, 改语义先改文档再改代码):
// 1. 端口被任一生效规则覆盖即受防护; 覆盖看规则的端口范围与协议。
// 2. 新连接命中生效拒绝规则 -> 按规则端口作用域封禁(只封该规则的
//    端口, 绝不扩成全局封禁, 复用 Ban 的 Scopes 作用域)。
// 3. 命中生效允许规则 -> 放行。
// 4. 多条命中时拒绝优先于允许。
// 5. 无任何规则命中 -> 按受防护端口默认处理: 非白名单即封禁,
//    作用域与时长取首个生效覆盖规则(按规则创建顺序)。
// 6. 内网/回环/保留段/信任名单永远豁免(复用 bannable 守门)。
// 7. 归属地库查不到国家的 IP(未知)不命中任何国家/省份类允许规则,
//    走默认封禁, 原因记"归属地未知", 界面展示"未知"。
// 8. 删除规则不自动解封其已封禁(封禁记录独立管理, 到期或解封);
//    编辑规则后该规则下已封禁 IP 的生效端口随新规则走(旧范围的
//    nft 规则会被删掉重建, 集合成员保留)。
// 9. 港澳台判定看库的省份字段(库里港澳台的国家仍是"中国", 省份是
//    香港特别行政区/澳门特别行政区/台湾省, 2026-10-27 实测确认)。
//
// 内核层: 每条规则两个集合 fw4_<规则ID>/fw6_<规则ID> + 按规则端口
// 范围的 drop 规则(TCP/UDP 按协议分建)。1-65535 这类大范围不再展开
// 成单端口列表(旧展开方式会生成 65535 个 PortWatch 条目, 已废弃);
// 采集层用 fwCoversPort() 查范围覆盖, 未监听的防护端口照样可见。
// 规则删除后集合与规则保留(其封禁记录仍要生效, 对齐时按记录里的
// 范围重建, 协议未知时按双协议重建, 只保不丢)。
//
// 旧规则迁移: loadPortGuard 识别旧格式(有 ports+locations、无 source)
// 自动转为新规则(端口不变、协议全部、来源=自定义位置且省份=旧省
// 名单、动作为允许、生效态与时长不变), 转完以新格式回写。旧省白名单
// UI 已下线, 但 guardLocationAllowed 等省市匹配逻辑仍由自定义位置复用。
// 旧 Ports 封禁记录继续走原按端口集合通道, 与新 Scopes 记录并存。

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

// GuardLocation 自定义位置里的一个省或市。Name/Province 一律存归一化形式
// (去省/市/自治区等后缀, 如 江苏、南京、内蒙古), 匹配时与归一化后的
// 归属地字段直接比对, 数据库里是"南京"还是"南京市"都能对上。
type GuardLocation struct {
	Kind     string `json:"kind"` // province | city
	Name     string `json:"name"`
	Province string `json:"province,omitempty"` // 市所属的省(归一化); 省条目为空
}

// FWSource 规则的来源范围, 单选其一(kind 决定语义, 其余字段按 kind 取舍)。
// custom_cn: 自定义位置(中国), 只含大陆省市(Locations); custom_foreign:
// 自定义位置(海外), 只含国家与地区代码(Countries, 含港澳台 HK/MO/TW)。
type FWSource struct {
	Kind      string          `json:"kind"`                // custom_ip | all_v4 | all_v6 | cn_in | cn_out | custom_cn | custom_foreign | all
	CIDR      string          `json:"cidr,omitempty"`      // custom_ip: IP 或 CIDR, 多个逗号分隔(原样存, 匹配用解析后的 cidrNets)
	Countries []string        `json:"countries,omitempty"` // custom_foreign: 国家与地区代码(新); 迁移进来的旧字符串原样保留作回退匹配
	Locations []GuardLocation `json:"locations,omitempty"` // custom_cn: 省市多选(任一命中即命中)

	cidrNets []*net.IPNet // CIDR 解析结果(load 与校验时填充, 不落盘)
}

// PortGuardRule 防火墙规则。ranges 由 PortText 解析而来(不落盘, load 与
// 校验时填充); 展示与封禁作用域一律用 ranges, 不用 PortText 原文。
type PortGuardRule struct {
	ID       string   `json:"id"`
	PortText string   `json:"portText"`
	Proto    string   `json:"proto"` // all | tcp | udp
	Source   FWSource `json:"source"`
	Action   string   `json:"action"`   // allow | deny
	BanHours int      `json:"banHours"` // 封禁时长(小时); 0=永久
	Enabled  bool     `json:"enabled"`

	ranges [][2]int `json:"-"`
}

// legacyPortGuardRule 旧格式(迁移专用, 读完即转新格式, 不再写出)。
type legacyPortGuardRule struct {
	ID        string          `json:"id"`
	Ports     []int           `json:"ports"`
	Locations []GuardLocation `json:"locations"`
	BanHours  int             `json:"banHours"`
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
		var raw []json.RawMessage
		if json.Unmarshal(b, &raw) == nil {
			migrated := false
			for _, item := range raw {
				var probe map[string]json.RawMessage
				if json.Unmarshal(item, &probe) != nil {
					continue
				}
				if _, ok := probe["source"]; ok {
					var r PortGuardRule
					if json.Unmarshal(item, &r) == nil {
						r.ranges, _ = parsePortRanges(r.PortText)
						r.Source.cidrNets, _ = parseCIDRNets(r.Source.CIDR)
						// v1.0.9 的 custom_loc 已拆: 省市分大陆与港澳台两拨,
						// 大陆省市 -> custom_cn, 国家 + 港澳台省市 -> custom_foreign;
						// 两边都有按同端口/协议/动作/时长/生效态拆成两条(新 ID 由
						// 旧 ID 派生, 并集语义不变); 转换后回写新格式。
						if r.Source.Kind == "custom_loc" {
							migrated = true
							mainLocs := []GuardLocation{}
							sarCodes := []string{}
							sarSeen := map[string]bool{}
							for _, l := range r.Source.Locations {
								prov := normRegionName(l.Province)
								name := normRegionName(l.Name)
								sar := ""
								if l.Kind == "province" {
									sar = name
								} else {
									sar = prov
								}
								if sar == "香港" || sar == "澳门" || sar == "台湾" {
									code := "HK"
									if sar == "澳门" {
										code = "MO"
									} else if sar == "台湾" {
										code = "TW"
									}
									if !sarSeen[code] {
										sarSeen[code] = true
										sarCodes = append(sarCodes, code)
									}
									continue
								}
								mainLocs = append(mainLocs, l)
							}
							foreign := normalizeCountrySelections(r.Source.Countries)
							for _, c := range sarCodes {
								found := false
								for _, x := range foreign {
									if x == c {
										found = true
										break
									}
								}
								if !found {
									foreign = append(foreign, c)
								}
							}
							hasC := len(foreign) > 0
							hasL := len(mainLocs) > 0
							if hasL {
								cn := r
								cn.ID = r.ID
								if hasC {
									cn.ID = r.ID + "-cn"
								}
								cn.Source = FWSource{Kind: "custom_cn", Locations: mainLocs}
								pgRules = append(pgRules, &cn)
							}
							if hasC {
								fr := r
								fr.ID = r.ID
								if hasL {
									fr.ID = r.ID + "-foreign"
								}
								fr.Source = FWSource{Kind: "custom_foreign", Countries: foreign}
								pgRules = append(pgRules, &fr)
							}
							if !hasC && !hasL {
								// 空的旧规则两边都不命中, 语义为空, 迁移时丢弃。
								continue
							}
							continue
						}
						pgRules = append(pgRules, &r)
					}
					continue
				}
				// 旧格式: 端口不变、协议全部、来源=自定义位置(中国)(旧省名单)、允许、生效态与时长不变
				var old legacyPortGuardRule
				if json.Unmarshal(item, &old) != nil {
					continue
				}
				r := &PortGuardRule{
					ID: old.ID, PortText: formatPorts(old.Ports), Proto: "all",
					Source:   FWSource{Kind: "custom_cn", Locations: old.Locations},
					Action:   "allow",
					BanHours: old.BanHours, Enabled: old.Enabled,
				}
				r.ranges = portsToRanges(old.Ports)
				pgRules = append(pgRules, r)
				migrated = true
			}
			if migrated {
				savePortGuardLocked()
			}
		}
	}
	if pgRules == nil {
		pgRules = []*PortGuardRule{}
	}
	// 一个端口一种动作的旧数据迁移(顺序不能乱):
	//  1. 先清动作冲突: 后建且动作相反的生效规则改禁用并释放其封禁(同动作并集保留);
	//  2. 再清拒绝规则端口上的旧默认封禁(旧语义下拒绝端口的未命中来源也被默认封禁,
	//     新语义下一律放行, 留着等于旧规则阴魂不散, 新规则永不生效);
	//  3. 最后按现行规则归一化剩余旧封禁(原有 migrateFwBansLocked)。
	if migrateFwRuleOverlapLocked() {
		savePortGuardLocked()
	}
	migrateFwDefaultBanOnDenyLocked()
	// 防火墙封禁改永久: 升级后首次加载, 把现存生效中的防火墙封禁
	// 转永久并挂到现行规则上, 无规则覆盖的予以释放(记录保留)。
	migrateFwBansLocked()
}

// migrateFwRuleOverlapLocked: 一个端口一种动作的旧数据迁移(调用方须已持 pgMu)。
// 旧版本允许多规则同端口(拒绝优先暗箱裁决), 新语义下允许与拒绝共存才是逻辑冲突:
// 按创建顺序, 每组重叠的已生效规则只保留最早一条的动作, 后建且动作相反的改禁用并
// 释放它们产生的封禁(releaseRuleBans: 只摘该规则的作用域, 记录保留); 同动作的后建
// 规则保留(来源并集, 如 v1.0.9 custom_loc 拆分对); 停用的旧规则原样保留可见,
// 但启用时会被启用关拦截, 直到冲突的生效规则被停用或删掉。
// 幂等: 迁移后不存在动作混杂的重叠生效规则, 再跑即空转。返回是否改动过规则。
func migrateFwRuleOverlapLocked() bool {
	kept := []*PortGuardRule{}
	changed := false
	disabled := []string{}
	for _, r := range pgRules {
		if !r.Enabled {
			continue
		}
		conflict := false
		for _, k := range kept {
			if k.Proto != "all" && r.Proto != "all" && k.Proto != r.Proto {
				continue
			}
			if k.Action == r.Action {
				continue
			}
			for _, a := range k.ranges {
				for _, b := range r.ranges {
					if a[0] <= b[1] && b[0] <= a[1] {
						conflict = true
					}
				}
			}
		}
		if conflict {
			r.Enabled = false
			disabled = append(disabled, r.ID)
			changed = true
			continue
		}
		kept = append(kept, r)
	}
	for _, id := range disabled {
		releaseRuleBans(id)
	}
	return changed
}

// migrateFwDefaultBanOnDenyLocked: 拒绝规则端口上旧默认封禁的清理(调用方须已持 pgMu,
// 且须在 migrateFwBansLocked 之前跑, 看的是原始作用域)。
// 旧语义下拒绝规则端口上的未命中来源也会被默认封禁; 新语义下拒绝规则只封命中来源,
// 未命中一律放行——旧默认封禁若留着, 新规则对这些 IP 永不生效。
// 只动能确证的: 原因以“防火墙默认封禁”开头、且唯一作用域规则为现行已生效拒绝规则的封禁,
// 或端口全落在同一条现行已生效拒绝规则范围内的旧 Ports 封禁; 允许规则端口上的默认封禁
// 在新语义下依然该封, 原样保留; 作用域混杂的保守不动, 交给后续归一化处理。
// 记录保留(只改状态), 内核集合同步删除。
func migrateFwDefaultBanOnDenyLocked() {
	denyRanges := map[string][][2]int{}
	for _, r := range pgRules {
		if r.Enabled && r.Action == "deny" {
			denyRanges[r.ID] = r.ranges
		}
	}
	if len(denyRanges) == 0 {
		return
	}
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now().Unix()
	changed := false
	for _, b := range bans {
		if b.Source != "portguard" {
			continue
		}
		normBanStatus(b, now)
		if b.Status != BanActive || !b.enforced(now) {
			continue
		}
		if !strings.HasPrefix(b.Reason, "防火墙默认封禁") {
			continue
		}
		release := false
		if len(b.Scopes) == 1 && len(b.Ports) == 0 {
			if _, ok := denyRanges[b.Scopes[0].RuleID]; ok {
				release = true
			}
		} else if len(b.Scopes) == 0 && len(b.Ports) > 0 {
			for _, rs := range denyRanges {
				all := true
				for _, p := range b.Ports {
					if !rangeCovers(rs, p) {
						all = false
						break
					}
				}
				if all {
					release = true
					break
				}
			}
		}
		if !release {
			continue
		}
		for _, p := range b.Ports {
			pgDelElement(b.IP, p)
		}
		for _, s := range b.Scopes {
			fwDelElement(b.IP, s.RuleID)
		}
		b.Ports = nil
		b.Scopes = nil
		b.Status = BanReleased
		b.ReleasedAt = now
		changed = true
	}
	if changed {
		saveBans()
	}
}

// migrateFwBansLocked 防火墙封禁永久化迁移(调用方须已持 pgMu)。
// 只动 Source=portguard 且状态为 active 的记录: 按其端口找现行已启用
// 规则, 优先拒绝规则、其次首个覆盖规则(先全覆盖、后部分覆盖); 找到则
// Until=0 并挂该规则的完整范围(内核集合本就是按规则整组封禁, 与
// 作用域口径一致); 找不到则释放(状态 released, 从内核集合里删掉)。
// 转换量 = 封禁数 × 规则数, 毫秒级, 不阻塞启动。
func migrateFwBansLocked() {
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now().Unix()
	changed := false
	for _, b := range bans {
		if b.Source != "portguard" {
			continue
		}
		normBanStatus(b, now)
		if b.Status != BanActive {
			continue
		}
		ports := map[int]bool{}
		for _, s := range b.Scopes {
			for _, r := range s.Ranges {
				for p := r[0]; p <= r[1]; p++ {
					ports[p] = true
				}
			}
		}
		for _, p := range b.Ports {
			ports[p] = true
		}
		if len(ports) == 0 {
			b.Status = BanReleased
			b.ReleasedAt = now
			b.Scopes = nil
			b.Ports = nil
			changed = true
			continue
		}
		var full, part *PortGuardRule
		for _, r := range pgRules {
			if !r.Enabled {
				continue
			}
			all, any := true, false
			for p := range ports {
				if ruleCoversPort(r, p) {
					any = true
				} else {
					all = false
				}
			}
			if !any {
				continue
			}
			if all {
				if r.Action == "deny" {
					full = r
					break
				}
				if full == nil {
					full = r
				}
			} else {
				// 部分覆盖: 拒绝优先于允许, 同类取首个。
				if part == nil || (r.Action == "deny" && part.Action != "deny") {
					part = r
				}
			}
		}
		chosen := full
		if chosen == nil {
			chosen = part
		}
		if chosen == nil {
			for _, s := range b.Scopes {
				fwDelElement(b.IP, s.RuleID)
			}
			for _, p := range b.Ports {
				pgDelElement(b.IP, p)
			}
			b.Status = BanReleased
			b.ReleasedAt = now
			b.Scopes = nil
			b.Ports = nil
			changed = true
			continue
		}
		if b.Until != 0 || len(b.Scopes) != 1 || b.Scopes[0].RuleID != chosen.ID {
			changed = true
		}
		b.Until = 0
		b.Scopes = []BanScope{{RuleID: chosen.ID, Ranges: append([][2]int{}, chosen.ranges...)}}
		b.Ports = nil
		fwAddElement(b.IP, chosen.ID, permBanBackstopSec)
	}
	if changed {
		saveBans()
	}
}

// ruleCoversPort: 规则的端口范围是否含指定端口。
func ruleCoversPort(r *PortGuardRule, port int) bool {
	for _, rg := range r.ranges {
		if port >= rg[0] && port <= rg[1] {
			return true
		}
	}
	return false
}

func savePortGuardLocked() { saveJSON(portGuardFile(), pgRules) }

// normalizeCountrySelections: 旧国家字符串 -> 代码(能归一化的转代码,
// 归一化不了的原样保留, 匹配时靠原字符串回退, 避免迁移丢语义); 去重保序。
func normalizeCountrySelections(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		if e, ok := countryEntryForName(c); ok {
			c = e.Code
		} else if code := countryCodeForName(c); code != "" {
			c = code
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

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

// parsePortRanges 解析端口文本: 分隔符支持英文逗号、中文逗号、正反斜杠、
// 顿号, 空格只做修剪不做分隔; 每段可为单个端口或 lo-hi 范围(如 1-65535)。
// 重叠/相邻范围自动合并并升序。出错时返回带问题片段的报错, 其中含非法
// 符号的按 PAPA 原话提示"符号不对, 不可以"。
func parsePortRanges(s string) ([][2]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("请填写端口")
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == '/' || r == '\\' || r == '、'
	})
	out := [][2]int{}
	for _, f := range fields {
		t := strings.TrimSpace(f)
		if t == "" {
			continue
		}
		if strings.Contains(t, "-") {
			parts := strings.Split(t, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("端口范围 %s 格式不对", t)
			}
			lo, err1 := parsePortNum(strings.TrimSpace(parts[0]))
			hi, err2 := parsePortNum(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				if err1 != nil {
					return nil, err1
				}
				return nil, err2
			}
			if lo > hi {
				return nil, fmt.Errorf("端口范围 %s 起止不对", t)
			}
			out = append(out, [2]int{lo, hi})
			continue
		}
		n, err := parsePortNum(t)
		if err != nil {
			return nil, err
		}
		out = append(out, [2]int{n, n})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("请填写端口")
	}
	return mergeRanges(out), nil
}

func parsePortNum(t string) (int, error) {
	if t == "" {
		return 0, fmt.Errorf("请填写端口")
	}
	for _, r := range t {
		if !unicode.IsDigit(r) {
			return 0, fmt.Errorf("符号 '%c' 不对，不可以", r)
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
		return 0, fmt.Errorf("端口 %s 超出范围(1-65535)", t)
	}
	return n, nil
}

// mergeRanges 排序并合并重叠/相邻的范围。
func mergeRanges(in [][2]int) [][2]int {
	if len(in) == 0 {
		return in
	}
	sorted := append([][2]int{}, in...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i][0] != sorted[j][0] {
			return sorted[i][0] < sorted[j][0]
		}
		return sorted[i][1] < sorted[j][1]
	})
	out := [][2]int{sorted[0]}
	for _, r := range sorted[1:] {
		last := &out[len(out)-1]
		if r[0] <= last[1]+1 {
			if r[1] > last[1] {
				last[1] = r[1]
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func rangesEqual(a, b [][2]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// formatPortRanges 范围展示: 单端口 "80"、范围 "8000-8010"、全范围 "全部端口"。
func formatPortRanges(ranges [][2]int) string {
	if len(ranges) == 1 && ranges[0][0] == 1 && ranges[0][1] == 65535 {
		return "全部端口"
	}
	parts := []string{}
	for _, r := range ranges {
		if r[0] == r[1] {
			parts = append(parts, itoa(r[0]))
		} else {
			parts = append(parts, itoa(r[0])+"-"+itoa(r[1]))
		}
	}
	return strings.Join(parts, ",")
}

// formatPorts 旧端口列表转文本(迁移用)。
func formatPorts(ports []int) string {
	parts := []string{}
	for _, p := range ports {
		parts = append(parts, itoa(p))
	}
	return strings.Join(parts, ",")
}

func portsToRanges(ports []int) [][2]int {
	out := [][2]int{}
	for _, p := range ports {
		out = append(out, [2]int{p, p})
	}
	return mergeRanges(out)
}

func rangeCovers(ranges [][2]int, port int) bool {
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// ---------- 省市清单校验与展示(自定义位置复用) ----------

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

// guardDisplay 省市展示名(用清单里的 Display, 如 江苏省、南京市（江苏省）)。
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

// ---------- 归属地分类(按 2026-10-27 内嵌库实测字段写, 不许凭空假设) ----------

// quirkProvMap: 库里个别 Cloudflare 中国 IP 把市写进了省份字段(省=广州/武汉),
// 匹配前先归属到真实省份, 否则广东/武汉规则匹配不上这些 IP。
var quirkProvMap = map[string]string{"广州": "广东", "武汉": "湖北"}

// guardLocationAllowed 省市判定: 任一位置命中即放行。省条目比省份字段,
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

// geoSAR: 该归属地是否港澳台, 是则返回"香港"/"澳门"/"台湾", 否则返回 ""。
// 实测: 库里港澳台的国家字段仍是"中国"(如 116.48.125.74 -> 中国|香港特别
// 行政区), 必须看省份, 不能只看国家。Code 分支是 v6 库兼容(v4 库里香港
// 的 Code 也是 CN, 指望不上)。
func geoSAR(geo GeoInfo) string {
	switch normRegionName(geo.Province) {
	case "香港", "澳门", "台湾":
		return normRegionName(geo.Province)
	}
	switch geo.Country {
	case "香港", "澳门", "台湾":
		return geo.Country
	case "中国香港":
		return "香港"
	case "中国澳门":
		return "澳门"
	case "中国台湾":
		return "台湾"
	}
	switch geo.Code {
	case "HK":
		return "香港"
	case "MO":
		return "澳门"
	case "TW":
		return "台湾"
	}
	return ""
}

// geoIsMainland: 是否中国大陆(国家是中国且省份不在港澳台)。港澳台在此算"国外"。
func geoIsMainland(geo GeoInfo) bool {
	return geo.Country == "中国" && geoSAR(geo) == ""
}

// parseCIDRNet: IP 或 CIDR 转网段。裸 IP 按单地址(/32 或 /128)处理;
// 解析失败返回 nil(调用方按不命中处理, 校验层会先拦住非法输入)。
func parseCIDRNet(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil
		}
		return n
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

// parseCIDRNets: 逗号分隔的多个 IP/CIDR 转网段表(一个端口一条规则后,
// 多 IP 允许要写进同一条规则)。任一非法即整体失败; 去重后返回。
func parseCIDRNets(s string) ([]*net.IPNet, error) {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == '、'
	})
	nets := []*net.IPNet{}
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n := parseCIDRNet(p)
		if n == nil {
			return nil, fmt.Errorf("IP 或 CIDR 格式不对: %s", p)
		}
		if seen[n.String()] {
			continue
		}
		seen[n.String()] = true
		nets = append(nets, n)
	}
	return nets, nil
}

// fwSourceMatch: 该来源范围是否命中(单选其一, 任一命中即命中)。
// 未知归属地(Country=="")不命中任何国家/省份类来源, 只命中"全部 IP"
// (与"全部 IPv4/IPv6"按地址族判定, 与归属地无关)。
func fwSourceMatch(src FWSource, ip net.IP, geo GeoInfo) bool {
	switch src.Kind {
	case "all":
		return true
	case "all_v4":
		return ip.To4() != nil
	case "all_v6":
		return ip.To4() == nil
	case "cn_in":
		return geoIsMainland(geo)
	case "cn_out":
		// 境外 = 非大陆: 外国 + 港澳台(港澳台不算大陆, 故可访问); 未知与私网不命中
		return geo.Country != "" && !geo.Private && !geoIsMainland(geo)
	case "custom_ip":
		for _, n := range src.cidrNets {
			if n != nil && n.Contains(ip) {
				return true
			}
		}
		return false
	case "custom_cn":
		// 自定义位置(中国): 省市任一命中即命中, 港澳台不在此列。
		return guardLocationAllowed(src.Locations, geo)
	case "custom_foreign":
		// 自定义位置(海外): 按代码归一化匹配。库里 "India" 与 "印度" 同属
		// IN, 选任何一种写法都生效; 迁移残留的旧字符串靠原串回退匹配。
		code := countryCodeForGeo(geo)
		for _, c := range src.Countries {
			if code != "" {
				if c == code {
					return true
				}
				if e, ok := countryEntryForName(c); ok && e.Code == code {
					return true
				}
			}
			if geo.Country != "" && c == geo.Country {
				return true
			}
		}
		return false
	}
	return false
}

// fwSourceSummary 来源范围的用户可见展示(对话框与规则列表共用)。
func fwSourceSummary(src FWSource) string {
	switch src.Kind {
	case "custom_ip":
		return src.CIDR
	case "all_v4":
		return "全部 IPv4"
	case "all_v6":
		return "全部 IPv6"
	case "cn_in":
		return "中国大陆境内"
	case "cn_out":
		return "中国大陆境外"
	case "custom_cn":
		if d := guardDisplay(src.Locations); d != "" {
			return "自定义位置（中国）：" + d
		}
		return "自定义位置（中国）"
	case "custom_foreign":
		parts := []string{}
		for _, c := range src.Countries {
			parts = append(parts, countryZhForCode(c))
		}
		if len(parts) == 0 {
			return "自定义位置（海外）"
		}
		return "自定义位置（海外）：" + strings.Join(parts, "、")
	case "all":
		return "全部 IP"
	}
	return src.Kind
}

func fwProtoLabel(proto string) string {
	switch proto {
	case "tcp":
		return "TCP"
	case "udp":
		return "UDP"
	}
	return "全部协议"
}

// fwRuleDesc 规则的用户可见描述(封禁原因与规则列表共用)。
func fwRuleDesc(r *PortGuardRule) string {
	return "端口 " + formatPortRanges(r.ranges) + " · " + fwProtoLabel(r.Proto) + " · " + fwSourceSummary(r.Source)
}

// fwRulesFor 覆盖指定端口与协议的生效规则(按创建顺序)。
func fwRulesFor(port int, proto string) []*PortGuardRule {
	pgMu.Lock()
	defer pgMu.Unlock()
	out := []*PortGuardRule{}
	for _, r := range pgRules {
		if !r.Enabled {
			continue
		}
		if r.Proto != "all" && r.Proto != proto {
			continue
		}
		if rangeCovers(r.ranges, port) {
			out = append(out, r)
		}
	}
	return out
}

// fwCoversPort 该端口与协议是否被任一生效规则覆盖(采集层可见性判定)。
func fwCoversPort(port int, proto string) bool {
	return len(fwRulesFor(port, proto)) > 0
}

// ---------- 旧按端口 nft 集合(旧 Ports 记录专用, 新规则走 fw 集合) ----------

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

// ensurePortGuardSets 为全部旧按端口封禁记录的端口建集合与规则(规则端口
// 不再走这里, 新规则由 ensureFWSets 建 fw 集合)。
func ensurePortGuardSets() {
	if dryBan {
		pgLinkOK = true
		return
	}
	ports := map[int]bool{}
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

// reconcilePortGuard 旧按端口集合与旧按端口记录对齐: 生效中必封、非生效中必不在集合。
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

// ---------- 防火墙 nft 集合(按规则, 范围不展开) ----------

func fwSetName(ruleID string, v6 bool) string {
	if v6 {
		return "fw6_" + ruleID
	}
	return "fw4_" + ruleID
}

func fwSetNameFor(ip string, ruleID string) string {
	if pip := net.ParseIP(ip); pip != nil && pip.To4() == nil {
		return fwSetName(ruleID, true)
	}
	return fwSetName(ruleID, false)
}

func fwRangeExpr(r [2]int) string {
	if r[0] == r[1] {
		return itoa(r[0])
	}
	return itoa(r[0]) + "-" + itoa(r[1])
}

// ensureFWRuleRanges 为某规则 ID 建集合 + 按范围的 drop 规则(幂等)。
// proto=all 时 TCP/UDP 各建一条; 单协议只建该协议。规则只丢"来源在
// 集合里 且 目标端口在范围里"的包, 不影响该 IP 的其他端口。
func ensureFWRuleRanges(ruleID string, ranges [][2]int, proto string) bool {
	if dryBan {
		pgLinkOK = true
		return true
	}
	ok := true
	for _, s := range []struct{ name, typ string }{{fwSetName(ruleID, false), "ipv4_addr"}, {fwSetName(ruleID, true), "ipv6_addr"}} {
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
	protos := []string{"tcp", "udp"}
	if proto == "tcp" {
		protos = []string{"tcp"}
	} else if proto == "udp" {
		protos = []string{"udp"}
	}
	for _, r := range ranges {
		for _, v6 := range []bool{false, true} {
			fam := "ip"
			if v6 {
				fam = "ip6"
			}
			set := fwSetName(ruleID, v6)
			for _, pr := range protos {
				needle := "@" + set + " " + pr + " dport " + fwRangeExpr(r) + " drop"
				if strings.Contains(out, needle) {
					continue
				}
				if _, err := nft("add", "rule", "inet", nftTable, "input", fam, "saddr", "@"+set, pr, "dport", fwRangeExpr(r), "drop"); err != nil {
					ok = false
				}
			}
		}
	}
	return ok
}

func ensureFWRule(r *PortGuardRule) bool {
	return ensureFWRuleRanges(r.ID, r.ranges, r.Proto)
}

// ensureFWSets 为全部规则 + 已删规则的封禁记录建 fw 集合与规则。
// 已删规则按记录里的范围、双协议重建(协议未知时只保不丢); 现存规则
// 按自身协议建, 不多建另一协议。
func ensureFWSets() {
	if dryBan {
		pgLinkOK = true
		return
	}
	ok := true
	pgMu.Lock()
	rules := append([]*PortGuardRule{}, pgRules...)
	pgMu.Unlock()
	live := map[string]bool{}
	for _, r := range rules {
		live[r.ID] = true
		if !ensureFWRule(r) {
			ok = false
		}
	}
	banMu.Lock()
	recs := append([]*Ban{}, bans...)
	banMu.Unlock()
	seen := map[string]bool{}
	for _, b := range recs {
		for _, s := range b.Scopes {
			if live[s.RuleID] || seen[s.RuleID] {
				continue
			}
			seen[s.RuleID] = true
			if !ensureFWRuleRanges(s.RuleID, s.Ranges, "all") {
				ok = false
			}
		}
	}
	pgLinkOK = ok
}

// fwDeleteRules 按 handle 删掉某规则 ID 的全部 nft 规则(编辑规则换范围时
// 用; 集合与成员保留, 已封禁 IP 的生效端口随新规则走)。删失败返回 false,
// 调用方不因此中断(旧规则残留是多封、不是漏封)。
func fwDeleteRules(ruleID string) bool {
	if dryBan {
		return true
	}
	out, err := nft("-a", "list", "chain", "inet", nftTable, "input")
	if err != nil {
		return false
	}
	ok := true
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "@fw4_"+ruleID) && !strings.Contains(line, "@fw6_"+ruleID) {
			continue
		}
		idx := strings.Index(line, "# handle ")
		if idx < 0 {
			continue
		}
		h := strings.TrimSpace(line[idx+len("# handle "):])
		if sp := strings.IndexAny(h, " \t"); sp >= 0 {
			h = h[:sp]
		}
		if _, err := nft("delete", "rule", "inet", nftTable, "input", "handle", h); err != nil {
			ok = false
		}
	}
	return ok
}

func fwAddElement(ip string, ruleID string, timeoutSec int) {
	set := fwSetNameFor(ip, ruleID)
	elem := ip
	if timeoutSec > 0 && setSupportsTimeout(set) {
		elem = ip + " timeout " + itoa(timeoutSec) + "s"
	}
	nft("delete", "element", "inet", nftTable, set, "{", ip, "}")
	nft("add", "element", "inet", nftTable, set, "{", elem, "}")
}

func fwDelElement(ip string, ruleID string) {
	nft("delete", "element", "inet", nftTable, fwSetNameFor(ip, ruleID), "{", ip, "}")
}

// reconcileFirewall fw 集合与 Scopes 记录对齐: 生效中必封、非生效中必不在集合。
// 规则删除/禁用时会先经 releaseRuleBans 摘掉该规则的作用域, 故对齐时已无
// 活跃记录指向已删规则; 下面已删规则重建分支仅作历史遗留记录的安全网。
func reconcileFirewall() {
	if dryBan {
		return
	}
	now := time.Now().Unix()
	desired := map[string]map[string]*Ban{}
	ruleIDs := map[string]bool{}
	banMu.Lock()
	allRecs := append([]*Ban{}, bans...)
	banMu.Unlock()
	for _, b := range allRecs {
		for _, s := range b.Scopes {
			ruleIDs[s.RuleID] = true
		}
	}
	for _, b := range activeBans() {
		for _, s := range b.Scopes {
			if desired[s.RuleID] == nil {
				desired[s.RuleID] = map[string]*Ban{}
			}
			desired[s.RuleID][b.IP] = b
		}
	}
	pgMu.Lock()
	live := map[string]*PortGuardRule{}
	for _, r := range pgRules {
		live[r.ID] = r
	}
	pgMu.Unlock()
	for id := range ruleIDs {
		if r, ok := live[id]; ok {
			ensureFWRule(r)
			continue
		}
		merged := [][2]int{}
		for _, b := range allRecs {
			for _, s := range b.Scopes {
				if s.RuleID == id {
					merged = append(merged, s.Ranges...)
				}
			}
		}
		ensureFWRuleRanges(id, mergeRanges(merged), "all")
	}
	for id := range ruleIDs {
		for _, v6 := range []bool{false, true} {
			set := fwSetName(id, v6)
			actual, err := nftListSet(set)
			if err != nil {
				continue // 集合缺失或读失败时本轮跳过, 上面已重建
			}
			for ip := range actual {
				if _, want := desired[id][ip]; !want {
					nft("delete", "element", "inet", nftTable, set, "{", ip, "}")
				}
			}
			for ip, b := range desired[id] {
				if fwSetNameFor(ip, id) != set || actual[ip] {
					continue
				}
				fwAddElement(ip, id, banKernelTimeout(b, now))
			}
		}
	}
}

// ---------- enforcement ----------

// portGuardCheck 新连接的防火墙检查(采集循环调用, proto 为 tcp|udp)。
// 顺序: 拒绝命中 > 允许命中 > 默认封禁; 内网/回环/保留段/信任/已封禁直接放过。
// portGuardCheck: 防火墙命中判定——一个端口只能有一种动作, 语义只有两种, 没有第三态:
//   - 允许规则: 任一来源命中 → 放行; 全不命中 → 拒绝(永久封禁, 作用域为规则端口)。
//   - 拒绝规则: 任一来源命中 → 拒绝(永久封禁); 全不命中 → 放行。
//   - 端口上没有任何生效规则 → 防火墙不管(原样放行, 不封禁)。
//
// 同动作多条规则按来源并集算(拆分对、跨类型多源都靠它); 允许与拒绝共存的旧数据
// 靠加载迁移清掉(见 migrateFwRuleOverlapLocked); 万一仍有动作混杂(手改 JSON),
// 取创建顺序第一条的动作, 绝不搞“拒绝优先”这种暗箱裁决。
func portGuardCheck(srcIP string, dstPort int, proto string) {
	rules := fwRulesFor(dstPort, proto)
	if len(rules) == 0 {
		return
	}
	pip := net.ParseIP(srcIP)
	if pip == nil {
		return
	}
	if ok, _ := bannable(srcIP); !ok {
		return // 内网/回环/保留段/信任名单永远豁免
	}
	if isGloballyBanned(srcIP) || isBannedFor(srcIP, dstPort) {
		return
	}
	geo := geoLookup(srcIP)
	if geo.Private {
		return
	}
	// 展示用归属地: 库查不到国家时记"归属地未知", 绝不静默当成某国;
	// 查得到时用 geo.Text(已含" · ISP", 如 Bangladesh · Cloudflare)。
	geoDisp := geo.Text
	if geo.Country == "" {
		geoDisp = "归属地未知"
	}
	r := rules[0]
	matched := false
	for _, rr := range rules {
		if fwSourceMatch(rr.Source, pip, geo) {
			matched = true
			break
		}
	}
	if r.Action == "allow" {
		if matched {
			return
		}
		reason := "防火墙拒绝：未命中允许规则（规则：" + fwRuleDesc(r) + "），来源" + geoDisp
		ensureFWRule(r)
		_, fresh, err := applyRuleBan(srcIP, reason, "portguard", r.ID, r.ranges)
		if err != nil || !fresh {
			return
		}
		emit(Event{Type: "portguard_ban", IP: srcIP, Port: dstPort, Detail: reason}, settings.AlertPortGuardBan)
		return
	}
	// deny: 命中才拒绝, 未命中一律放行。
	if !matched {
		return
	}
	reason := "防火墙拒绝：" + fwRuleDesc(r) + "，来源" + geoDisp
	ensureFWRule(r)
	_, fresh, err := applyRuleBan(srcIP, reason, "portguard", r.ID, r.ranges)
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

// geoCountryAllowed: 自定义位置的国家选项是否合法(库原字符串 + 港澳台)。
func geoCountryAllowed(c string) bool {
	if c == "香港" || c == "澳门" || c == "台湾" {
		return true
	}
	for _, x := range geoCountries() {
		if x == c {
			return true
		}
	}
	return false
}

// parseFWRuleInput 校验一条防火墙规则的输入(POST 新增与 PUT 编辑共用)。
// 返回可直接落库的规则(已填充 ranges 与 cidrNet); 非相关字段会被清空
// (如切到全部 IP 后旧 CIDR 不残留)。
func parseFWRuleInput(portText, proto string, src FWSource, action string, banHours int) (*PortGuardRule, error) {
	ranges, err := parsePortRanges(portText)
	if err != nil {
		return nil, err
	}
	switch proto {
	case "", "all":
		proto = "all"
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("通信协议不对")
	}
	switch action {
	case "", "allow":
		action = "allow"
	case "deny":
	default:
		return nil, fmt.Errorf("动作不对")
	}
	switch src.Kind {
	case "custom_ip":
		src.CIDR = strings.TrimSpace(src.CIDR)
		if src.CIDR == "" {
			return nil, fmt.Errorf("请填写 IP 或 CIDR")
		}
		nets, err := parseCIDRNets(src.CIDR)
		if err != nil || len(nets) == 0 {
			return nil, fmt.Errorf("IP 或 CIDR 格式不对")
		}
		src.cidrNets = nets
		src.Countries = nil
		src.Locations = nil
	case "all_v4", "all_v6", "cn_in", "cn_out", "all":
		src.CIDR = ""
		src.Countries = nil
		src.Locations = nil
	case "custom_cn":
		src.CIDR = ""
		src.Countries = nil
		if len(src.Locations) == 0 {
			return nil, fmt.Errorf("自定义位置（中国）请至少选一个省市")
		}
		locSeen := map[string]bool{}
		locOut := []GuardLocation{}
		for i := range src.Locations {
			l := src.Locations[i]
			l.Name = normRegionName(l.Name)
			l.Province = normRegionName(l.Province)
			if l.Kind == "province" {
				l.Province = ""
			}
			if l.Name == "香港" || l.Name == "澳门" || l.Name == "台湾" || l.Province == "香港" || l.Province == "澳门" || l.Province == "台湾" {
				return nil, fmt.Errorf("港澳台不进中国选择器, 请到自定义位置（海外）里选")
			}
			if !validGuardLocation(l) {
				return nil, fmt.Errorf("自定义位置（中国）中含未知省市: %s", l.Name)
			}
			k := l.Kind + "|" + l.Name + "|" + l.Province
			if locSeen[k] {
				continue
			}
			locSeen[k] = true
			locOut = append(locOut, l)
		}
		src.Locations = locOut
	case "custom_foreign":
		src.CIDR = ""
		src.Locations = nil
		if len(src.Countries) == 0 {
			return nil, fmt.Errorf("自定义位置（海外）请至少选一个国家或地区")
		}
		// 入库一律存代码: 旧字符串(中文名/库原英文)归一化转代码, 归一化不了
		// 的原样保留(匹配时靠原串回退, 不丢语义)。
		src.Countries = normalizeCountrySelections(src.Countries)
		for _, c := range src.Countries {
			if _, ok := countryEntryForCode(c); ok {
				continue
			}
			if !geoCountryAllowed(c) {
				return nil, fmt.Errorf("未知国家或地区: %s", c)
			}
		}
	default:
		return nil, fmt.Errorf("来源范围不对")
	}
	hours := banHours
	if hours < 0 {
		return nil, fmt.Errorf("封禁时长不能为负")
	}
	if hours > 8760 {
		hours = 8760
	}
	return &PortGuardRule{PortText: portText, Proto: proto, Source: src, Action: action, BanHours: hours, ranges: ranges}, nil
}

// fwRuleDup: 与已有规则完全相同(端口范围+协议+动作+来源)即判重复(生效态不计)。
// 精确重复与动作冲突互斥: 重复是同动作, 冲突是反动作, 两关并列。
func fwRuleDup(r *PortGuardRule, skipID string) bool {
	pgMu.Lock()
	defer pgMu.Unlock()
	return fwRuleDupLocked(r, skipID)
}

// fwRuleDupLocked: 调用方已持 pgMu 时用。
func fwRuleDupLocked(r *PortGuardRule, skipID string) bool {
	for _, x := range pgRules {
		if x.ID == skipID {
			continue
		}
		if !rangesEqual(x.ranges, r.ranges) || x.Proto != r.Proto || x.Action != r.Action {
			continue
		}
		if x.Source.Kind != r.Source.Kind || x.Source.CIDR != r.Source.CIDR {
			continue
		}
		if len(x.Source.Countries) != len(r.Source.Countries) {
			continue
		}
		match := true
		for i, c := range x.Source.Countries {
			if r.Source.Countries[i] != c {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if len(x.Source.Locations) != len(r.Source.Locations) {
			continue
		}
		for i, l := range x.Source.Locations {
			if r.Source.Locations[i] != l {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// fwRuleConflict: 新规则是否与已有生效规则在端口与协议上重叠且动作相反
// (一个端口只能有一种动作: 允许与拒绝绝不共存, 这才是真正的逻辑冲突;
// 同动作多条规则按来源并集算, 不冲突——如 v1.0.9 custom_loc 拆分对,
// 以及“江苏 + 美国”这种跨类型多源允许, 都靠并集表达)。
// 只与生效规则比: 停用的规则不是该端口现行设置, 不挡新建; 启用时再拦一次。
// skipID: 编辑时跳过自身。返回冲突的那条规则(用于报错里点名), 无冲突返回 nil。
func fwRuleConflict(r *PortGuardRule, skipID string) *PortGuardRule {
	pgMu.Lock()
	defer pgMu.Unlock()
	return fwRuleConflictLocked(r, skipID)
}

// fwRuleConflictLocked: 调用方已持 pgMu 时用。
func fwRuleConflictLocked(r *PortGuardRule, skipID string) *PortGuardRule {
	for _, x := range pgRules {
		if x.ID == skipID || !x.Enabled {
			continue
		}
		if x.Action == r.Action {
			continue
		}
		if x.Proto != "all" && r.Proto != "all" && x.Proto != r.Proto {
			continue
		}
		overlap := false
		for _, a := range x.ranges {
			for _, b := range r.ranges {
				if a[0] <= b[1] && b[0] <= a[1] {
					overlap = true
					break
				}
			}
			if overlap {
				break
			}
		}
		if overlap {
			return x
		}
	}
	return nil
}

// fwConflictErr: 动作冲突报错文案, 点名冲突规则(端口 + 协议 + 动作 + 来源)。
func fwConflictErr(x *PortGuardRule) string {
	act := "允许"
	if x.Action == "deny" {
		act = "拒绝"
	}
	return "端口已有生效的" + act + "规则（" + fwRuleDesc(x) + "），一个端口上不许同时存在允许和拒绝；想换动作请先停用或删除旧规则"
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
			PortText string   `json:"portText"`
			Proto    string   `json:"proto"`
			Source   FWSource `json:"source"`
			Action   string   `json:"action"`
			// BanHours 仅线上传输兼容(旧节点缺省 0=永久), 引擎不再使用:
			// 防火墙封禁一律永久, 直到规则删除/禁用或手动解封。
			BanHours int `json:"banHours"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		rule, err := parseFWRuleInput(in.PortText, in.Proto, in.Source, in.Action, 0)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		if fwRuleDup(rule, "") {
			errJSON(w, 400, "已存在相同规则")
			return
		}
		if x := fwRuleConflict(rule, ""); x != nil {
			errJSON(w, 400, fwConflictErr(x))
			return
		}
		rule.ID = newPortGuardRuleID()
		rule.Enabled = true
		pgMu.Lock()
		pgRules = append(pgRules, rule)
		savePortGuardLocked()
		pgMu.Unlock()
		ensureFWRule(rule)
		writeJSON(w, 200, rule)
	default:
		errJSON(w, 405, "method")
	}
}

func handlePortGuardItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/portguard/")
	switch r.Method {
	case "PUT":
		// 开关切换只传 enabled；整条编辑传 portText(+proto+source+action)，两者可同传。
		// banHours 已废弃: 传了也忽略, 封禁一律永久。
		var in struct {
			Enabled  *bool     `json:"enabled"`
			PortText *string   `json:"portText"`
			Proto    *string   `json:"proto"`
			Source   *FWSource `json:"source"`
			Action   *string   `json:"action"`
			BanHours *int      `json:"banHours"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || (in.Enabled == nil && in.PortText == nil) {
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
		if in.Enabled != nil && *in.Enabled && !rule.Enabled {
			// 启用开关：只与已生效且动作相反的规则比（迁移遗留的动作冲突对就靠这一关拦住；
			// 同动作重叠是并集，不拦）。
			if x := fwRuleConflictLocked(&PortGuardRule{Proto: rule.Proto, Action: rule.Action, ranges: rule.ranges}, id); x != nil {
				pgMu.Unlock()
				errJSON(w, 400, fwConflictErr(x))
				return
			}
		}
		if in.Enabled != nil {
			rule.Enabled = *in.Enabled
		}
		edited := false
		if in.PortText != nil {
			proto := rule.Proto
			if in.Proto != nil {
				proto = *in.Proto
			}
			src := rule.Source
			if in.Source != nil {
				src = *in.Source
			}
			action := rule.Action
			if in.Action != nil {
				action = *in.Action
			}
			// banHours 已废弃, 一律按永久处理(旧节点缺省 0=永久, 与新语义一致)。
			nr, err := parseFWRuleInput(*in.PortText, proto, src, action, 0)
			if err != nil {
				pgMu.Unlock()
				errJSON(w, 400, err.Error())
				return
			}
			if fwRuleDupLocked(nr, id) {
				pgMu.Unlock()
				errJSON(w, 400, "已存在相同规则")
				return
			}
			if x := fwRuleConflictLocked(nr, id); x != nil {
				pgMu.Unlock()
				errJSON(w, 400, fwConflictErr(x))
				return
			}
			rule.PortText, rule.Proto, rule.Source, rule.Action, rule.BanHours, rule.ranges = nr.PortText, nr.Proto, nr.Source, nr.Action, nr.BanHours, nr.ranges
			edited = true
		}
		savePortGuardLocked()
		pgMu.Unlock()
		if edited {
			// 旧范围规则删掉重建, 集合成员保留, 已封禁随新规则走
			fwDeleteRules(id)
			ensureFWRule(rule)
		}
		if in.Enabled != nil && !*in.Enabled {
			// 规则禁用即释放该规则产生的全部封禁(记录保留); 重启用后下次命中再封禁。
			releaseRuleBans(id)
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
		// 规则删除即释放该规则产生的全部封禁(记录保留, 集合与规则由看门狗对齐)。
		releaseRuleBans(id)
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

func handleGeoCountries(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	// countries/sar 保持老形状(字符串, 旧面板兼容); countriesBilingual/
	// sarBilingual 为新形状(代码+中英名, 新对话框用, 优先于老字段)。
	// 表里没有的库原字符串(如 v6 新增国家)原样回退, 不丢选项。
	names := geoCountries()
	bil := []CountryEntry{}
	for _, s := range names {
		if e, ok := countryEntryForName(s); ok {
			bil = append(bil, e)
		} else {
			bil = append(bil, CountryEntry{Zh: s, En: s})
		}
	}
	writeJSON(w, 200, map[string]any{
		"countries": names, "sar": []string{"香港", "澳门", "台湾"},
		"countriesBilingual": bil, "sarBilingual": countrySARTable,
	})
}

func handleGeoCities(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	d := geoCities()
	writeJSON(w, 200, map[string]any{"provinces": d.Provinces, "cities": d.Cities})
}
