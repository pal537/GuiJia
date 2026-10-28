package main

// HTTP API: 总览 / 实时连接 / 端口管理 / 事件 / 黑名单 / 设置 / 数据清理

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func handleOverview(w http.ResponseWriter, r *http.Request) {
	ds := todayStats()
	statsMu.Lock()
	snap := map[string]any{
		"sshLogins": ds.SSHLogins, "sshFails": ds.SSHFails,
		"uiLogins": ds.UILogins, "bans": ds.Bans, "newSources": len(ds.Sources),
	}
	statsMu.Unlock()
	rescueMu.Lock()
	rescueActive, rescueUntil := rescueSt.KillActive, rescueSt.KillUntil
	rescueMu.Unlock()
	connMu.RLock()
	n := len(liveConns)
	connMu.RUnlock()
	// 监听端口数 = 当前本机监听的 TCP+UDP 端口数(去重); 监控清单概念已废弃,
	// 统计卡不再用清单覆盖数。starredPorts 仅保留兼容(前端不再用)。
	_, starred := coverCounts()
	watched := len(ssListeners())
	var v6Size int64
	var v6Date int64
	if fi, err := os.Stat(geoV6Path); err == nil {
		v6Size = fi.Size()
		v6Date = fi.ModTime().Unix()
	}
	var v4Size int64
	var v4Date int64
	v4FromFile := false
	if fi, err := os.Stat(geoV4Path); err == nil {
		v4Size = fi.Size()
		v4Date = fi.ModTime().Unix()
		v4FromFile = true
	} else {
		v4Size = int64(len(embeddedXDBv4))
	}
	closed := []map[string]any{}
	for _, pb := range activePortBans() {
		closed = append(closed, map[string]any{"port": pb.Port, "until": pb.Until})
	}
	traffic := []map[string]any{}
	for _, t := range trafficSnapshot() {
		traffic = append(traffic, map[string]any{
			"name": t.Name, "addr": t.Addr, "rxBps": t.RxBps, "txBps": t.TxBps,
			"rxTotal": t.RxTot, "txTotal": t.TxTot,
		})
	}
	// 黑名单计数透明：生效中（activeBans 已归一化过期状态）之外，
	// 同时给出全部记录数与解封/过期 breakdown，前端不再只看到生效数。
	_, bansReleased, bansExpired, bansTotal := banCounts()
	writeJSON(w, 200, map[string]any{
		"traffic":  traffic,
		"connsNow": n, "watchedPorts": watched, "starredPorts": starred,
		"activeBans": len(activeBans()), "bansTotal": bansTotal, "bansReleased": bansReleased, "bansExpired": bansExpired,
		"closedPorts": closed, "fwLinkOk": fwLinkOK, "pgLinkOk": pgLinkOK, "dryBan": dryBan,
		"nftTimeoutBackstop": setSupportsTimeout(setV4) && setSupportsTimeout(setV6),
		"rescueActive":       rescueActive, "rescueUntil": rescueUntil,
		"honeypotBansToday": ds.HoneypotBans,
		"geoV6":             geoV6Loaded(), "geoV6Downloading": atomic.LoadInt32(&geoDLRun) == 1,
		"geoV6Size": v6Size, "geoV6Date": v6Date,
		"geoV4Size": v4Size, "geoV4Date": v4Date, "geoV4FromFile": v4FromFile,
		"today": snap, "uptimeSec": int(time.Since(startedAt).Seconds()),
	})
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, _ := effPorts() // 与采集同口径: 清单 ∪ 监听, 未加清单的服务也带名称/类型展示
	connMu.RLock()
	out := []map[string]any{}
	for _, c := range liveConns {
		name, star, kind := "", false, "other"
		if pw := ws[c.DstPort]; pw != nil {
			name, star, kind = pw.Name, pw.Star, pw.Kind
		}
		g := geoLookup(c.SrcIP)
		proto := c.Proto
		if proto == "" {
			proto = "tcp"
		}
		cumRx, cumTx := ledgerCum(c.SrcIP + "|" + itoa(c.DstPort) + "|" + proto)
		out = append(out, map[string]any{
			"ip": c.SrcIP, "sport": c.SrcPort, "port": c.DstPort, "portName": name,
			"star": star, "fw": fwCoversPort(c.DstPort, proto), "kind": kind, "proc": c.Proc, "proto": proto, "since": c.Since,
			"geo": g.Text, "private": g.Private, "banned": isBannedFor(c.SrcIP, c.DstPort),
			"trusted": isTrusted(c.SrcIP),
			"rx":      c.Rx, "tx": c.Tx, "rxBps": c.RxBps, "txBps": c.TxBps, "hasBytes": c.HasBytes,
			"cumRx": cumRx, "cumTx": cumTx, // 账本累计(历次连接总和), 悬停显示
		})
	}
	connMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i]["port"] != out[j]["port"] {
			return out[i]["port"].(int) < out[j]["port"].(int)
		}
		return out[i]["since"].(int64) < out[j]["since"].(int64)
	})
	writeJSON(w, 200, out)
}

func handlePorts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		mu.Lock()
		defer mu.Unlock()
		lst := ssListeners()
		out := []map[string]any{}
		for _, p := range ports {
			_, listening := lst[p.Port]
			var closedUntil int64
			if pb := portBanOf(p.Port); pb != nil {
				closedUntil = pb.Until
			}
			out = append(out, map[string]any{
				"port": p.Port, "name": p.Name, "star": p.Star, "kind": p.Kind,
				"source": p.Source, "listening": listening, "closedUntil": closedUntil,
			})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["port"].(int) < out[j]["port"].(int) })
		rout := []map[string]any{}
		for _, g := range portRanges {
			rout = append(rout, map[string]any{
				"from": g.From, "to": g.To, "count": g.To - g.From + 1,
				"name": g.Name, "star": g.Star, "kind": g.Kind, "source": g.Source,
			})
		}
		sort.Slice(rout, func(i, j int) bool { return rout[i]["from"].(int) < rout[j]["from"].(int) })
		writeJSON(w, 200, map[string]any{"ports": out, "ranges": rout})
	case "POST":
		var in struct {
			Spec    string `json:"spec"` // 新: 单个/范围/逗号组合(第 7 项)
			Port    int    `json:"port"` // 旧: 单个(兼容老前端)
			Name    string `json:"name"`
			Star    bool   `json:"star"`
			Kind    string `json:"kind"`
			Confirm bool   `json:"confirm"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		var segs []rangeSeg
		if strings.TrimSpace(in.Spec) != "" {
			var err error
			segs, err = parsePortSpec(in.Spec)
			if err != nil {
				errJSON(w, 400, err.Error())
				return
			}
		} else if in.Port >= 1 && in.Port <= 65535 {
			segs = []rangeSeg{{in.Port, in.Port}}
		} else {
			errJSON(w, 400, "端口无效")
			return
		}
		mu.Lock()
		defer mu.Unlock()
		plan := planRangeAdd(segs, in.Star, strings.TrimSpace(in.Name), normKind(in.Kind))
		if len(plan.ToAdd) == 0 {
			// 全部被覆盖: 按原因给明确提示(星标 > 范围 > 单个)
			for _, s := range plan.Skipped {
				if strings.Contains(s.Reason, "星标") {
					errJSON(w, 409, "该端口已星标")
					return
				}
			}
			if len(segs) == 1 && segs[0].from == segs[0].to {
				if g := rangeOf(segs[0].from); g != nil {
					errJSON(w, 409, fmt.Sprintf("该端口已包含在范围 %d-%d 中", g.From, g.To))
					return
				}
			}
			errJSON(w, 409, "该端口已在监控清单")
			return
		}
		// 蜜罐互斥: 拟新增的任一段与已启用蜜罐端口重叠即拒绝
		honeypotMu.Lock()
		hpPorts := append([]int{}, honeypotCfg.Ports...)
		hpEnabled := honeypotCfg.Enabled
		honeypotMu.Unlock()
		if hpEnabled {
			for _, t := range plan.ToAdd {
				for _, hp := range hpPorts {
					if hp >= t.From && hp <= t.To {
						errJSON(w, 409, fmt.Sprintf("端口 %d 是已启用的蜜罐端口, 监控与蜜罐互斥", hp))
						return
					}
				}
			}
		}
		if plan.NeedsPreview && !in.Confirm {
			writeJSON(w, 200, map[string]any{"needConfirm": true, "plan": plan})
			return
		}
		applyRangeAddPlan(plan)
		// 删过的忽略标记里若有本次新增的端口, 清掉(用户亲手加回来)
		for _, t := range plan.ToAdd {
			for p := t.From; p <= t.To; p++ {
				delete(ignoredPorts, p)
			}
		}
		savePorts()
		writeJSON(w, 200, map[string]any{"ok": true, "added": plan.ToAdd, "cut": plan.Cut, "excludedSelf": plan.ExcludedSelf})
	case "DELETE":
		// 删范围条目(整体删除): body {from, to}
		var in struct {
			From int `json:"from"`
			To   int `json:"to"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for i, g := range portRanges {
			if g.From == in.From && g.To == in.To {
				ignoredRanges = append(ignoredRanges, *g)
				portRanges = append(portRanges[:i], portRanges[i+1:]...)
				savePorts()
				writeJSON(w, 200, map[string]bool{"ok": true})
				return
			}
		}
		errJSON(w, 404, "未找到该范围")
	default:
		http.Error(w, "method", 405)
	}
}

// rangeOf 返回覆盖某端口的范围条目(调用方须持有 mu)。
func rangeOf(port int) *PortRange {
	idx := portIndexPtr.Load()
	if idx == nil || port < 1 || port > 65535 || idx.rangeIdx[port] == 0 {
		return nil
	}
	if i := int(idx.rangeIdx[port]) - 1; i < len(portRanges) {
		return portRanges[i]
	}
	return nil
}

// handleRangeStar 范围星标开关(第 7 项): 星标与普通互斥由不变量保证,
// 翻成星标时若含自身端口则切掉自身端口并提示。
func handleRangeStar(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	var in struct {
		From int  `json:"from"`
		To   int  `json:"to"`
		Star bool `json:"star"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for i, g := range portRanges {
		if g.From != in.From || g.To != in.To {
			continue
		}
		notice := ""
		if in.Star && !g.Star {
			// 切掉自身端口(18793 与运行端口)
			var self []rangeSeg
			for _, sp := range []int{18793, appPort()} {
				if sp >= g.From && sp <= g.To {
					self = append(self, rangeSeg{sp, sp})
				}
			}
			if len(self) > 0 {
				rest := subtractSeg(g.From, g.To, self)
				var repl []*PortRange
				for _, m := range rest {
					repl = append(repl, &PortRange{From: m.from, To: m.to, Name: g.Name, Star: true, Kind: g.Kind, Source: g.Source})
				}
				portRanges = append(portRanges[:i], append(repl, portRanges[i+1:]...)...)
				var names []string
				for _, s := range self {
					names = append(names, itoa(s.from))
				}
				notice = "已自动排除自身端口 " + strings.Join(names, "、")
				savePorts()
				writeJSON(w, 200, map[string]any{"ok": true, "notice": notice})
				return
			}
		}
		g.Star = in.Star
		savePorts()
		writeJSON(w, 200, map[string]any{"ok": true, "notice": notice})
		return
	}
	errJSON(w, 404, "未找到该范围")
}

func handlePortItem(w http.ResponseWriter, r *http.Request) {
	seg := strings.TrimPrefix(r.URL.Path, "/api/ports/")
	port, err := strconv.Atoi(seg)
	if err != nil {
		errJSON(w, 400, "bad port")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	p := findPort(port)
	if p == nil {
		// 范围里的端口不归单个接口管: 指明所属范围, 整体管理
		if g := rangeOf(port); g != nil {
			errJSON(w, 404, fmt.Sprintf("该端口属于范围 %d-%d, 范围需整体管理", g.From, g.To))
			return
		}
		errJSON(w, 404, "不在监控清单")
		return
	}
	switch r.Method {
	case "PUT":
		var in struct {
			Name *string `json:"name"`
			Star *bool   `json:"star"`
			Kind *string `json:"kind"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "bad json")
			return
		}
		if in.Name != nil {
			p.Name = strings.TrimSpace(*in.Name)
		}
		if in.Star != nil {
			p.Star = *in.Star
		}
		if in.Kind != nil {
			p.Kind = normKind(*in.Kind)
		}
		// 用户亲手编辑过的条目转为 manual 来源, 防火墙同步不再覆盖/移除
		if p.Source == "firewall" {
			p.Source = "manual"
		}
		savePorts()
		writeJSON(w, 200, p)
	case "DELETE":
		for i, x := range ports {
			if x.Port == port {
				ports = append(ports[:i], ports[i+1:]...)
				break
			}
		}
		ignoredPorts[port] = true // 记住: 同步/扫描不再自动导回
		savePorts()
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		errJSON(w, 405, "method")
	}
}

func handlePortScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		items := scanListeners()
		out := []map[string]any{}
		for _, it := range items {
			out = append(out, map[string]any{"port": it.Port, "proc": it.Proc, "watched": it.Watched, "ignored": it.Ignored})
		}
		writeJSON(w, 200, out)
	case "POST":
		var in struct {
			Items []struct {
				Port int    `json:"port"`
				Name string `json:"name"`
			} `json:"items"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "bad json")
			return
		}
		mu.Lock()
		defer mu.Unlock()
		added := 0
		for _, it := range in.Items {
			if it.Port < 1 || it.Port > 65535 || findPort(it.Port) != nil {
				continue
			}
			ports = append(ports, &PortWatch{Port: it.Port, Proto: "tcp", Name: strings.TrimSpace(it.Name), Source: "scan"})
			delete(ignoredPorts, it.Port)
			added++
		}
		savePorts()
		writeJSON(w, 200, map[string]int{"added": added})
	default:
		errJSON(w, 405, "method")
	}
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	evs, total := listEvents(r.URL.Query().Get("type"), r.URL.Query().Get("q"), limit, offset)
	out := []map[string]any{}
	for _, ev := range evs {
		out = append(out, map[string]any{
			"id": ev.ID, "ts": ev.Ts, "type": ev.Type, "ip": ev.IP,
			"port": ev.Port, "detail": ev.Detail, "geo": ev.Geo,
		})
	}
	writeJSON(w, 200, map[string]any{
		"items": out, "total": total, "hasMore": offset+len(out) < total,
	})
}

func handleBans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		out := []map[string]any{}
		for _, b := range allBans() {
			out = append(out, map[string]any{
				"ip": b.IP, "until": b.Until, "reason": b.Reason,
				"source": b.Source, "createdAt": b.CreatedAt, "geo": geoLookup(b.IP).Text,
				"status": b.Status, "releasedAt": b.ReleasedAt, "ports": b.Ports, "scopes": b.Scopes,
			})
		}
		writeJSON(w, 200, out)
	case "POST":
		var in struct {
			IP     string `json:"ip"`
			Hours  int    `json:"hours"`
			Reason string `json:"reason"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.IP == "" {
			errJSON(w, 400, "参数无效")
			return
		}
		if in.Reason == "" {
			in.Reason = "手动拉黑"
		}
		b, err := applyBan(in.IP, in.Reason, "manual", in.Hours)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		pushEvent(Event{Type: "ban", IP: in.IP, Detail: "手动拉黑: " + in.Reason})
		writeJSON(w, 200, b)
	default:
		errJSON(w, 405, "method")
	}
}

func handleBanItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		errJSON(w, 405, "method")
		return
	}
	ip := strings.TrimPrefix(r.URL.Path, "/api/bans/")
	if releaseBan(ip) {
		// 解封单独成类型: 旧代码复用 ban 类型, 导致解封也被算进「今日拉黑」
		pushEvent(Event{Type: "unban", IP: ip, Detail: "已解除拉黑"})
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	errJSON(w, 404, "该 IP 不在黑名单")
}

// 洪峰防护: 手动恢复被临时关闭的端口
func handlePortBanItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		errJSON(w, 405, "method")
		return
	}
	port, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/portbans/"))
	if err != nil {
		errJSON(w, 400, "bad port")
		return
	}
	if reopenPort(port) {
		pushEvent(Event{Type: "port_flood", Port: port, Detail: "端口 " + itoa(port) + " 已手动恢复开放"})
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	errJSON(w, 404, "该端口未处于关闭状态")
}

// tgTokenMask: Bot Token 的星号占位(前后端约定)。前端原样回传即表示未改动。
const tgTokenMask = "********"

// normalizeServerName: 服务器名归一化——去首尾空格, 超 32 字符按 rune 截断(中文不截半)。
func normalizeServerName(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 32 {
		return string(r[:32])
	}
	return s
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		mu.Lock()
		s := settings
		mu.Unlock()
		b, _ := json.Marshal(s)
		var m map[string]any
		json.Unmarshal(b, &m)
		delete(m, "rescuePassHash") // 超级密码哈希永不外泄(只能由专用接口改)
		// Bot Token 永不明文外泄: 已设置时只返回星号占位, 前端原样回传即保留旧值
		if tok, _ := m["tgBotToken"].(string); tok != "" {
			m["tgBotToken"] = tgTokenMask
		}
		m["panelPort"] = appPort() // 面板实际监听端口(设置页"面板端口"输入框默认值)
		cur, err := acctRead()
		m["acctOn"] = err == nil && cur == "1" // 内核字节计数当前是否开着
		m["acctByApp"] = loadAcctState().WeEnabled
		// 蜜罐命中报警开关的唯一事实来源是蜜罐配置(蜜罐页已不再改它):
		// 设置页只镜像展示, 保存时再写回蜜罐配置。
		honeypotMu.Lock()
		m["alertHoneypotHit"] = honeypotCfg.AlertEnabled
		honeypotMu.Unlock()
		// 防护同步标记: 节点视图据此把已同步卡片换成“已与主服务器同步”。
		fl := protSyncSnapshot()
		m["protectionSynced"] = map[string]any{
			"flood": fl.Flood, "autoban": fl.Autoban, "scan": fl.Scan, "intel": fl.Intel,
		}
		writeJSON(w, 200, m)
	case "PUT":
		body, _ := io.ReadAll(r.Body)
		var raw map[string]any
		if json.Unmarshal(body, &raw) != nil {
			errJSON(w, 400, "bad json")
			return
		}
		// 按字段合并: 先取当前设置, 再用请求体覆盖已提交的键;
		// UI 不再提交的键(如面板 SSL 四项)保持原值, 绝不清零。
		mu.Lock()
		in := settings
		mu.Unlock()
		if json.Unmarshal(body, &in) != nil {
			errJSON(w, 400, "bad json")
			return
		}
		// 报警项目里的蜜罐命中报警: 写回蜜罐配置(老前端不传此键时不动)。
		{
			if v, ok := raw["alertHoneypotHit"].(bool); ok {
				honeypotMu.Lock()
				if honeypotCfg.AlertEnabled != v {
					honeypotCfg.AlertEnabled = v
					saveHoneypot()
				}
				honeypotMu.Unlock()
			}
		}
		if in.BruteWindowMin < 1 {
			in.BruteWindowMin = 10
		}
		if in.BruteThreshold < 2 {
			in.BruteThreshold = 5
		}
		if in.FloodWindowMin < 1 || in.FloodWindowMin > 60 {
			in.FloodWindowMin = 1
		}
		if in.FloodDistinctIPs < 2 || in.FloodDistinctIPs > 100000 {
			in.FloodDistinctIPs = 30
		}
		if in.FloodCloseMin < 1 || in.FloodCloseMin > 1440 {
			in.FloodCloseMin = 60
		}
		// 手动洪峰端口: 提交了非空文本时必须能解析, 否则 400 拒收(不写盘);
		// 空文本合法 = 不对任何端口触发。
		if _, ok := raw["floodPorts"]; ok {
			if strings.TrimSpace(in.FloodPorts) != "" {
				if _, err := parsePortRanges(in.FloodPorts); err != nil {
					errJSON(w, 400, "洪峰端口: "+err.Error())
					return
				}
			}
		}
		if in.LogKeepDays < 1 || in.LogKeepDays > 365 {
			in.LogKeepDays = 30
		}
		if in.NewSrcKeepDays < 0 || in.NewSrcKeepDays > 365 {
			in.NewSrcKeepDays = 7
		}
		if in.LedgerKeepDays < 0 || in.LedgerKeepDays > 3650 {
			in.LedgerKeepDays = 7
		}
		if _, err := time.Parse("15:04", in.ReportTime); err != nil {
			in.ReportTime = "09:00"
		}
		clean := []string{}
		for _, t := range in.TrustedIPs {
			if t = strings.TrimSpace(t); t != "" {
				clean = append(clean, t)
			}
		}
		in.TrustedIPs = clean
		// 服务器名: 去首尾空格, 超 32 字符截断(按 rune, 中文不截半), 绝不报错崩溃。
		in.ServerName = normalizeServerName(in.ServerName)
		// 服务器指纹: PUT 永不改动它(前端回传旧值、漏传、清空都一样);
		// 旧值空时才用请求值, 仍空则生成(指纹是回调防串台的唯一依据, 不能被写空)。
		if settings.ServerID == "" {
			if in.ServerID == "" {
				in.ServerID = newServerID()
			}
		} else {
			in.ServerID = settings.ServerID
		}
		// 面板 SSL 只在请求确实提交了 SSL 键时才全量校验;
		// 未提交时只钳制封禁次数, 既不碰 SSL 旧值, 也不因旧证书过期卡住无关保存。
		sslTouched := false
		for _, k := range []string{"panelSslMode", "panelSslCert", "panelSslPort", "panelDomain"} {
			if _, ok := raw[k]; ok {
				sslTouched = true
				break
			}
		}
		if sslTouched {
			if err := validatePanelSettings(&in); err != nil {
				errJSON(w, 400, err.Error())
				return
			}
		} else {
			if in.PanelBanThreshold == 0 {
				in.PanelBanThreshold = 5
			} else if in.PanelBanThreshold < 1 {
				in.PanelBanThreshold = 1
			} else if in.PanelBanThreshold > 100 {
				in.PanelBanThreshold = 100
			}
		}
		mu.Lock()
		in.RescuePassHash = settings.RescuePassHash // 哈希只能由专用接口改, 通用设置接口不得覆盖
		if in.TGBotToken == tgTokenMask {
			in.TGBotToken = settings.TGBotToken // 星号占位 = 未改动, 保留旧 Token
		}
		// 防护同步护栏: 被控节点上已同步的项, 本地通用保存不得改动其配置值
		// (前端已隐藏这些卡片, 这里是防旧页面/直接调接口的第二道; 未改动的值
		// 原样回传不触发, 不影响其他项保存)。
		// 注意: 此处已持有 mu, 绝不能调 effectiveRunMode()(它会再锁 mu 而死锁);
		// 只需判 RunMode=="managed" 本身。
		if settings.RunMode == "managed" {
			fl := protSyncSnapshot()
			violated := ""
			if fl.Flood && (settings.FloodEnabled != in.FloodEnabled || settings.FloodWindowMin != in.FloodWindowMin || settings.FloodDistinctIPs != in.FloodDistinctIPs || settings.FloodCloseMin != in.FloodCloseMin || settings.FloodPorts != in.FloodPorts) {
				violated = "端口洪峰防护"
			} else if fl.Autoban && (settings.AutoBanEnabled != in.AutoBanEnabled || settings.BruteWindowMin != in.BruteWindowMin || settings.BruteThreshold != in.BruteThreshold || settings.BruteBanHours != in.BruteBanHours) {
				violated = "爆破自动拉黑"
			} else if fl.Scan && (settings.ScanEnabled != in.ScanEnabled || settings.ScanAutoBan != in.ScanAutoBan || settings.ScanWindowMin != in.ScanWindowMin || settings.ScanDistinctPorts != in.ScanDistinctPorts) {
				violated = "扫描识别"
			}
			if violated != "" {
				mu.Unlock()
				errJSON(w, 403, violated+"已与主服务器同步，本地不可改")
				return
			}
		}
		panelUnchanged := settings.PanelBanThreshold == in.PanelBanThreshold &&
			settings.PanelSSLMode == in.PanelSSLMode &&
			settings.PanelSSLCert == in.PanelSSLCert &&
			settings.PanelSSLPort == in.PanelSSLPort &&
			settings.PanelDomain == in.PanelDomain
		oldTGEnabled, oldTGToken, oldTGChat := settings.TGEnabled, settings.TGBotToken, settings.TGChatID
		settings = in
		mu.Unlock()
		saveSettings()
		syncTrafficAcct() // 流量统计开关改了立即对齐内核状态
		syncTrustedSets() // 信任名单改了立即进内核集合
		// TG 配置变化且现已配置时注册一次命令菜单(绑定保存即生效, 失败只记日志)。
		if (oldTGEnabled != in.TGEnabled || oldTGToken != in.TGBotToken || oldTGChat != in.TGChatID) && tgConfigured() {
			go tgRegisterCommands()
		}
		if !panelUnchanged {
			// 异步重建: 不能在当前请求的 handler 里同步 Shutdown(会等自身连接空闲而死锁)。
			go rebuildPanelServer()
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		errJSON(w, 405, "method")
	}
}

func handleDataClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Scope       string `json:"scope"`
		Confirm     string `json:"confirm"`
		ReleaseBans bool   `json:"releaseBans"` // 是否释放全部黑名单: 必须由前端单独询问后回传
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Confirm != "YES" {
		errJSON(w, 400, "需要二次确认")
		return
	}
	switch in.Scope {
	case "events":
		clearEvents()
		statsMu.Lock()
		statsMap = map[string]*DayStats{}
		statsMu.Unlock()
		saveStats()
	case "bans":
		// 黑名单记录唯一的删除路径: 必须明确选择释放全部黑名单
		if !in.ReleaseBans {
			errJSON(w, 400, "清空黑名单需明确选择「释放全部黑名单」")
			return
		}
		wipeBans()
	case "ledger":
		clearLedger()
	case "all":
		clearEvents()
		statsMu.Lock()
		statsMap = map[string]*DayStats{}
		statsMu.Unlock()
		saveStats()
		clearLedger()
		// 未明确选择释放时, 黑名单(记录+封禁)完全不碰
		if in.ReleaseBans {
			wipeBans()
		}
	default:
		errJSON(w, 400, "scope 无效")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func normKind(k string) string {
	switch k {
	case "ssh", "ui", "smb", "ftp", "webdav", "nfs", "dlna", "media", "db", "download":
		return k
	}
	return "other"
}

// 一键信任: 把来源 IP 加入信任名单(连接列表/事件页调用)
func handleTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		IP string `json:"ip"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "IP 无效")
		return
	}
	already, err := trustIP(in.IP)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "already": already})
}

// ---------- 急救(第 2 项) ----------

// 设置/更换急救超级密码(网页端, 信任通道)。空密码 = 清除密码保护,
// 之后 TG 破坏性急救动作会被拒绝(需先设密码)。
// 被控节点不设本地密码: 急救统一走主服务器(主服务器密码管全部服务器),
// 面板代理到节点调本接口一律拒绝, 本地密码栏在节点视图里也不显示。
func handleRescuePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if effectiveRunMode() == "managed" {
		errJSON(w, 403, "被控节点不设本地超级密码，急救统一走主服务器")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "bad json")
		return
	}
	pw := strings.TrimSpace(in.Password)
	mu.Lock()
	defer mu.Unlock()
	if pw == "" {
		settings.RescuePassHash = ""
	} else {
		if len([]rune(pw)) < rescuePassMinLen {
			errJSON(w, 400, "超级密码至少 6 位")
			return
		}
		h, err := hashRescuePassword(pw)
		if err != nil {
			errJSON(w, 500, "生成哈希失败: "+err.Error())
			return
		}
		settings.RescuePassHash = h
	}
	saveSettings()
	// 网页端改密是信任通道: 顺带清除 TG 端的锁定与错误计数
	rescueMu.Lock()
	rescueSt.FailCount = 0
	rescueSt.LockedUntil = 0
	saveRescue()
	rescueMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "hasPassword": settings.RescuePassHash != ""})
}

func handleRescueStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	mu.Lock()
	hasPw := settings.RescuePassHash != ""
	mu.Unlock()
	rescueMu.Lock()
	st := rescueSt
	rescueMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"hasPassword": hasPw, "killActive": st.KillActive, "killUntil": st.KillUntil,
		"lockedUntil": st.LockedUntil,
	})
}

// 网页端手动恢复防护(急救模式下才有效)。
func handleRescueRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if !rescueRestore() {
		errJSON(w, 400, "当前未处于急救模式")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func handleTGTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Token  string `json:"tgBotToken"`
		ChatID string `json:"tgChatId"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	if in.Token == tgTokenMask {
		in.Token = "" // 星号占位 = 用已保存的 Token(tgTestSend 为空时回落到已保存值)
	}
	if msg := tgTestSend(strings.TrimSpace(in.Token), strings.TrimSpace(in.ChatID)); msg != "" {
		if msg == tgRateMsg {
			errJSON(w, 429, msg)
			return
		}
		errJSON(w, 400, msg)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func handleGeoLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		errJSON(w, 400, "need ip")
		return
	}
	g := geoLookup(ip)
	writeJSON(w, 200, map[string]any{"ip": ip, "geo": g.Text, "country": g.Country, "province": g.Province, "city": g.City, "isp": g.ISP, "private": g.Private})
}

func handleGeoDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	force := r.URL.Query().Get("force") == "1"
	if geoV6Loaded() && !force {
		writeJSON(w, 200, map[string]bool{"loaded": true})
		return
	}
	go downloadGeoV6(force)
	writeJSON(w, 200, map[string]bool{"started": true})
}

const geoV6URL = "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb"

// 检查更新: HEAD 上游 v6 库, 与本地文件大小/日期比对
// handleGeoCheck 手动检查更新(POST ?v=4|6, 缺省 6): 后台下载比对, 不阻塞请求。
// 结果分两种, 文案按 PAPA 定稿: 已是最新 -> "当前版本已是最新";
// 下载并转正后 -> "已经更新到最新版本"。
func handleGeoCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	v := r.URL.Query().Get("v")
	if v != "4" {
		v = "6"
	}
	geoCheckMu.Lock()
	running := geoCheckRun[v]
	geoCheckMu.Unlock()
	if running {
		writeJSON(w, 200, map[string]bool{"running": true})
		return
	}
	go geoCheckUpdate(v)
	writeJSON(w, 200, map[string]bool{"started": true})
}

func handleGeoCheckStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	v := r.URL.Query().Get("v")
	if v != "4" {
		v = "6"
	}
	geoCheckMu.Lock()
	running := geoCheckRun[v]
	res := geoCheckRes[v]
	geoCheckMu.Unlock()
	var size, date int64
	path := geoV6Path
	if v == "4" {
		path = geoV4Path
	}
	if fi, err := os.Stat(path); err == nil {
		size, date = fi.Size(), fi.ModTime().Unix()
	} else if v == "4" {
		size = int64(len(embeddedXDBv4))
	}
	writeJSON(w, 200, map[string]any{
		"running": running, "result": res, "size": size, "date": date,
		"loaded": v == "4" || geoV6Loaded(),
	})
}
