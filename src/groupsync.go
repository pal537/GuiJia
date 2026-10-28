package main

// 群控设置: 共享黑名单 / 共享白名单(第 11 项)。
// 主服务器名单为源, 经命令通道推向各节点; 按 IP 去重、已有跳过;
// 同步条目标记 shared, 只动 shared 条目, 本机条目绝不动。
// 黑名单只做新增与状态同步(主服务器解封则节点条目变解封态, 绝不硬删记录,
// 黑名单“记录永不丢失”硬规矩同样适用); 白名单按 shared 标记收敛。
// 配置存 groupsync.json(0600, 不进 settings.json, 免得通用设置保存覆盖)。
// 只要开启, 新加入节点批准后立即自动同步一次; 另有后台 ticker 按间隔同步。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type groupSyncCfg struct {
	Enabled     bool   `json:"enabled"`
	IntervalMin int    `json:"intervalMin"` // 5 | 10 | 30 | 60, 默认 10
	LastSyncAt  int64  `json:"lastSyncAt"`
	LastStatus  string `json:"lastStatus"` // ok | partial | failed | ""
	LastDetail  string `json:"lastDetail"`
}

type groupSyncFile struct {
	Blacklist groupSyncCfg `json:"blacklist"`
	Whitelist groupSyncCfg `json:"whitelist"`
}

var (
	gsMu     sync.Mutex
	gsCfg    groupSyncFile
	gsTicker bool
)

func groupSyncFilePath() string {
	if dataDir == "" {
		return "groupsync.json"
	}
	return filepath.Join(dataDir, "groupsync.json")
}

func loadGroupSync() {
	gsMu.Lock()
	defer gsMu.Unlock()
	gsCfg = groupSyncFile{
		Blacklist: groupSyncCfg{IntervalMin: 10},
		Whitelist: groupSyncCfg{IntervalMin: 10},
	}
	if b, err := os.ReadFile(groupSyncFilePath()); err == nil {
		var f groupSyncFile
		if json.Unmarshal(b, &f) == nil {
			if f.Blacklist.IntervalMin != 0 {
				gsCfg.Blacklist = f.Blacklist
			} else {
				gsCfg.Blacklist.Enabled = f.Blacklist.Enabled
				gsCfg.Blacklist.LastSyncAt = f.Blacklist.LastSyncAt
				gsCfg.Blacklist.LastStatus = f.Blacklist.LastStatus
				gsCfg.Blacklist.LastDetail = f.Blacklist.LastDetail
			}
			if f.Whitelist.IntervalMin != 0 {
				gsCfg.Whitelist = f.Whitelist
			} else {
				gsCfg.Whitelist.Enabled = f.Whitelist.Enabled
				gsCfg.Whitelist.LastSyncAt = f.Whitelist.LastSyncAt
				gsCfg.Whitelist.LastStatus = f.Whitelist.LastStatus
				gsCfg.Whitelist.LastDetail = f.Whitelist.LastDetail
			}
		}
	}
	if gsCfg.Blacklist.IntervalMin <= 0 {
		gsCfg.Blacklist.IntervalMin = 10
	}
	if gsCfg.Whitelist.IntervalMin <= 0 {
		gsCfg.Whitelist.IntervalMin = 10
	}
}

func saveGroupSyncLocked() {
	b, _ := json.MarshalIndent(gsCfg, "", "  ")
	os.WriteFile(groupSyncFilePath(), b, 0600)
}

func groupSyncPublic() map[string]any {
	gsMu.Lock()
	defer gsMu.Unlock()
	return map[string]any{
		"blacklist": map[string]any{
			"enabled": gsCfg.Blacklist.Enabled, "intervalMin": gsCfg.Blacklist.IntervalMin,
			"lastSyncAt": gsCfg.Blacklist.LastSyncAt, "lastStatus": gsCfg.Blacklist.LastStatus,
			"lastDetail": gsCfg.Blacklist.LastDetail,
		},
		"whitelist": map[string]any{
			"enabled": gsCfg.Whitelist.Enabled, "intervalMin": gsCfg.Whitelist.IntervalMin,
			"lastSyncAt": gsCfg.Whitelist.LastSyncAt, "lastStatus": gsCfg.Whitelist.LastStatus,
			"lastDetail": gsCfg.Whitelist.LastDetail,
		},
	}
}

func handleGroupSyncSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, 200, groupSyncPublic())
	case "POST":
		var in struct {
			Group       string `json:"group"` // blacklist | whitelist
			Enabled     bool   `json:"enabled"`
			IntervalMin int    `json:"intervalMin"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			errJSON(w, 400, "请求无效")
			return
		}
		if in.Group != "blacklist" && in.Group != "whitelist" {
			errJSON(w, 400, "分组无效")
			return
		}
		switch in.IntervalMin {
		case 5, 10, 30, 60:
		default:
			errJSON(w, 400, "同步间隔只能是 5/10/30/60 分钟")
			return
		}
		gsMu.Lock()
		if in.Group == "blacklist" {
			gsCfg.Blacklist.Enabled, gsCfg.Blacklist.IntervalMin = in.Enabled, in.IntervalMin
		} else {
			gsCfg.Whitelist.Enabled, gsCfg.Whitelist.IntervalMin = in.Enabled, in.IntervalMin
		}
		saveGroupSyncLocked()
		startGroupSyncTickerLocked()
		gsMu.Unlock()
		// 保存后立即同步一次(已开启的组): 不等 ticker 最长 60 秒后的第一趟,
		// 用户点保存就能亲眼看到同步生效; 异步跑, 不阻塞保存返回。
		// 定时同步继续按新间隔走, 本次同步成功后上次时间推进, ticker 自动顺延。
		if in.Enabled {
			runGroupSyncAsync(in.Group)
		}
		writeJSON(w, 200, groupSyncPublic())
	default:
		errJSON(w, 405, "method")
	}
}

// groupSyncPayloadFor 构造推向节点的名单: 黑名单全量(状态同步用, 节点侧
// 只建 active 的、只改已有的 shared), 白名单为信任名单全量。
func groupSyncPayloadFor(group string) map[string]any {
	if group == "whitelist" {
		mu.Lock()
		list := append([]string{}, settings.TrustedIPs...)
		mu.Unlock()
		return map[string]any{"whitelist": list}
	}
	banMu.Lock()
	defer banMu.Unlock()
	entries := []map[string]any{}
	for _, b := range bans {
		if b == nil {
			continue
		}
		entries = append(entries, map[string]any{
			"ip": b.IP, "status": b.Status, "until": b.Until, "reason": b.Reason,
		})
	}
	return map[string]any{"blacklist": entries}
}

// syncGroupToNode 推一组名单给一台节点(经内部命令通道)。
// 返回 (成功与否, 详情): 节点离线/通道异常都算失败, 不抛错给调用方。
// 超时语义(第 2 项): 同步命令给 90 秒结果等待(大名单落内核可能超过默认
// 20 秒); 90 秒仍超时不直接判失败, 先读节点共享状态核实——已应用则报
// 成功, 未应用则利用幂等(按 IP 去重)安全重试一次、再核实一次, 仍未应用
// 才报失败。状态行只报核实后的结果, 不把“慢”报成“失败”。
func syncGroupToNode(group, fp string) (bool, string) {
	// whitelist 组只发白名单、blacklist 组只发黑名单(节点侧另一组留空即不动)。
	var body map[string]any
	if group == "whitelist" {
		body = map[string]any{"whitelist": groupSyncPayloadFor(group)["whitelist"]}
	} else {
		body = map[string]any{"blacklist": groupSyncPayloadFor(group)["blacklist"]}
	}
	bb, _ := json.Marshal(body)
	if ok, detail, needVerify := syncGroupAttempt(group, fp, bb); needVerify {
		if applied, _ := verifyGroupSyncApplied(group, fp, body); applied {
			return true, "已应用（超时后核实）"
		}
		if ok2, detail2, needVerify2 := syncGroupAttempt(group, fp, bb); needVerify2 {
			if applied, _ := verifyGroupSyncApplied(group, fp, body); applied {
				return true, "已应用（超时后核实）"
			}
			return false, "节点响应超时"
		} else if ok2 {
			return true, detail2
		} else {
			return false, detail2
		}
	} else if ok {
		return true, detail
	} else {
		return false, detail
	}
}

// syncResultWait 同步命令结果等待(默认 90 秒, 单测可调小模拟慢节点)。
var syncResultWait = 90 * time.Second

// verifyResultWait 核实读结果等待(默认 30 秒, 单测可调小)。
var verifyResultWait = 30 * time.Second

// syncGroupAttempt 发一次同步命令: 返回 (成功, 详情, 是否超时需核实)。
func syncGroupAttempt(group, fp string, bb []byte) (bool, string, bool) {
	status, respBody, errKind := hubCallNodeInternalTimeout(fp, "POST", "api/sync/apply-lists", bb, true, syncResultWait)
	if errKind != "" {
		if errKind == "timeout" {
			return false, "", true
		}
		return false, proxyErrMessage(fp, errKind), false
	}
	if status < 200 || status >= 300 {
		return false, fmt.Sprintf("节点返回 %d", status), false
	}
	var v struct {
		Blacklist map[string]int `json:"blacklist"`
		Whitelist map[string]int `json:"whitelist"`
	}
	_ = json.Unmarshal(respBody, &v)
	if group == "whitelist" {
		return true, fmt.Sprintf("新增 %d, 移除 %d, 跳过 %d", v.Whitelist["added"], v.Whitelist["removed"], v.Whitelist["skipped"]), false
	}
	return true, fmt.Sprintf("新增 %d, 更新 %d, 跳过 %d", v.Blacklist["added"], v.Blacklist["updated"], v.Blacklist["skipped"]), false
}

// sharedStateResp 节点共享状态快照(超时后核实读的返回体)。
type sharedStateResp struct {
	Blacklist []sharedStateBan `json:"blacklist"`
	Whitelist []string         `json:"whitelist"`
	// 核实黑名单时复算节点视角的 bannable 跳过用: 节点完整信任名单与 LAN 标志。
	Trust    []string `json:"trust"`
	TrustLAN bool     `json:"trustLan"`
}

// sharedStateBan 节点侧一条共享黑名单的生效状态(enforced=当前是否在内核生效)。
type sharedStateBan struct {
	IP       string `json:"ip"`
	Enforced bool   `json:"enforced"`
}

// verifyGroupSyncApplied 超时后核实: 读一次节点共享状态, 比对本次发送的组是否已收敛。
// 返回 (已应用, 核实失败原因): 核实读本身失败时原因非空(调用方直接报核实失败,
// 不把“不知道”说成“失败”); 核实读成功但未收敛时原因空(调用方可安全重试)。
// 黑名单收敛语义: 发 active 的须在节点生效, 发 released/expired 的须不在节点生效
// (节点对从未有过的 released/expired 不建记录, 缺席即等效于未生效)。
// 白名单收敛语义: 节点 shared 标记集合须与发送集合相等(节点侧按 shared 标记收敛)。
func verifyGroupSyncApplied(group, fp string, body map[string]any) (bool, string) {
	status, respBody, errKind := hubCallNodeInternalTimeout(fp, "GET", "api/sync/shared-state", nil, true, verifyResultWait)
	if errKind != "" || status < 200 || status >= 300 {
		return false, "节点响应超时（核实失败）"
	}
	var st sharedStateResp
	if json.Unmarshal(respBody, &st) != nil {
		return false, "节点响应超时（核实失败）"
	}
	return groupSyncVerifyState(group, body, st), ""
}

// groupSyncVerifyState 纯比对: 发送组是否已在节点共享状态里收敛(供单测与核实共用)。
func groupSyncVerifyState(group string, body map[string]any, st sharedStateResp) bool {
	if group == "whitelist" {
		want, _ := body["whitelist"].([]string)
		wantSet := map[string]bool{}
		for _, ip := range want {
			wantSet[ip] = true
		}
		if len(st.Whitelist) != len(wantSet) {
			return false
		}
		for _, ip := range st.Whitelist {
			if !wantSet[ip] {
				return false
			}
		}
		return true
	}
	entries, _ := body["blacklist"].([]map[string]any)
	nodeEnforced := map[string]bool{}
	for _, b := range st.Blacklist {
		nodeEnforced[b.IP] = b.Enforced
	}
	for _, e := range entries {
		ip, _ := e["ip"].(string)
		stt, _ := e["status"].(string)
		if ip == "" {
			continue
		}
		if stt == "active" {
			// 节点视角的合法跳过(内网/回环、节点本地信任、非法格式):
			// 应用侧会跳过这些条目, 核实同样跳过, 不算未应用。
			if nodeWouldSkipActive(ip, st) {
				continue
			}
			if !nodeEnforced[ip] {
				return false
			}
		} else if stt == "released" || stt == "expired" {
			if nodeEnforced[ip] {
				return false
			}
		}
		// 未知状态: 应用侧跳过, 核实同样跳过。
	}
	return true
}

// nodeWouldSkipActive 节点视角的 bannable 跳过: 与节点应用侧的预过滤一致
// (内网/回环不可拉黑、信任名单不可拉黑、非法格式跳过)。
func nodeWouldSkipActive(ip string, st sharedStateResp) bool {
	pip := net.ParseIP(strings.TrimSpace(ip))
	if pip == nil {
		return true
	}
	if isPrivateIP(pip) {
		return true
	}
	return ipInTrustList(ip, st.Trust, st.TrustLAN)
}

// ipInTrustList IP 是否在给定信任名单里(精确匹配或 CIDR 包含; trustLAN 时
// 四段标准私网范围同样算信任)。纯函数, 供核实与单测用。
func ipInTrustList(ip string, list []string, trustLAN bool) bool {
	if trustLAN && isStdPrivateIP(ip) {
		return true
	}
	for _, t := range list {
		if t == ip {
			return true
		}
		if strings.Contains(t, "/") {
			if _, n, err := net.ParseCIDR(t); err == nil {
				if pip := net.ParseIP(ip); pip != nil && n.Contains(pip) {
					return true
				}
			}
		}
	}
	return false
}

// syncGroupToAllOnline 推一组名单给全部在线节点, 返回 (成功数, 总数, 明细)。
func syncGroupToAllOnline(group string) (int, int, string) {
	hubMu.Lock()
	fps := []string{}
	names := map[string]string{}
	for _, s := range hubServers {
		if s != nil && hubNodeOnline(s) {
			fps = append(fps, s.Fingerprint)
			names[s.Fingerprint] = s.Name
		}
	}
	hubMu.Unlock()
	ok, details := 0, []string{}
	for _, fp := range fps {
		if good, d := syncGroupToNode(group, fp); good {
			ok++
			details = append(details, names[fp]+"："+d)
		} else {
			details = append(details, names[fp]+"：失败("+d+")")
		}
	}
	return ok, len(fps), strings.Join(details, "；")
}

// markGroupSyncResult 记一次同步结果(上次同步时间只在全成功时推进,
// 部分失败留待下次 ticker 补推, 不谎报成功)。
func markGroupSyncResult(group string, ok, total int, detail string) {
	gsMu.Lock()
	defer gsMu.Unlock()
	var c *groupSyncCfg
	if group == "blacklist" {
		c = &gsCfg.Blacklist
	} else {
		c = &gsCfg.Whitelist
	}
	if total > 0 && ok == total {
		c.LastSyncAt = time.Now().Unix()
		c.LastStatus = "ok"
	} else if ok > 0 {
		c.LastStatus = "partial"
	} else {
		c.LastStatus = "failed"
	}
	c.LastDetail = detail
	saveGroupSyncLocked()
}

// runGroupSyncOnce: 同步一组并记结果, 返回(成功数, 总数, 明细)。
// 黑名单先做并集合并再推, 白名单只推; 上次同步时间只在全成功时推进,
// 部分失败留待下次 ticker 补推, 不谎报成功。
func runGroupSyncOnce(group string) (int, int, string) {
	var ok, total int
	var detail string
	if group == "blacklist" {
		ok, total, detail = syncBlacklistToAllOnline()
	} else {
		ok, total, detail = syncGroupToAllOnline(group)
	}
	markGroupSyncResult(group, ok, total, detail)
	return ok, total, detail
}

// gsSyncing: 异步同步(保存触发、ticker)的执行权, 防同一组叠加跑。
// 立即同步按钮是用户显式动作, 保持同步直跑、不抢这把锁(与异步跑重叠时
// 两边都是幂等推送, 结果以后写者为准, 不 corrupt)。
var gsSyncing = map[string]bool{}

// tryBeginAsyncGroupSync: 抢到同一组的异步执行权才返回 true。
func tryBeginAsyncGroupSync(group string) bool {
	gsMu.Lock()
	defer gsMu.Unlock()
	if gsSyncing[group] {
		return false
	}
	gsSyncing[group] = true
	return true
}

func endAsyncGroupSync(group string) {
	gsMu.Lock()
	defer gsMu.Unlock()
	delete(gsSyncing, group)
}

// runGroupSyncAsync: 异步同步一组(保存触发与 ticker 共用); 已有同组同步在跑时直接跳过。
func runGroupSyncAsync(group string) {
	if !tryBeginAsyncGroupSync(group) {
		return
	}
	go func() {
		defer endAsyncGroupSync(group)
		runGroupSyncOnce(group)
	}()
}

func handleGroupSyncNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Group string `json:"group"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	if in.Group != "blacklist" && in.Group != "whitelist" {
		errJSON(w, 400, "分组无效")
		return
	}
	// 黑名单同步先做并集合并（从各在线节点吸入主服务器没有的 IP），
	// 再推给全部在线节点；白名单仍以主服务器为唯一源。
	ok, total, detail := runGroupSyncOnce(in.Group)
	writeJSON(w, 200, map[string]any{
		"ok": true, "synced": ok, "total": total, "detail": detail,
		"settings": groupSyncPublic(),
	})
}

// maybeAutoSyncNewNode 新节点批准后立即自动同步一次(已开启的组):
// 等节点上线(最长 2 分钟, 每 10 秒看一次), 上线即推, 不阻塞审批返回。
func maybeAutoSyncNewNode(fp, name string) {
	gsMu.Lock()
	bl, wl := gsCfg.Blacklist.Enabled, gsCfg.Whitelist.Enabled
	gsMu.Unlock()
	if !bl && !wl {
		return
	}
	go func() {
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			hubMu.Lock()
			s := findHubServer(fp)
			online := hubNodeOnline(s)
			hubMu.Unlock()
			if online {
				break
			}
			time.Sleep(10 * time.Second)
		}
		hubMu.Lock()
		s := findHubServer(fp)
		online := hubNodeOnline(s)
		hubMu.Unlock()
		if !online {
			return
		}
		// 批准自动同步：黑名单先合并（含新节点独有 IP）再推给全部在线节点，
		// 新节点一次拿到全网并集；白名单仍只推新节点（主服务器为唯一源）。
		if bl {
			ok, _, detail := syncBlacklistToAllOnline()
			if ok > 0 {
				gsMu.Lock()
				gsCfg.Blacklist.LastDetail = "新节点 " + name + " 已自动同步：" + detail
				saveGroupSyncLocked()
				gsMu.Unlock()
			}
		}
		if wl {
			if good, d := syncGroupToNode("whitelist", fp); good {
				gsMu.Lock()
				gsCfg.Whitelist.LastDetail = "新节点 " + name + " 已自动同步：" + d
				saveGroupSyncLocked()
				gsMu.Unlock()
			}
		}
	}()
}

// startGroupSyncTickerLocked 启动后台 ticker(调用方须持有 gsMu):
// 每 60 秒看一次, 到间隔的已开启组推全部在线节点。
func startGroupSyncTickerLocked() {
	if gsTicker {
		return
	}
	gsTicker = true
	go func() {
		for {
			time.Sleep(60 * time.Second)
			gsMu.Lock()
			bl, wl := gsCfg.Blacklist, gsCfg.Whitelist
			gsMu.Unlock()
			now := time.Now().Unix()
			for _, g := range []struct {
				name string
				cfg  groupSyncCfg
			}{{"blacklist", bl}, {"whitelist", wl}} {
				if !g.cfg.Enabled {
					continue
				}
				if g.cfg.LastSyncAt > 0 && now-g.cfg.LastSyncAt < int64(g.cfg.IntervalMin)*60 {
					continue
				}
				// 黑名单 ticker 同样先合并再推；白名单只推。异步跑, 同组已有同步在跑时跳过。
				if !tryBeginAsyncGroupSync(g.name) {
					continue
				}
				go func(name string) {
					defer endAsyncGroupSync(name)
					runGroupSyncOnce(name)
				}(g.name)
			}
		}
	}()
}

// startGroupSyncTicker 启动后台 ticker(供 main 启动时调用, 已开启才起)。
func startGroupSyncTicker() {
	gsMu.Lock()
	defer gsMu.Unlock()
	if gsCfg.Blacklist.Enabled || gsCfg.Whitelist.Enabled {
		startGroupSyncTickerLocked()
	}
}
