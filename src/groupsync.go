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
func syncGroupToNode(group, fp string) (bool, string) {
	// whitelist 组只发白名单、blacklist 组只发黑名单(节点侧另一组留空即不动)。
	var body map[string]any
	if group == "whitelist" {
		body = map[string]any{"whitelist": groupSyncPayloadFor(group)["whitelist"]}
	} else {
		body = map[string]any{"blacklist": groupSyncPayloadFor(group)["blacklist"]}
	}
	bb, _ := json.Marshal(body)
	status, respBody, errKind := hubCallNodeInternal(fp, "POST", "api/sync/apply-lists", bb, true)
	if errKind != "" {
		switch errKind {
		case "offline":
			return false, "节点离线"
		case "nochan":
			return false, "节点未建立命令通道"
		case "timeout":
			return false, "节点响应超时"
		default:
			return false, errKind
		}
	}
	if status < 200 || status >= 300 {
		return false, fmt.Sprintf("节点返回 %d", status)
	}
	var v struct {
		Blacklist map[string]int `json:"blacklist"`
		Whitelist map[string]int `json:"whitelist"`
	}
	_ = json.Unmarshal(respBody, &v)
	if group == "whitelist" {
		return true, fmt.Sprintf("新增 %d, 移除 %d, 跳过 %d", v.Whitelist["added"], v.Whitelist["removed"], v.Whitelist["skipped"])
	}
	return true, fmt.Sprintf("新增 %d, 更新 %d, 跳过 %d", v.Blacklist["added"], v.Blacklist["updated"], v.Blacklist["skipped"])
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
	ok, total, detail := syncGroupToAllOnline(in.Group)
	markGroupSyncResult(in.Group, ok, total, detail)
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
		if bl {
			if good, d := syncGroupToNode("blacklist", fp); good {
				gsMu.Lock()
				gsCfg.Blacklist.LastDetail = "新节点 " + name + " 已自动同步：" + d
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
				ok, total, detail := syncGroupToAllOnline(g.name)
				markGroupSyncResult(g.name, ok, total, detail)
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
