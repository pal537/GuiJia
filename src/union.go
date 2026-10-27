package main

// 群控黑名单并集合并：主服务器从各在线节点拉回完整黑名单记录，
// 把主服务器没有的 IP 以 shared 条目并入，随后推给全部节点。
// 语义（与黑名单“记录永不丢失”硬规矩一致）：
//   - 只新增：主服务器已有 IP（任何来源、任何状态）绝不因合并改状态；
//   - 节点本地条目绝不动：推回时节点侧 applySharedBansLocked 会跳过
//     Source != "shared" 的本机条目，合并吸入的 IP 回到原节点时同样跳过；
//   - 离线节点跳过：拉取失败的节点只记名跳过，缺席绝不等于空集
//     （组隔离 bug 的教训：缺席组绝不能当空列表收敛）；
//   - bannable 守门：内网/回环/信任名单 IP 不吸入（与手动拉黑同一护栏）；
//   - 白名单不做并集：白名单仍以主服务器为唯一源（信任是管理决定，
//     节点本地信任绝不反向推给主服务器与其他节点）。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// fullBanEntry 节点完整黑名单里的一条记录（并集拉取用，含全部来源与状态）。
type fullBanEntry struct {
	IP        string `json:"ip"`
	Status    string `json:"status"` // active | released | expired
	Until     int64  `json:"until"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	CreatedAt int64  `json:"createdAt"`
}

// handleSyncFullBans 节点侧完整黑名单（内部命令专用，只认内部头，
// 与 shared-state 同 guard；面板代理调它只会 403，无法窃取别机名单）。
func handleSyncFullBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	if r.Header.Get("X-Guijia-Internal") != "1" {
		errJSON(w, 403, "仅主服务器内部同步可调用")
		return
	}
	banMu.Lock()
	defer banMu.Unlock()
	out := []fullBanEntry{}
	for _, b := range bans {
		if b == nil {
			continue
		}
		out = append(out, fullBanEntry{
			IP: b.IP, Status: b.Status, Until: b.Until,
			Reason: b.Reason, Source: b.Source, CreatedAt: b.CreatedAt,
		})
	}
	writeJSON(w, 200, map[string]any{"blacklist": out})
}

// unionPullWait 并集拉取等待（默认 30 秒，单测可调小模拟慢节点）。
var unionPullWait = 30 * time.Second

// unionMu 串行化并集合并（ticker / 立即同步 / 批准自动同步可能并发触发）。
var unionMu sync.Mutex

// canonUnionIP 并集 IP 归一化：非法格式返回 ""（跳过），合法则取标准写法，
// 避免同一 IP 的不同写法（如 IPv6 缩写差异）被当成两条。
func canonUnionIP(s string) string {
	pip := net.ParseIP(strings.TrimSpace(s))
	if pip == nil {
		return ""
	}
	return pip.String()
}

// collectBlacklistUnion 从全部在线节点拉回完整记录并入主服务器。
// 返回（新增数，合并后主服务器全部记录数，跳过节点名）。
func collectBlacklistUnion() (added, total int, skipped []string) {
	unionMu.Lock()
	defer unionMu.Unlock()
	hubMu.Lock()
	type node struct{ fp, name string }
	nodes := []node{}
	for _, s := range hubServers {
		if s != nil {
			nodes = append(nodes, node{s.Fingerprint, s.Name})
		}
	}
	hubMu.Unlock()
	now := time.Now().Unix()
	for _, n := range nodes {
		// 离线节点只记名跳过（不拉取、不清空、不报错），缺席绝不等于空集。
		hubMu.Lock()
		s := findHubServer(n.fp)
		online := hubNodeOnline(s)
		hubMu.Unlock()
		if !online {
			skipped = append(skipped, n.name)
			continue
		}
		status, body, errKind := hubCallNodeInternalTimeout(n.fp, "GET", "api/sync/full-bans", nil, true, unionPullWait)
		if errKind != "" || status < 200 || status >= 300 {
			skipped = append(skipped, n.name)
			continue
		}
		var v struct {
			Blacklist []fullBanEntry `json:"blacklist"`
		}
		if json.Unmarshal(body, &v) != nil {
			skipped = append(skipped, n.name)
			continue
		}
		// 先在锁外做 bannable 过滤（它读信任名单，不能在 banMu 内调），
		// 再在 banMu 内判重后新增，避免并发手动拉黑造成重复。
		cands := []fullBanEntry{}
		for _, e := range v.Blacklist {
			ip := canonUnionIP(e.IP)
			if ip == "" {
				continue
			}
			if ok, _ := bannable(ip); !ok {
				continue // 内网/回环/信任：不吸入
			}
			e.IP = ip
			cands = append(cands, e)
		}
		banMu.Lock()
		changed := false
		for _, e := range cands {
			exists := false
			for _, b := range bans {
				if b != nil && b.IP == e.IP {
					exists = true
					break
				}
			}
			if exists {
				continue // 主服务器已有：状态绝不动
			}
			st := e.Status
			if st != BanActive && st != BanReleased && st != BanExpired {
				continue
			}
			reason := e.Reason
			if reason == "" {
				reason = "群控并集"
			}
			created := e.CreatedAt
			if created <= 0 {
				created = now
			}
			b := &Ban{IP: e.IP, Source: "shared", Status: st, Until: e.Until, Reason: reason, CreatedAt: created}
			normBanStatus(b, now)
			bans = append([]*Ban{b}, bans...)
			if b.enforced(now) {
				nftAddElement(b.IP, banKernelTimeout(b, now))
			}
			added++
			changed = true
		}
		if changed {
			saveBans()
		}
		banMu.Unlock()
	}
	banMu.Lock()
	total = len(bans)
	banMu.Unlock()
	return added, total, skipped
}

// banCounts 黑名单计数（只按归一化规则计，不改状态不落盘）：
// active 且未到期为生效中；active 但已到期计已过期；其余按状态计。
func banCounts() (active, released, expired, total int) {
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now().Unix()
	total = len(bans)
	for _, b := range bans {
		if b == nil {
			continue
		}
		switch b.Status {
		case BanReleased:
			released++
		case BanExpired:
			expired++
		default: // active（含老数据空状态）：
			if b.Until > 0 && b.Until <= now {
				expired++
			} else {
				active++
			}
		}
	}
	return active, released, expired, total
}

// syncBlacklistToAllOnline 并集版黑名单同步：先从各在线节点合并，
// 再把合并后的集合推给全部在线节点（推送与状态同步逻辑复用现有路径）。
// 返回（成功数，总数，明细：合并数 + 并集总数 + 跳过节点 + 各节点详情）。
func syncBlacklistToAllOnline() (int, int, string) {
	added, total, skipped := collectBlacklistUnion()
	ok, n, detail := syncGroupToAllOnline("blacklist")
	prefix := fmt.Sprintf("并集：合并新增 %d 条，当前并集 %d 条", added, total)
	if len(skipped) > 0 {
		prefix += "（跳过离线节点：" + strings.Join(skipped, "、") + "）"
	}
	return ok, n, prefix + "；" + detail
}
