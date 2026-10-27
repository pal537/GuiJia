package main

// 群控共享名单的节点侧落地(第 11 项)。
// 主服务器经命令通道推名单, 节点只认 X-Guijia-Internal 头(命令通道内部
// 命令才打该头; 面板代理的命令绝不带, 故面板用户无法伪造内部调用)。
// 黑名单硬规矩同样适用: 同步只新增与改状态, 绝不硬删记录; 本机条目绝不动。
// 白名单按 shared 标记收敛: 只动 shared 条目, 本机条目绝不动。

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sharedTrustFile 共享白名单标记文件(0600): 记哪些信任条目是群控同步来的。
// 信任名单本体仍在 settings.TrustedIPs 里(内核集合与 isTrusted 都读它),
// 本文件只做“哪些是 shared”的标记, 绝不替代本体。
func sharedTrustFile() string {
	if dataDir == "" {
		return "shared_lists.json"
	}
	return filepath.Join(dataDir, "shared_lists.json")
}

type sharedLists struct {
	SharedTrust []string `json:"sharedTrust"`
}

func loadSharedLists() sharedLists {
	var sl sharedLists
	if b, err := os.ReadFile(sharedTrustFile()); err == nil {
		json.Unmarshal(b, &sl)
	}
	if sl.SharedTrust == nil {
		sl.SharedTrust = []string{}
	}
	return sl
}

func saveSharedLists(sl sharedLists) {
	b, _ := json.MarshalIndent(sl, "", "  ")
	os.WriteFile(sharedTrustFile(), b, 0600)
}

// syncBanEntry 主服务器推来的黑名单条目(只传状态, 不传删除)。
type syncBanEntry struct {
	IP     string `json:"ip"`
	Status string `json:"status"` // active | released | expired
	Until  int64  `json:"until"`  // 0=永久
	Reason string `json:"reason"`
}

// applySharedBansLocked 在 banMu 内应用共享黑名单(调用方须持有 banMu)。
// 返回 (新增, 更新状态, 跳过)。本机条目(Source != "shared")一律跳过;
// bannable 校验由调用方在锁外先做(它要读信任名单, 不能在 banMu 内调)。
func applySharedBansLocked(entries []syncBanEntry, now int64) (added, updated, skipped int) {
	for _, e := range entries {
		ip := strings.TrimSpace(e.IP)
		if ip == "" {
			skipped++
			continue
		}
		var b *Ban
		for _, x := range bans {
			if x.IP == ip {
				b = x
				break
			}
		}
		if b != nil && b.Source != "shared" {
			skipped++ // 本机条目绝不动
			continue
		}
		switch e.Status {
		case "active":
			if b == nil {
				b = &Ban{IP: ip, Source: "shared", CreatedAt: now}
				bans = append([]*Ban{b}, bans...)
				added++
			} else {
				updated++
			}
			// 按端口的旧 shared 记录转全局: 先摘端口元素。
			if len(b.Ports) > 0 {
				for _, p := range b.Ports {
					pgDelElement(ip, p)
				}
				b.Ports = nil
			}
			b.Reason = e.Reason
			b.Status, b.ReleasedAt, b.Until = BanActive, 0, e.Until
			normBanStatus(b, now)
			if b.enforced(now) {
				nftAddElement(ip, banKernelTimeout(b, now))
			}
		case "released", "expired":
			if b == nil {
				skipped++ // 没有的 shared 记录不凭空建一条已解封/已过期的
				continue
			}
			was := b.enforced(now)
			b.Status = e.Status
			if e.Status == "released" {
				b.ReleasedAt = now
			}
			if was {
				nftDelElement(ip)
			}
			updated++
		default:
			skipped++
		}
	}
	if added > 0 || updated > 0 {
		saveBans()
	}
	return added, updated, skipped
}

// validTrustEntry 信任条目校验: 单 IP 或 CIDR, 其余一律跳过。
func validTrustEntry(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// applySharedTrust 应用共享白名单(调用方负责 settings 锁外流程):
//
//	hub 列表里没有的旧 shared 条目移除, 缺的补上, 本机条目绝不动。
//
// 返回 (新增, 移除, 跳过, 是否有改动)。
func applySharedTrust(hubList []string) (added, removed, skipped int, changed bool) {
	want := map[string]bool{}
	for _, t := range hubList {
		if t = strings.TrimSpace(t); validTrustEntry(t) {
			want[t] = true
		} else if t != "" {
			skipped++
		}
	}
	sl := loadSharedLists()
	marked := map[string]bool{}
	for _, t := range sl.SharedTrust {
		marked[t] = true
	}
	mu.Lock()
	cur := append([]string{}, settings.TrustedIPs...)
	inCur := map[string]bool{}
	for _, t := range cur {
		inCur[t] = true
	}
	next := []string{}
	for _, t := range cur {
		if marked[t] && !want[t] {
			removed++ // 旧 shared、hub 已没有: 收敛掉(白名单无永不删规矩)
			changed = true
			continue
		}
		next = append(next, t)
	}
	newMarked := []string{}
	for _, t := range sl.SharedTrust {
		if want[t] {
			newMarked = append(newMarked, t)
		}
	}
	for t := range want {
		if !inCur[t] {
			next = append(next, t)
			newMarked = append(newMarked, t)
			added++
			changed = true
		}
	}
	if changed {
		settings.TrustedIPs = next
		saveSettings()
	}
	mu.Unlock()
	if changed {
		sl.SharedTrust = newMarked
		saveSharedLists(sl)
		syncTrustedSets()
	}
	return added, removed, skipped, changed
}

// handleSyncApplyLists 节点侧群控同步落地接口: 只认内部头, 其余一律 403。
// 路径 /api/sync/apply-lists 在面板代理放行集内, 但面板代理的命令不带
// 内部头, 故面板用户调它只会拿到 403, 无法伪造同步。
// 关键语义: 只应用请求里出现的组, 缺席的组绝不动——主服务器按组单发
// (一次只推黑名单或只推白名单), 若把缺席组当空列表收敛, 单组同步会
// 清空另一组的共享状态(双机实测抓到的真 bug: 黑名单同步后白名单被
// 清空, 靠 5 分钟 ticker 重推才恢复, 绝不能依赖这种自愈)。
func handleSyncApplyLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if r.Header.Get("X-Guijia-Internal") != "1" {
		errJSON(w, 403, "仅主服务器内部同步可调用")
		return
	}
	// 用指针区分“组缺席”(跳过)与“组为空列表”(收敛到空)。
	var in struct {
		Blacklist *[]syncBanEntry `json:"blacklist"`
		Whitelist *[]string       `json:"whitelist"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	now := time.Now().Unix()
	black := map[string]int{"added": 0, "updated": 0, "skipped": 0}
	white := map[string]int{"added": 0, "removed": 0, "skipped": 0}
	if in.Blacklist != nil {
		// 黑名单: bannable 校验在锁外做(内网/回环/信任一律跳过, 绝不进名单)。
		// 只对目标为 active 的条目校验(解封/过期不生效, 无需校验)。
		filtered := []syncBanEntry{}
		banSkipped := 0
		for _, e := range *in.Blacklist {
			if e.Status == "active" {
				if ok, _ := bannable(strings.TrimSpace(e.IP)); !ok {
					banSkipped++
					continue
				}
			}
			filtered = append(filtered, e)
		}
		banMu.Lock()
		added, updated, skipped := applySharedBansLocked(filtered, now)
		banMu.Unlock()
		skipped += banSkipped
		if added > 0 || updated > 0 {
			reconcileBans()
		}
		black = map[string]int{"added": added, "updated": updated, "skipped": skipped}
	}
	if in.Whitelist != nil {
		// 白名单收敛(内部处理 settings 锁与内核集合)。
		tAdded, tRemoved, tSkipped, _ := applySharedTrust(*in.Whitelist)
		white = map[string]int{"added": tAdded, "removed": tRemoved, "skipped": tSkipped}
	}
	writeJSON(w, 200, map[string]any{
		"ok":        true,
		"blacklist": black,
		"whitelist": white,
	})
}
