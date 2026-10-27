package main

// 威胁情报: 外部攻击名单, 单独分区 enforcement, 永不进黑名单记录。
//
// 定点(2026-10-27 PAPA 拍板):
// 1. 名单不进他自己的黑名单列表: 面板黑名单里不展开条目, 只显示总数;
// 黑名单总数与今日拉黑都不含情报名单, 数字分开算。
// 2. 底层直接封禁: 名单进独立 nft 集合 intel4/intel6, 入方向全端口丢弃
// (TCP+UDP), 与黑名单同一层丢弃但不同集合。
// 3. 信任白名单优先于一切: 信任名单与内网先放行, 再查黑名单与情报名单;
// 即使 IP 已在黑名单或情报名单里, 加入信任后照样能连。实现靠链首
// accept 规则(trusted4/trusted6), 不是靠应用层过滤, 这样信任增删
// 立即生效, 不用重拉名单。
// 4. 防护页底部独立卡片, 不算进五板斧; 手动开启, 默认关; 关了立即
// 清空情报集合(缓存文件保留, 重开直接恢复)。
// 5. 来源只有公开聚合直链, 默认 FireHOL level1, 地址可改, 免费、无需
// Key。CrowdSec 官方源 2026-10-27 已拿掉: Service API key 要 29 美元/
// 月, PAPA 否决, 不搞。
// 6. 拉取失败不断档: 旧名单继续封禁, 状态标失败原因; 连续失败 3 次
// 才 TG 报一次, 不刷屏。超过 2 个更新周期未成功则状态记"过期"
// (旧名单仍在封禁)。
// 7. 情报名单是缓存, 不是他的记录: 每次拉取整包替换, 不适用黑名单
// "记录永不丢失"规矩; 今日拉黑/黑名单统计永远不含情报封禁。
// 8. 保留地址段永不进集合(2026-10-27 血的教训): 外部名单可能含
// IANA 特殊用途段, FireHOL level1 的 fullbogons 就含 127.0.0.0/8,
// 一旦进集合, 本机回环(nginx 反代面板走 127.0.0.1)立刻被封, 面板
// 当场失联, 且刷新会重新上锁。根治三层, 缺一不可:
//   a. 解析层过滤: 任何与保留段重叠的条目一律不进名单(与源无关,
//      换任何直链都一样, 别人用也不会中招);
//   b. 应用层兜底: 写 nft 集合前再滤一次, 未来任何新路径绕过解析
//      也进不了集合;
//   c. 链首回环放行: input 链首 iif lo accept, 回环流量永远先放行,
//      不受任何集合(情报/黑名单/端口防护)影响, 面板不可能再被自己
//      的名单锁死。

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	intelSetV4 = "intel4"
	intelSetV6 = "intel6"
	// 信任集合: interval 标志才能装 CIDR 前缀; 不带 timeout, 信任不过期。
	trustSetV4 = "trusted4"
	trustSetV6 = "trusted6"

	intelDefaultPublicURL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
	intelFetchTimeout     = 30 * time.Second
	intelBatchSize        = 2000 // 单次 nft add element 的条目上限, 避免参数过长
)

type IntelState struct {
	Enabled       bool   `json:"enabled"` // 手动开启, 默认关
	PublicURL     string `json:"publicUrl"`
	UpdatesPerDay int    `json:"updatesPerDay"` // 默认 4, 钳制 1~24
	CountV4       int    `json:"countV4"`
	CountV6       int    `json:"countV6"`
	LastFetchUnix int64  `json:"lastFetchUnix"` // 上次成功拉取, 0=从未成功
	NextFetchUnix int64  `json:"nextFetchUnix"`
	Status        string `json:"status"` // never | ok | fetching | failed | expired
	LastError     string `json:"lastError"`
	FailCount     int    `json:"failCount"` // 连续失败次数, 成功清零
}

var (
	intelMu       sync.Mutex
	intelState    IntelState
	intelWake     = make(chan struct{}, 1)
	intelFetching bool
)

func intelDir() string { return filepath.Join(dataDir, "intel") }
func intelStatePath() string {
	return filepath.Join(intelDir(), "state.json")
}
func intelCachePath() string {
	return filepath.Join(intelDir(), "cache.txt")
}
func intelLoadState() {
	intelState = IntelState{UpdatesPerDay: 4, Status: "never", PublicURL: intelDefaultPublicURL}
	if b, err := os.ReadFile(intelStatePath()); err == nil {
		var st IntelState
		if json.Unmarshal(b, &st) == nil {
			intelState = st
		}
	}
	if intelState.UpdatesPerDay < 1 || intelState.UpdatesPerDay > 24 {
		intelState.UpdatesPerDay = 4
	}
	if intelState.PublicURL == "" {
		intelState.PublicURL = intelDefaultPublicURL
	}
}

func intelSaveState() {
	os.MkdirAll(intelDir(), 0755)
	saveJSON(intelStatePath(), intelState)
}

func intelInterval() time.Duration {
	n := intelState.UpdatesPerDay
	if n < 1 || n > 24 {
		n = 4
	}
	return 24 * time.Hour / time.Duration(n)
}

// intelReservedNets: IANA 特殊用途地址段, 永不进任何封禁集合。
// 含回环、私网、链路本地、CGNAT、文档、基准测试、组播、未来保留
// 段; 封了它们等于封自己人(回环断面板、内网断服务、Docker 网段断
// 容器), 且与名单来源无关, 必须在解析与应用两处同时过滤。
var intelReservedNets []*net.IPNet

func init() {
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16",
		"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "100::/64",
		"2001::/32", "2001:2::/48", "2001:10::/28",
		"2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			intelReservedNets = append(intelReservedNets, n)
		}
	}
}

// isDocRange: 文档示例段(写进 RFC 的测试地址, 公网不可达, 全库测试
// 固件都用它)。bannable 特意放行, 否则 203.0.113.x 的测试固件全灭;
// 生产入站来源不可能是文档段, 放行不影响真实防护。情报名单过滤
// (intelOverlapsReserved)不走这条例外, 文档段仍不进情报集合。
func isDocRange(ip net.IP) bool {
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// isReservedIP: 该 IP 是否落在任一 IANA 特殊用途段(文档段除外)。
// 供 bannable 守门: 保留段永远不封禁, 不依赖 Go 的 IsPrivate() 是否
// 含 100.64/10 这类边界(实测 100.64.0.1 在旧守门下可封, 已补)。
func isReservedIP(ip net.IP) bool {
	if ip == nil || isDocRange(ip) {
		return false
	}
	for _, r := range intelReservedNets {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
func intelOverlapsReserved(ln string) bool {
	if strings.Contains(ln, "/") {
		_, n, err := net.ParseCIDR(ln)
		if err != nil {
			return false
		}
		for _, r := range intelReservedNets {
			if r.Contains(n.IP) || n.Contains(r.IP) {
				return true
			}
		}
		return false
	}
	ip := net.ParseIP(ln)
	if ip == nil {
		return false
	}
	for _, r := range intelReservedNets {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// filterIntelReserved: 写集合前的兜底过滤, 保留段一律剔除。
// 新分配切片, 不改动入参(调用方用原切片长度记数)。
func filterIntelReserved(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !intelOverlapsReserved(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// parseIntelList 解析名单文本: 忽略空行与 # 注释, 取每行首字段,
// 接受 CIDR 与裸 IP, 归一化后去重, 分 v4/v6 两列返回; 与保留段重叠
// 的条目直接计入 skipped, 永不进名单(见文件头第 8 条)。
func parseIntelList(data []byte) (v4, v6 []string, skipped int) {
	seen := map[string]bool{}
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if f := strings.Fields(ln); len(f) > 0 {
			ln = f[0]
		}
		if strings.Contains(ln, "/") {
			_, n, err := net.ParseCIDR(ln)
			if err != nil {
				skipped++
				continue
			}
			ln = n.String()
		} else if ip := net.ParseIP(ln); ip != nil {
			ln = ip.String()
		} else {
			skipped++
			continue
		}
		if intelOverlapsReserved(ln) {
			skipped++
			continue
		}
		if seen[ln] {
			continue
		}
		seen[ln] = true
		if strings.Contains(ln, ":") {
			v6 = append(v6, ln)
		} else {
			v4 = append(v4, ln)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, skipped
}

// validateIntelInput 校验直链地址: 须是 http(s) 直链。空地址由调用方
// 先填默认 FireHOL 地址, 到这里一定非空。
func validateIntelInput(publicURL string) error {
	if !strings.HasPrefix(publicURL, "http://") && !strings.HasPrefix(publicURL, "https://") {
		return fmt.Errorf("直链地址须以 http:// 或 https:// 开头")
	}
	return nil
}

func intelFetch() ([]byte, error) {
	url := intelState.PublicURL
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "guijia-intel/1.0")
	cli := &http.Client{Timeout: intelFetchTimeout}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("拉取失败: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// intelEnsureSets 建情报集合与丢弃规则(幂等); 信任集合与链首放行规则
// 由 ensureTrustedSetsAndRules 负责, 两处都只在规则缺失时补, 不重复加。
func intelEnsureSets() {
	if dryBan {
		return
	}
	for _, s := range []struct{ name, typ string }{{intelSetV4, "ipv4_addr"}, {intelSetV6, "ipv6_addr"}} {
		if _, err := nft("add", "set", "inet", nftTable, s.name, "{", "type", s.typ, ";", "flags", "interval", ";", "}"); err != nil {
			if _, lerr := nft("list", "set", "inet", nftTable, s.name); lerr != nil {
				fmt.Fprintln(os.Stderr, "intel: 建集合失败", s.name, err)
			}
		}
	}
	if out, err := nft("list", "chain", "inet", nftTable, "input"); err == nil {
		if !strings.Contains(out, "@"+intelSetV4) {
			nft("add", "rule", "inet", nftTable, "input", "ip", "saddr", "@"+intelSetV4, "drop")
		}
		if !strings.Contains(out, "@"+intelSetV6) {
			nft("add", "rule", "inet", nftTable, "input", "ip6", "saddr", "@"+intelSetV6, "drop")
		}
	}
}

// chunkStrings 把条目切成每批至多 size 条, 避免单次 nft 调用参数过长。
func chunkStrings(ips []string, size int) [][]string {
	var out [][]string
	for i := 0; i < len(ips); i += size {
		j := i + size
		if j > len(ips) {
			j = len(ips)
		}
		out = append(out, ips[i:j])
	}
	return out
}

// intelApply 整包替换情报集合: 先 flush 再分批写入; 失败保留旧集合
// (调用方在失败时不更新状态计数, 下次拉取重试)。写集合前再滤一次
// 保留段(兜底, 见文件头第 8 条): 未来任何新路径绕过解析也进不了集合。
func intelApply(v4, v6 []string) error {
	intelEnsureSets()
	if dryBan {
		return nil
	}
	v4, v6 = filterIntelReserved(v4), filterIntelReserved(v6)
	for _, s := range []string{intelSetV4, intelSetV6} {
		if _, err := nft("flush", "set", "inet", nftTable, s); err != nil {
			return err
		}
	}
	for _, job := range []struct {
		set string
		ips []string
	}{{intelSetV4, v4}, {intelSetV6, v6}} {
		for _, chunk := range chunkStrings(job.ips, intelBatchSize) {
			elems := "{" + strings.Join(chunk, ", ") + "}"
			if _, err := nft("add", "element", "inet", nftTable, job.set, "{", elems, "}"); err != nil {
				return err
			}
		}
	}
	return nil
}

func intelFlushSets() {
	if dryBan {
		return
	}
	for _, s := range []string{intelSetV4, intelSetV6} {
		nft("flush", "set", "inet", nftTable, s)
	}
}

// intelRefreshNow 拉取并整包替换一次; 成功更新计数与缓存, 失败不断档
// (旧集合不动, 只记状态与连续失败数, 第 3 次连续失败 TG 报一次)。
func intelRefreshNow() {
	intelMu.Lock()
	if intelFetching {
		intelMu.Unlock()
		return
	}
	intelFetching = true
	intelMu.Unlock()
	defer func() {
		intelMu.Lock()
		intelFetching = false
		intelMu.Unlock()
	}()

	intelMu.Lock()
	intelState.Status = "fetching"
	intelMu.Unlock()

	data, err := intelFetch()
	now := time.Now()
	intelMu.Lock()
	defer intelMu.Unlock()
	if err != nil {
		intelState.Status = "failed"
		intelState.LastError = err.Error()
		intelState.FailCount++
		intelState.NextFetchUnix = now.Add(intelInterval()).Unix()
		if intelState.FailCount == 3 && tgConfigured() {
			go tgSend(tgWithTitle("名单拉取连续失败 3 次, 旧名单仍在封禁: "+err.Error()), "", false)
		}
		intelSaveState()
		return
	}
	v4, v6, _ := parseIntelList(data)
	if err := intelApply(v4, v6); err != nil {
		intelState.Status = "failed"
		intelState.LastError = "写入 nft 失败: " + err.Error()
		intelState.FailCount++
		intelState.NextFetchUnix = now.Add(intelInterval()).Unix()
		intelSaveState()
		return
	}
	os.MkdirAll(intelDir(), 0755)
	os.WriteFile(intelCachePath(), data, 0644)
	intelState.CountV4, intelState.CountV6 = len(v4), len(v6)
	intelState.LastFetchUnix = now.Unix()
	intelState.NextFetchUnix = now.Add(intelInterval()).Unix()
	intelState.Status = "ok"
	intelState.LastError = ""
	intelState.FailCount = 0
	intelSaveState()
}

// intelDisplayStatus 面板显示用状态: 未开启 / 正常 / 拉取失败(旧名单仍在封禁)
// / 过期(超过 2 个周期未成功, 旧名单仍在封禁)。
func intelDisplayStatus() string {
	intelMu.Lock()
	defer intelMu.Unlock()
	if !intelState.Enabled {
		return "未开启"
	}
	if intelState.Status == "fetching" {
		return "拉取中"
	}
	if intelState.LastFetchUnix > 0 && time.Since(time.Unix(intelState.LastFetchUnix, 0)) > 2*intelInterval() {
		return "过期(旧名单仍在封禁)"
	}
	if intelState.Status == "failed" {
		return "拉取失败(旧名单仍在封禁)"
	}
	if intelState.Status == "never" || intelState.LastFetchUnix == 0 {
		return "未拉取过"
	}
	return "正常"
}

func intelWakeUp() {
	select {
	case intelWake <- struct{}{}:
	default:
	}
}

func intelLoop() {
	for {
		intelMu.Lock()
		enabled := intelState.Enabled
		next := time.Unix(intelState.NextFetchUnix, 0)
		intelMu.Unlock()
		var wait time.Duration
		if !enabled {
			wait = time.Hour
		} else if d := time.Until(next); d > 0 {
			wait = d
		} else {
			go intelRefreshNow()
			wait = intelInterval()
		}
		select {
		case <-intelWake:
			continue
		case <-time.After(wait):
		}
	}
}

// intelInit 启动时: 开启则用缓存恢复集合并起定时循环; 关闭则清空
// 集合, 保证"关了就是关了"在重启后仍然成立。
func intelInit() {
	intelLoadState()
	if !intelState.Enabled {
		intelFlushSets()
		go intelLoop()
		return
	}
	if b, err := os.ReadFile(intelCachePath()); err == nil {
		v4, v6, _ := parseIntelList(b)
		if err := intelApply(v4, v6); err == nil {
			intelMu.Lock()
			intelState.CountV4, intelState.CountV6 = len(v4), len(v6)
			intelMu.Unlock()
		}
	}
	go intelLoop()
}

// ---------- 信任白名单: 链首放行, 优先于黑名单与情报名单 ----------

// ensureTrustedSetsAndRules 建信任集合与链首 accept 规则(幂等)。
// insert rule 默认插到链首, 因此信任放行一定在黑名单/情报丢弃规则之前。
// 另在链首补一条回环放行(见文件头第 8 条): 回环流量只可能来自本机,
// 外网伪造的回环源地址在入口就被内核丢弃, 因此放行回环不引入外部
// 风险, 却能保证任何集合(情报/黑名单/端口防护)都锁不死本机面板。
func ensureTrustedSetsAndRules() {
	if dryBan {
		return
	}
	for _, s := range []struct{ name, typ string }{{trustSetV4, "ipv4_addr"}, {trustSetV6, "ipv6_addr"}} {
		if _, err := nft("add", "set", "inet", nftTable, s.name, "{", "type", s.typ, ";", "flags", "interval", ";", "}"); err != nil {
			if _, lerr := nft("list", "set", "inet", nftTable, s.name); lerr != nil {
				fmt.Fprintln(os.Stderr, "intel: 建信任集合失败", s.name, err)
			}
		}
	}
	if out, err := nft("list", "chain", "inet", nftTable, "input"); err == nil {
		if !strings.Contains(out, "@"+trustSetV4) {
			nft("insert", "rule", "inet", nftTable, "input", "ip", "saddr", "@"+trustSetV4, "accept")
		}
		if !strings.Contains(out, "@"+trustSetV6) {
			nft("insert", "rule", "inet", nftTable, "input", "ip6", "saddr", "@"+trustSetV6, "accept")
		}
		if !chainHasLoopbackAccept(out) {
			nft("insert", "rule", "inet", nftTable, "input", "iif", "lo", "accept")
		}
	}
}

// chainHasLoopbackAccept: 链文本里是否已有回环放行规则(按行判定,
// 兼容 nft 不同版本的引号格式)。
func chainHasLoopbackAccept(chain string) bool {
	for _, ln := range strings.Split(chain, "\n") {
		if strings.Contains(ln, "iif") && strings.Contains(ln, "lo") && strings.Contains(ln, "accept") {
			return true
		}
	}
	return false
}

// normalizeTrustEntry 归一化一条信任条目: 裸 IP 原样, CIDR 归一化为网段
// 地址(如 1.2.3.4/24 -> 1.2.3.0/24), 非法返回 false, 供内核 interval
// 集合与应用层 isTrusted 双边一致。
func normalizeTrustEntry(t string) (string, bool) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", false
	}
	if strings.Contains(t, "/") {
		_, n, err := net.ParseCIDR(t)
		if err != nil {
			return "", false
		}
		return n.String(), true
	}
	if net.ParseIP(t) == nil {
		return "", false
	}
	return t, true
}

// 信任条目很少, flush 窗口可忽略; 失败只记日志, 看门狗下一轮 ensure
// 会重建集合与规则, 下一次信任变更或设置保存会重新同步。
// trustSetLists 内核信任集合的条目来源: 设置名单 + (勾选“信任全部内网 IP”时)
// 四段标准私网范围, 归一化后去重(第 6 项: 标志位隐式信任, 绝不写进列表)。
func trustSetLists() (v4, v6 []string) {
	mu.Lock()
	list := append([]string{}, settings.TrustedIPs...)
	trustLAN := settings.TrustLAN
	mu.Unlock()
	if trustLAN {
		list = append(list, stdPrivateCIDRs...)
	}
	seen := map[string]bool{}
	for _, t := range list {
		nt, ok := normalizeTrustEntry(t)
		if !ok || seen[nt] {
			continue
		}
		seen[nt] = true
		if strings.Contains(nt, ":") {
			v6 = append(v6, nt)
		} else {
			v4 = append(v4, nt)
		}
	}
	return v4, v6
}

// syncTrustedSets 把设置里的信任名单同步进内核集合(flush 后重写)。
func syncTrustedSets() {
	if dryBan {
		return
	}
	v4, v6 := trustSetLists()
	ensureTrustedSetsAndRules()
	for _, job := range []struct {
		set string
		ips []string
	}{{trustSetV4, v4}, {trustSetV6, v6}} {
		if _, err := nft("flush", "set", "inet", nftTable, job.set); err != nil {
			fmt.Fprintln(os.Stderr, "intel: 清空信任集合失败", job.set, err)
			continue
		}
		if len(job.ips) == 0 {
			continue
		}
		elems := "{" + strings.Join(job.ips, ", ") + "}"
		if _, err := nft("add", "element", "inet", nftTable, job.set, "{", elems, "}"); err != nil {
			fmt.Fprintln(os.Stderr, "intel: 写入信任集合失败", job.set, err)
		}
	}
}

// ---------- 面板 API ----------

func handleIntelStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	intelMu.Lock()
	st := intelState
	intelMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"enabled":       st.Enabled,
		"publicUrl":     st.PublicURL,
		"updatesPerDay": st.UpdatesPerDay,
		"countV4":       st.CountV4, "countV6": st.CountV6, "count": st.CountV4 + st.CountV6,
		"lastFetchUnix": st.LastFetchUnix, "nextFetchUnix": st.NextFetchUnix,
		"status": intelDisplayStatus(), "lastError": st.LastError, "failCount": st.FailCount,
	})
}

func handleIntelSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Enabled       bool   `json:"enabled"`
		PublicURL     string `json:"publicUrl"`
		UpdatesPerDay int    `json:"updatesPerDay"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "bad json")
		return
	}
	in.PublicURL = strings.TrimSpace(in.PublicURL)
	if in.UpdatesPerDay < 1 || in.UpdatesPerDay > 24 {
		in.UpdatesPerDay = 4
	}
	if in.PublicURL == "" {
		in.PublicURL = intelDefaultPublicURL
	}
	if in.Enabled {
		if err := validateIntelInput(in.PublicURL); err != nil {
			errJSON(w, 400, err.Error())
			return
		}
	}
	intelMu.Lock()
	wasEnabled := intelState.Enabled
	intelState.Enabled = in.Enabled
	intelState.PublicURL = in.PublicURL
	intelState.UpdatesPerDay = in.UpdatesPerDay
	if in.Enabled {
		intelState.NextFetchUnix = time.Now().Unix()
	}
	intelSaveState()
	intelMu.Unlock()
	if !in.Enabled {
		intelFlushSets() // 关了立即清空, 不再封禁
	} else if !wasEnabled {
		go intelRefreshNow() // 刚开启立即拉一次
	}
	intelWakeUp()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func handleIntelRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	intelMu.Lock()
	enabled := intelState.Enabled
	fetching := intelFetching
	intelMu.Unlock()
	if !enabled {
		errJSON(w, 400, "威胁情报未开启")
		return
	}
	if fetching {
		errJSON(w, 400, "正在拉取中, 稍后再试")
		return
	}
	go intelRefreshNow()
	writeJSON(w, 200, map[string]bool{"ok": true})
}
