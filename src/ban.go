package main

// 黑名单: nftables 独立表 inet connwatch(集合 block4/block6 带 timeout 标志 + input 链 drop 规则)
// 选择 nft 的原因: 系统未必预装 ipset, 而 nft 是通用 Linux 自带, 自有表不占用系统防火墙规则
// 集合元素带 timeout, 到期内核自动放行; bans.json 保存镜像(原因/到期/来源)供 UI 展示
// 看门狗每分钟自检表/集合/规则是否还在, 缺失自动重建(只动自有表, 不修改系统防火墙规则)
// GUIJIA_DRYBAN=1 时只记录命令不执行(本地测试用)

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Ban struct {
	IP         string `json:"ip"`
	Until      int64  `json:"until"` // 0=永久
	Reason     string `json:"reason"`
	Source     string `json:"source"` // manual | tg | auto | honeypot | scan | portguard
	CreatedAt  int64  `json:"createdAt"`
	Status     string `json:"status"`               // active|expired|released, 见下方常量
	ReleasedAt int64  `json:"releasedAt,omitempty"` // 解封时间(状态变 released 时记)
	Offenses   int    `json:"offenses,omitempty"`   // 自动封禁累计次数(递进阶梯用, 手动/TG 不碰)
	// Ports 作用域(旧端口防护遗留): 为空 = 全局封禁(全部端口); 非空 = 仅封这些端口。
	// 一 IP 仍只一条记录, 全局与按端口互斥: 全局生效时按端口记录不再单独存在。
	Ports []int `json:"ports,omitempty"`
	// Scopes 作用域(防火墙规则用): 每条 = 一条规则下的端口范围。
	// Ports 为空且 Scopes 非空 = 仅封这些规则的端口(不是全局)。
	// 旧记录只有 Ports, 新记录只有 Scopes, 两者可并存(旧记录后来又被新规则封)。
	Scopes []BanScope `json:"scopes,omitempty"`
}

// BanScope: 一条防火墙规则在某封禁记录上的作用域。Ranges 是该规则
// 封禁时(或编辑后, 以最新规则为准)的端口范围; 规则删除后 Ranges 仍
// 在记录里, 内核对齐不依赖规则存在, 删除规则不自动解封。
type BanScope struct {
	RuleID string   `json:"ruleId"`
	Ranges [][2]int `json:"ranges"`
}

// scopeCovers: 该作用域是否覆盖指定端口。
func (s BanScope) covers(port int) bool {
	for _, r := range s.Ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// 黑名单记录状态(PAPA 2026-10-24 硬规矩): 记录永不丢失, 到期/解封只改状态;
// 唯一能删除记录的是设置里数据清理且明确选择「释放全部黑名单」(wipeBans)。
const (
	BanActive   = "active"   // 生效中: 内核集合里必有此 IP
	BanExpired  = "expired"  // 已过期: 内核集合里必无此 IP
	BanReleased = "released" // 已解封: 内核集合里必无此 IP
)

// enforced 报告该记录此刻是否应当正在封禁(名单即唯一事实来源)。
func (b *Ban) enforced(now int64) bool {
	return b.Status == BanActive && (b.Until == 0 || b.Until > now)
}

// normBanStatus 把一条记录的状态归一化(老数据无 status 字段按到期推导;
// 生效中但已过期的翻为已过期)。只改状态, 绝不删记录。返回是否有改动。
func normBanStatus(b *Ban, now int64) bool {
	changed := false
	if b.Status == "" {
		b.Status = BanActive
		changed = true
	}
	if b.Status == BanActive && b.Until > 0 && b.Until <= now {
		b.Status = BanExpired
		changed = true
	}
	return changed
}

var (
	banMu    sync.Mutex
	bans     []*Ban
	dryBan   = os.Getenv("GUIJIA_DRYBAN") == "1"
	fwLinkOK = false // 最近一次看门狗检查: 表/集合/规则都在
)

const (
	nftTable  = "connwatch"
	setV4     = "block4"
	setV6     = "block6"
	setClosed = "closed_ports" // 洪峰防护临时关闭的端口(inet_service, 带 timeout)
)

func loadBans() {
	if b, err := os.ReadFile(bansFile); err == nil {
		json.Unmarshal(b, &bans)
	}
	if bans == nil {
		bans = []*Ban{}
	}
	now := time.Now().Unix()
	changed := false
	for _, b := range bans {
		if normBanStatus(b, now) {
			changed = true
		}
	}
	if changed {
		saveBans()
	}
}

func saveBans() { saveJSON(bansFile, bans) }

func runCmd(name string, args ...string) (string, error) {
	if dryBan && (name == "nft" || name == "ipset" || name == "iptables" || name == "ip6tables") {
		fmt.Printf("[dryban] %s %s\n", name, strings.Join(args, " "))
		return "", nil
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func setNameFor(ip string) string {
	if pip := net.ParseIP(ip); pip != nil && pip.To4() == nil {
		return setV6
	}
	return setV4
}

func nft(args ...string) (string, error) {
	return runCmd("nft", args...)
}

// 建表/链/集合/规则(幂等), 返回是否全部就位
func ensureSetAndRule() bool {
	if dryBan {
		fwLinkOK = true
		return true
	}
	ok := true
	if _, err := nft("add", "table", "inet", nftTable); err != nil {
		// 已存在时 add 会报错, 以 list 结果为准
		if _, lerr := nft("list", "table", "inet", nftTable); lerr != nil {
			ok = false
		}
	}
	if _, err := nft("add", "chain", "inet", nftTable, "input", "{", "type", "filter", "hook", "input", "priority", "-100", ";", "policy", "accept", ";", "}"); err != nil {
		if out, lerr := nft("list", "chain", "inet", nftTable, "input"); lerr != nil || !strings.Contains(out, "hook input") {
			ok = false
		}
	}
	for _, s := range []struct{ name, typ string }{{setV4, "ipv4_addr"}, {setV6, "ipv6_addr"}, {setClosed, "inet_service"}} {
		if _, err := nft("add", "set", "inet", nftTable, s.name, "{", "type", s.typ, ";", "flags", "timeout", ";", "}"); err != nil {
			if _, lerr := nft("list", "set", "inet", nftTable, s.name); lerr != nil {
				ok = false
			}
		}
	}
	// 情报与信任集合: 装 CIDR 前缀必须用 interval 标志, 不带 timeout。
	intelEnsureSets()
	ensureTrustedSetsAndRules()
	if out, err := nft("list", "chain", "inet", nftTable, "input"); err == nil {
		if !strings.Contains(out, "@"+setV4) {
			if _, err := nft("add", "rule", "inet", nftTable, "input", "ip", "saddr", "@"+setV4, "drop"); err != nil {
				ok = false
			}
		}
		if !strings.Contains(out, "@"+setV6) {
			if _, err := nft("add", "rule", "inet", nftTable, "input", "ip6", "saddr", "@"+setV6, "drop"); err != nil {
				ok = false
			}
		}
		if !strings.Contains(out, "@"+setClosed) {
			// 洪峰临时关端口: 只丢"公网来源 -> 已关闭端口"的新连接; 内网来源不匹配此规则,
			// 照常走后续链(系统防火墙), 不受影响。用 != 地址集而非 accept 豁免,
			// 避免在本链提前放行、绕过系统自己的规则。
			priv4 := []string{"{", "10.0.0.0/8,", "172.16.0.0/12,", "192.168.0.0/16", "}"}
			priv6 := []string{"{", "fc00::/7,", "fe80::/10", "}"}
			for _, rl := range [][]string{
				append(append([]string{"ip", "saddr", "!="}, priv4...), "tcp", "dport", "@"+setClosed, "ct", "state", "new", "drop"),
				append(append([]string{"ip", "saddr", "!="}, priv4...), "udp", "dport", "@"+setClosed, "ct", "state", "new", "drop"),
				append(append([]string{"ip6", "saddr", "!="}, priv6...), "tcp", "dport", "@"+setClosed, "ct", "state", "new", "drop"),
				append(append([]string{"ip6", "saddr", "!="}, priv6...), "udp", "dport", "@"+setClosed, "ct", "state", "new", "drop"),
			} {
				if _, err := nft(append([]string{"add", "rule", "inet", nftTable, "input"}, rl...)...); err != nil {
					ok = false
				}
			}
		}
	} else {
		ok = false
	}
	fwLinkOK = ok
	ensurePortGuardSets()
	ensureFWSets()
	syncTrustedSets() // 信任名单进内核集合, 看门狗每分钟跑一次即自愈漂移
	return ok
}

// 启动时把 bans.json 里生效中的条目重新灌入集合(重启/重装后恢复)
func banInit() {
	if dryBan {
		fwLinkOK = true
		return
	}
	ensureSetAndRule()
	migrateSetTimeoutFlags() // 缺 timeout 标志的老集合删了重建(第 3 项迁移)
	ensureSetAndRule()       // 补回迁移中删掉的规则
	now := time.Now().Unix()
	for _, b := range bans {
		if !b.enforced(now) {
			continue
		}
		if len(b.Ports) > 0 {
			for _, p := range b.Ports {
				pgAddElement(b.IP, p, banKernelTimeout(b, now))
			}
			continue
		}
		nftAddElement(b.IP, banKernelTimeout(b, now))
	}
	for _, pb := range portBans {
		if pb.Until > 0 && pb.Until <= now {
			continue
		}
		timeout := 0
		if pb.Until > 0 {
			timeout = int(pb.Until - now)
		}
		nftAddClosed(pb.Port, timeout)
	}
}

// ---------- 重点端口临时关闭(洪峰防护) ----------
// portbans.json 保存镜像(原因/到期)供 UI 展示; 内核侧端口集合元素带 timeout, 到期自动放行

type PortBan struct {
	Port      int    `json:"port"`
	Until     int64  `json:"until"` // 0=永久(手动关闭才可能出现)
	Reason    string `json:"reason"`
	CreatedAt int64  `json:"createdAt"`
}

var (
	pbMu     sync.Mutex
	portBans []*PortBan
)

func loadPortBans() {
	if b, err := os.ReadFile(portBansFile); err == nil {
		json.Unmarshal(b, &portBans)
	}
	if portBans == nil {
		portBans = []*PortBan{}
	}
}

func savePortBans() { saveJSON(portBansFile, portBans) }

func nftAddClosed(port, timeoutSec int) {
	elem := itoa(port)
	if timeoutSec > 0 {
		elem = elem + " timeout " + itoa(timeoutSec) + "s"
	}
	nft("delete", "element", "inet", nftTable, setClosed, "{", itoa(port), "}")
	nft("add", "element", "inet", nftTable, setClosed, "{", elem, "}")
}

// minutes<=0 表示永久关闭
func closePort(port, minutes int, reason string) {
	pbMu.Lock()
	defer pbMu.Unlock()
	for i, b := range portBans {
		if b.Port == port {
			portBans = append(portBans[:i], portBans[i+1:]...)
			break
		}
	}
	now := time.Now()
	pb := &PortBan{Port: port, Reason: reason, CreatedAt: now.Unix()}
	timeout := 0
	if minutes > 0 {
		pb.Until = now.Add(time.Duration(minutes) * time.Minute).Unix()
		timeout = minutes * 60
	}
	nftAddClosed(port, timeout)
	portBans = append([]*PortBan{pb}, portBans...)
	savePortBans()
}

func reopenPort(port int) bool {
	pbMu.Lock()
	defer pbMu.Unlock()
	for i, b := range portBans {
		if b.Port == port {
			portBans = append(portBans[:i], portBans[i+1:]...)
			nft("delete", "element", "inet", nftTable, setClosed, "{", itoa(port), "}")
			savePortBans()
			return true
		}
	}
	return false
}

func activePortBans() []*PortBan {
	pbMu.Lock()
	defer pbMu.Unlock()
	now := time.Now().Unix()
	out := []*PortBan{}
	changed := false
	for _, b := range portBans {
		if b.Until > 0 && b.Until <= now {
			changed = true
			continue
		}
		out = append(out, b)
	}
	if changed {
		portBans = out
		savePortBans()
	}
	return out
}

func portBanOf(port int) *PortBan {
	for _, b := range activePortBans() {
		if b.Port == port {
			return b
		}
	}
	return nil
}

func isPortClosed(port int) bool { return portBanOf(port) != nil }

func nftAddElement(ip string, timeoutSec int) {
	set := setNameFor(ip)
	elem := ip
	if timeoutSec > 0 && setSupportsTimeout(set) {
		elem = ip + " timeout " + itoa(timeoutSec) + "s"
	}
	// 先删后加, 保证时长以最新为准
	nft("delete", "element", "inet", nftTable, set, "{", ip, "}")
	nft("add", "element", "inet", nftTable, set, "{", elem, "}")
}

func nftDelElement(ip string) {
	nft("delete", "element", "inet", nftTable, setNameFor(ip), "{", ip, "}")
}

// ---------- nft 超时兜底(第 3 项) ----------
// 定时封禁早已带内核 timeout(到期内核自动放行); 永久封禁此前 timeout=0,
// 应用一旦死了内核元素就永不消失 = 永久锁死。兜底: 永久封禁也给一个 30 天
// 内核超时——应用活着时 reconcile 会补齐, 实际上仍是永久; 应用死了, 最坏锁
// 30 天, 不会无限期。兜底只管执行层, 账本(bans.json)不受影响。

const permBanBackstopSec = 30 * 24 * 3600 // 永久封禁的内核超时兜底: 30 天

// banKernelTimeout 计算某条封禁应写入内核集合的 timeout 秒数。
func banKernelTimeout(b *Ban, now int64) int {
	if b.Until > 0 {
		if t := int(b.Until - now); t > 1 {
			return t
		}
		return 1
	}
	return permBanBackstopSec
}

// setTimeoutOK 记录各集合是否支持 timeout 元素(启动时迁移检查后填入)。
// 未填入时默认按新版集合处理(1.6.x 起建集合就带 timeout 标志)。
var setTimeoutOK = map[string]bool{}

func setSupportsTimeout(set string) bool {
	if dryBan {
		return true
	}
	if v, ok := setTimeoutOK[set]; ok {
		return v
	}
	return true
}

// parseSetFlagsJSON 从 nft -j list set 输出里读集合的 flags(纯函数, 可单测)。
func parseSetFlagsJSON(out string) []string {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Flags []string `json:"flags"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}
	for _, item := range doc.Nftables {
		if item.Set != nil {
			return item.Set.Flags
		}
	}
	return nil
}

func setHasTimeoutFlag(set string) (bool, error) {
	out, err := nft("-j", "list", "set", "inet", nftTable, set)
	if err != nil {
		return false, err
	}
	for _, f := range parseSetFlagsJSON(out) {
		if f == "timeout" {
			return true, nil
		}
	}
	return false, nil
}

// migrateSetTimeoutFlags 升级迁移: 缺 timeout 标志的老集合删了重建。
// 任一步失败即放弃该集合的迁移, 降级为无 timeout 元素(封禁照常生效,
// 只丢死应用兜底), 绝不因迁移失败破坏现有封禁。
func migrateSetTimeoutFlags() {
	for _, set := range []string{setV4, setV6, setClosed} {
		ok, err := setHasTimeoutFlag(set)
		if err == nil && ok {
			setTimeoutOK[set] = true
			continue
		}
		if err == nil && !ok && migrateOneSet(set) {
			setTimeoutOK[set] = true
			continue
		}
		setTimeoutOK[set] = false
	}
}

func migrateOneSet(set string) bool {
	// 先删引用该集合的规则(否则集合删不掉): nft -a list chain 找 handle
	out, err := nft("-a", "list", "chain", "inet", nftTable, "input")
	if err != nil {
		return false
	}
	var handles []string
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, "@"+set) {
			continue
		}
		if i := strings.LastIndex(ln, "# handle "); i >= 0 {
			if h := strings.TrimSpace(ln[i+len("# handle "):]); h != "" {
				handles = append(handles, h)
			}
		}
	}
	for _, h := range handles {
		if _, err := nft("delete", "rule", "inet", nftTable, "input", "handle", h); err != nil {
			return false
		}
	}
	if _, err := nft("delete", "set", "inet", nftTable, set); err != nil {
		return false
	}
	typ := "ipv4_addr"
	if set == setV6 {
		typ = "ipv6_addr"
	} else if set == setClosed {
		typ = "inet_service"
	}
	if _, err := nft("add", "set", "inet", nftTable, set, "{", "type", typ, ";", "flags", "timeout", ";", "}"); err != nil {
		return false
	}
	return true
}

// hours<=0 表示永久
// 同一 IP 已有记录(不论状态)时原地更新为新的生效记录: 行不消失, 状态翻回生效中。
func applyBan(ip, reason, source string, hours int) (*Ban, error) {
	if ok, why := bannable(ip); !ok {
		return nil, fmt.Errorf("%s", why)
	}
	banMu.Lock()
	defer banMu.Unlock()
	return upsertBanLocked(ip, reason, source, hours), nil
}

// upsertBanLocked 创建或复活一条封禁记录并落内核元素(调用方须持有 banMu)。
// 只改状态与封禁字段, 绝不删记录; Offenses 字段由自动拉黑路径自行维护, 这里不碰。
// 全局封禁覆盖按端口封禁: 旧记录若是按端口的, 先摘除其端口元素再转全局。
func upsertBanLocked(ip, reason, source string, hours int) *Ban {
	now := time.Now()
	var b *Ban
	for _, x := range bans {
		if x.IP == ip {
			b = x
			break
		}
	}
	if b == nil {
		b = &Ban{IP: ip}
		bans = append([]*Ban{b}, bans...)
	}
	if len(b.Ports) > 0 {
		for _, p := range b.Ports {
			pgDelElement(ip, p)
		}
		b.Ports = nil
	}
	if len(b.Scopes) > 0 {
		for _, s := range b.Scopes {
			fwDelElement(ip, s.RuleID)
		}
		b.Scopes = nil
	}
	b.Reason, b.Source, b.CreatedAt = reason, source, now.Unix()
	b.Status, b.ReleasedAt, b.Until = BanActive, 0, 0
	if hours > 0 {
		b.Until = now.Add(time.Duration(hours) * time.Hour).Unix()
	}
	nftAddElement(ip, banKernelTimeout(b, now.Unix()))
	saveBans()
	return b
}

// upsertRuleBanLocked 按防火墙规则封禁(调用方须持有 banMu)。
// 返回 (记录, 是否新封): 已全局生效的 IP 直接返回旧记录、不重复封
// (全局更广)。同一规则已生效则只刷新时长与原因, 不重复事件;
// 同一 IP 被另一规则封则追加 Scopes(多规则并存, 不新开记录)。
// 只改状态与封禁字段。ranges 是规则当时的端口范围(存入记录, 规则
// 删除后仍可对齐, 删除规则不自动解封)。
func upsertRuleBanLocked(ip, reason, source string, hours int, ruleID string, ranges [][2]int) (*Ban, bool) {
	now := time.Now()
	var b *Ban
	for _, x := range bans {
		if x.IP == ip {
			b = x
			break
		}
	}
	if b != nil {
		normBanStatus(b, now.Unix())
		if b.enforced(now.Unix()) && len(b.Ports) == 0 && len(b.Scopes) == 0 {
			return b, false // 已全局封禁, 规则封禁无需再封
		}
	}
	if b == nil {
		b = &Ban{IP: ip}
		bans = append([]*Ban{b}, bans...)
	}
	fresh := true
	for i, s := range b.Scopes {
		if s.RuleID == ruleID {
			// 同规则已在记录里: 刷新范围与时长, 不算新封(避免重复事件/TG)
			b.Scopes[i].Ranges = append([][2]int{}, ranges...)
			fresh = false
			break
		}
	}
	if fresh {
		b.Scopes = append(b.Scopes, BanScope{RuleID: ruleID, Ranges: append([][2]int{}, ranges...)})
	}
	b.Reason, b.Source, b.CreatedAt = reason, source, now.Unix()
	b.Status, b.ReleasedAt, b.Until = BanActive, 0, 0
	if hours > 0 {
		b.Until = now.Add(time.Duration(hours) * time.Hour).Unix()
	}
	fwAddElement(ip, ruleID, banKernelTimeout(b, now.Unix()))
	saveBans()
	return b, fresh
}

func applyRuleBan(ip, reason, source string, hours int, ruleID string, ranges [][2]int) (*Ban, bool, error) {
	if ok, why := bannable(ip); !ok {
		return nil, false, fmt.Errorf("%s", why)
	}
	banMu.Lock()
	defer banMu.Unlock()
	b, fresh := upsertRuleBanLocked(ip, reason, source, hours, ruleID, ranges)
	return b, fresh, nil
}

// ---------- 自动封禁递进(第 1 项) ----------

// 自动封禁阶梯: 首次 1 小时、再次 24 小时、累犯永久。目标: 误伤小, 累犯治得住。
// 只用于自动触发路径(SSH 爆破、扫描识别); 手动/TG 拉黑带用户自选时长, 不走阶梯;
// 蜜罐自动拉黑用自有 T 旋钮(第 6 项定稿), 也不走阶梯。
func autoBanHours(offenses int) int {
	switch offenses {
	case 1:
		return 1
	case 2:
		return 24
	default:
		return 0 // 永久
	}
}

// applyAutoBan 自动拉黑(递进): 同一 IP 的自动封禁次数累计在记录的 Offenses
// 字段里, 到期/解封不清除, 手动/TG 拉黑不碰它。调用方须保证触发时该 IP 未生效
// (如 onSSHFail 的 !isBanned  guard), 避免生效中重复累进。
func applyAutoBan(ip, reason string) (*Ban, error) {
	if ok, why := bannable(ip); !ok {
		return nil, fmt.Errorf("%s", why)
	}
	banMu.Lock()
	defer banMu.Unlock()
	var b *Ban
	for _, x := range bans {
		if x.IP == ip {
			b = x
			break
		}
	}
	offenses := 1
	if b != nil {
		offenses = b.Offenses + 1
	}
	b = upsertBanLocked(ip, reason, "auto", autoBanHours(offenses))
	b.Offenses = offenses
	saveBans()
	return b, nil
}

// releaseBan 解封: 只改状态为已解封并摘除内核元素, 记录保留。
// 返回该 IP 是否有记录(没有记录才算未找到)。
func releaseBan(ip string) bool {
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now().Unix()
	for _, b := range bans {
		if b.IP == ip {
			normBanStatus(b, now)
			was := b.enforced(now)
			ports := append([]int{}, b.Ports...)
			b.Status = BanReleased
			b.ReleasedAt = now
			saveBans()
			if was {
				for _, p := range ports {
					pgDelElement(ip, p)
				}
				for _, s := range b.Scopes {
					fwDelElement(ip, s.RuleID)
				}
				if len(ports) == 0 && len(b.Scopes) == 0 {
					nftDelElement(ip)
				}
			}
			return true
		}
	}
	return false
}

// wipeBans 是全系统唯一删除黑名单记录的入口: 仅供设置页数据清理在用户
// 明确选择「释放全部黑名单」时调用。先解除全部内核封禁, 再清空记录。
func wipeBans() {
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now().Unix()
	for _, b := range bans {
		normBanStatus(b, now)
		if b.enforced(now) {
			if len(b.Ports) > 0 {
				for _, p := range b.Ports {
					pgDelElement(b.IP, p)
				}
			} else {
				nftDelElement(b.IP)
			}
		}
	}
	bans = []*Ban{}
	saveBans()
}

// allBans 返回全部记录(黑名单页展示用): 含已过期/已解封, 永不丢。
func allBans() []*Ban {
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now().Unix()
	changed := false
	for _, b := range bans {
		if normBanStatus(b, now) {
			changed = true
		}
	}
	if changed {
		saveBans()
	}
	out := make([]*Ban, len(bans))
	copy(out, bans)
	return out
}

// activeBans 返回当前真正生效(正在封)的记录。过期只翻状态, 不再删记录。
func activeBans() []*Ban {
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now().Unix()
	out := []*Ban{}
	changed := false
	for _, b := range bans {
		if normBanStatus(b, now) {
			changed = true
		}
		if b.enforced(now) {
			out = append(out, b)
		}
	}
	if changed {
		saveBans()
	}
	return out
}

func isBanned(ip string) bool {
	for _, b := range activeBans() {
		if b.IP == ip {
			return true
		}
	}
	return false
}

// isGloballyBanned 该 IP 是否被全局封禁(全部端口)。按端口/按规则封禁
// 不算全局, 因此自动拉黑/蜜罐/扫描的全局封禁判定必须用它, 不能用 isBanned。
// 注意: Ports 为空但 Scopes 非空是规则作用域, 不是全局, 必须同时判空。
func isGloballyBanned(ip string) bool {
	for _, b := range activeBans() {
		if b.IP == ip && len(b.Ports) == 0 && len(b.Scopes) == 0 {
			return true
		}
	}
	return false
}

// isBannedFor 该 IP 是否在指定端口上被封禁(全局封禁覆盖全部端口)。
// 旧 Ports 记录与新 Scopes 记录都判: 任一覆盖即算封禁。
func isBannedFor(ip string, port int) bool {
	for _, b := range activeBans() {
		if b.IP != ip {
			continue
		}
		if len(b.Ports) == 0 && len(b.Scopes) == 0 {
			return true
		}
		for _, p := range b.Ports {
			if p == port {
				return true
			}
		}
		for _, s := range b.Scopes {
			if s.covers(port) {
				return true
			}
		}
	}
	return false
}

// ---------- 名单与内核集合对齐(名单即唯一事实来源, 看门狗每分钟跑) ----------

// nftListSet 读回某集合当前的元素 IP; 失败返回 error, 调用方不得据此删元素。
func nftListSet(set string) (map[string]bool, error) {
	out, err := nft("-j", "list", "set", "inet", nftTable, set)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, err
	}
	ips := map[string]bool{}
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			var wrap struct {
				Elem struct {
					Val string `json:"val"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &wrap) == nil && wrap.Elem.Val != "" {
				ips[wrap.Elem.Val] = true
				continue
			}
			var plain string
			if json.Unmarshal(raw, &plain) == nil && plain != "" {
				ips[plain] = true
			}
		}
	}
	return ips, nil
}

// reconcileBans: 生效中的记录必须在内核集合里(缺了按剩余时长补回),
// 不在生效中的 IP 必须不在集合里(多了摘除)。集合读失败则本轮跳过,
// 绝不凭空删元素。
func reconcileBans() {
	if dryBan {
		return
	}
	now := time.Now().Unix()
	desired := map[string]*Ban{}
	for _, b := range activeBans() {
		if len(b.Ports) > 0 {
			continue // 按端口记录不在全局集合里, 由 reconcilePortGuard 管
		}
		desired[b.IP] = b
	}
	for _, set := range []string{setV4, setV6} {
		actual, err := nftListSet(set)
		if err != nil {
			continue
		}
		for ip := range actual {
			if _, want := desired[ip]; !want {
				nftDelElement(ip)
			}
		}
		for ip, b := range desired {
			if len(b.Ports) > 0 {
				continue // 按端口记录不在全局集合里, 由 reconcilePortGuard 管
			}
			if setNameFor(ip) != set || actual[ip] {
				continue
			}
			nftAddElement(ip, banKernelTimeout(b, now))
		}
	}
	reconcilePortGuard()
	reconcileFirewall()
}
