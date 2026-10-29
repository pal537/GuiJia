package main

// guijia(龟甲安全防护 Linux 通用版): 连接监控与入侵防护
// 实时连接(按监控端口分组, 带归属地)、登录/爆破/新监听事件、nft 黑名单、TG 报警与日报
// 数据源: ss 连接表、conntrack、系统 auth 日志
// 环境变量: GUIJIA_DATA_DIR(默认 /var/lib/guijia), GUIJIA_PORT(默认 59188),
//   GUIJIA_AUTHLOG(SSH 日志路径, 默认自动识别), GUIJIA_DRYBAN=1(拉黑只记录不执行)

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // 内嵌时区库: 不依赖系统 zoneinfo 也能取到 Asia/Shanghai
)

// 应用版本(备份文件里的 version 字段与此一致; manifest 里的 version 也须同步)。
// var 而不用 const: 实测可用 -ldflags -X main.appVersion=<版> 造出"新版"二进制,
// 供升级功能的双机实测用(默认仍是 0.1)。
var appVersion = "0.1"

// 全程序统一中国时间: TG 通知/日报/事件日界都以 Asia/Shanghai 为准
// (系统时区不可靠时通知曾出现 UTC 时间, 故不跟系统时区走)。
func init() {
	if loc, err := time.LoadLocation("Asia/Shanghai"); err == nil {
		time.Local = loc
	}
}

//go:embed ui/index.html
var indexHTML []byte

//go:embed ui/managed.html
var managedHTML []byte

//go:embed geo/ip2region.xdb
var embeddedXDBv4 []byte

var (
	dataDir      string
	portsFile    string
	bansFile     string
	portBansFile string
	settingFile  string
	statsFile    string
	eventsDir    string
	eventsSrcDir string
	geoV6Path    string
	geoV4Path    string
	rescueFile   string
	authFile     string
	nodeFile     string
	serversFile  string
	homeSeenFile string
	startedAt    = time.Now()
)

// ---------- 数据模型 ----------

type PortWatch struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`  // tcp
	Name   string `json:"name"`   // 备注名
	Star   bool   `json:"star"`   // 重点关注
	Source string `json:"source"` // firewall | scan | manual
	Kind   string `json:"kind"`   // ssh | ui | smb | ftp | webdav | nfs | dlna | media | db | download | other
}

type Settings struct {
	TGEnabled         bool     `json:"tgEnabled"`
	TGBotToken        string   `json:"tgBotToken"`
	TGChatID          string   `json:"tgChatId"`
	AlertSSHLogin     bool     `json:"alertSshLogin"`       // 默认开
	AlertSSHBrute     bool     `json:"alertSshBrute"`       // 默认开
	AlertSSHConn      bool     `json:"alertSshConn"`        // SSH 端口新连接推送, 默认开
	AlertPortGuardBan bool     `json:"alertPortGuardBan"`   // 端口防护封禁推送, 默认开(此前无开关恒推送)
	AlertUILogin      bool     `json:"alertUiLogin"`        // 默认开
	AlertNewListener  bool     `json:"alertNewListener"`    // 默认关
	AlertMuteInternal bool     `json:"alertMuteInternal"`   // 内网访问不通知(只记录不推送), 默认关=内网照常通知
	AutoBanEnabled    bool     `json:"autoBanEnabled"`      // 默认关(手动开启)
	BruteWindowMin    int      `json:"bruteWindowMin"`      // 默认10
	BruteThreshold    int      `json:"bruteThreshold"`      // 默认5
	BruteBanHours     int      `json:"bruteBanHours"`       // 默认24
	ScanEnabled       bool     `json:"scanEnabled"`         // 扫描识别, 默认关
	AlertScan         bool     `json:"alertScan"`           // 扫描报警, 默认开
	ScanAutoBan       bool     `json:"scanAutoBan"`         // 扫描自动拉黑, 默认关
	ScanWindowMin     int      `json:"scanWindowMin"`       // 默认 5
	ScanDistinctPorts int      `json:"scanDistinctPorts"`   // 默认 5
	FloodEnabled      bool     `json:"floodEnabled"`        // 端口洪峰防护(分布式爆破), 默认关
	FloodWindowMin    int      `json:"floodWindowMin"`      // 默认1
	FloodDistinctIPs  int      `json:"floodDistinctIps"`    // 默认30
	FloodCloseMin     int      `json:"floodCloseMin"`       // 默认60
	FloodPorts        string   `json:"floodPorts"`          // 手动洪峰端口列表(原始文本, 用统一解析逻辑解析; 空 = 不对任何端口触发)
	ReportEnabled     bool     `json:"reportEnabled"`       // 默认开
	ReportTime        string   `json:"reportTime"`          // 默认 09:00
	LogKeepDays       int      `json:"logKeepDays"`         // 默认30
	NewSrcKeepDays    int      `json:"newSrcKeepDays"`      // 新来源事件保留天数, 默认7; 0=只计数不记录
	TrafficAcct       bool     `json:"trafficAcct"`         // 每连接流量统计: 应用自动打开内核字节计数, 默认开
	LedgerKeepDays    int      `json:"ledgerKeepDays"`      // 流量每日明细保留天数, 默认7; 0=永久保留(永久累计不受此设置影响)
	TrustedIPs        []string `json:"trustedIps"`          // 信任名单: 不报警、不可拉黑
	TrustLAN          bool     `json:"trustLan"`            // 信任全部内网 IP: 四段标准私网范围隐式信任, 绝不写进列表(第 6 项)
	RescuePassHash    string   `json:"rescuePassHash"`      // 急救超级密码哈希(GET 时剥离, 永不外泄; 只能由专用接口改)
	AuthLogPath       string   `json:"authLogPath"`         // SSH 日志路径: 为空 = 自动识别 auth.log/secure
	PanelBanThreshold int      `json:"panelBanThreshold"`   // 面板防爆破阈值: 连续错几次封 IP, 默认 5(可调, 时长固定 7 天)
	PanelSSLMode      string   `json:"panelSslMode"`        // 面板 SSL: off | port | domain(阶段 4 实现)
	PanelSSLCert      string   `json:"panelSslCert"`        // 面板 SSL 证书 ID(阶段 4 实现)
	PanelSSLPort      int      `json:"panelSslPort"`        // 面板 SSL 端口模式端口, 默认 59188(阶段 4 实现)
	PanelDomain       string   `json:"panelDomain"`         // 面板域名直访域名(阶段 4 实现)
	ServerName        string   `json:"serverName"`          // 服务器名称: TG 通知标题用, 留空则用系统 hostname
	ServerID          string   `json:"serverId"`            // 服务器指纹: 首次启动生成 8 位 hex, 改名不变, 随设置备份走, TG 回调靠它防串台
	RunMode           string   `json:"runMode"`             // 运行模式: ""=未定(首次), standalone=独立用, managed=被主服务器群控
	HubURL            string   `json:"hubUrl"`              // 被群控时主服务器地址
	HubName           string   `json:"hubName"`             // 被群控时主服务器名(批准后回填)
	HubID             string   `json:"hubId"`               // 被群控时主服务器 serverId(批准后回填)
	JoinError         string   `json:"joinError,omitempty"` // 加入失败回退原因: rejected=主服务器拒绝, revoked=曾配对后被移除；加入页据此提示，下次提交时清掉
	NodeTGMode        string   `json:"nodeTgMode"`          // 被群控时 TG 通知模式: ""=走主服务器(默认), independent=独立通知
	ManualLocation    string   `json:"manualLocation"`      // 首页本机卡片手动归属地, 为空则按本机主 IP 自动解析
}

func defaultSettings() Settings {
	return Settings{
		AlertSSHLogin: true, AlertSSHBrute: true, AlertSSHConn: true, AlertPortGuardBan: true, AlertUILogin: true,
		AutoBanEnabled: false, BruteWindowMin: 10, BruteThreshold: 5, BruteBanHours: 24,
		ScanEnabled: false, AlertScan: true, ScanAutoBan: false, ScanWindowMin: 5, ScanDistinctPorts: 5,
		FloodEnabled: false, FloodWindowMin: 1, FloodDistinctIPs: 30, FloodCloseMin: 60,
		ReportEnabled: true, ReportTime: "09:00", LogKeepDays: 30, NewSrcKeepDays: 7,
		TrafficAcct: true, LedgerKeepDays: 7,
		TrustedIPs:        []string{},
		PanelBanThreshold: 5, PanelSSLMode: "off", PanelSSLPort: 59188,
	}
}

var (
	mu       sync.Mutex
	ports    []*PortWatch
	settings = defaultSettings()
	// 被"同步/扫描"忽略的端口(用户删过或忽略过, 不再自动导回)
	ignoredPorts = map[int]bool{}
	// 端口范围(第 7 项)与删过的范围(同步不再导回)
	portRanges    []*PortRange
	ignoredRanges []PortRange
)

func nowMs() int64 { return time.Now().UnixMilli() }

func saveJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, b, 0644)
}

func loadAll() {
	if b, err := os.ReadFile(portsFile); err == nil {
		var wrap struct {
			Ports         []*PortWatch `json:"ports"`
			Ignored       []int        `json:"ignored"`
			Ranges        []*PortRange `json:"ranges"`
			IgnoredRanges []PortRange  `json:"ignoredRanges"`
		}
		if json.Unmarshal(b, &wrap) == nil {
			ports = wrap.Ports
			for _, p := range wrap.Ignored {
				ignoredPorts[p] = true
			}
			portRanges = wrap.Ranges
			ignoredRanges = wrap.IgnoredRanges
		}
	}
	if ports == nil {
		ports = []*PortWatch{}
	}
	if portRanges == nil {
		portRanges = []*PortRange{}
	}
	if ignoredRanges == nil {
		ignoredRanges = []PortRange{}
	}
	rebuildPortIndex()
	settingRaw, settingErr := os.ReadFile(settingFile)
	if settingErr == nil {
		json.Unmarshal(settingRaw, &settings)
	}
	// 旧版设置文件没有洪峰字段(三项全 0): 只补数值默认值, 开关绝不强制写回;
	// 缺字段时开关取默认关, 文件里明确为 true 的保持 true
	if settings.FloodDistinctIPs == 0 && settings.FloodWindowMin == 0 && settings.FloodCloseMin == 0 {
		settings.FloodWindowMin = 1
		settings.FloodDistinctIPs = 30
		settings.FloodCloseMin = 60
	}
	if settings.LogKeepDays < 1 {
		settings.LogKeepDays = 30
	}
	// 新来源保留期是后加的设置: 旧设置文件里没有这个键时给默认 7 天;
	// 用户显式填 0 表示「只计数不记录」, 不能被默认值覆盖
	if settingErr == nil && !strings.Contains(string(settingRaw), "newSrcKeepDays") {
		settings.NewSrcKeepDays = 7
	}
	// 流量统计开关同理: 旧设置文件没有这个键时默认开(开箱即用)
	if settingErr == nil && !strings.Contains(string(settingRaw), "trafficAcct") {
		settings.TrafficAcct = true
	}
	// 流量明细保留期同理: 旧设置没有这个键时默认 7 天; 显式 0 = 永久保留
	if settingErr == nil && !strings.Contains(string(settingRaw), "ledgerKeepDays") {
		settings.LedgerKeepDays = 7
	}
	if settings.TrustedIPs == nil {
		settings.TrustedIPs = []string{}
	}
	loadBans()
	loadPortBans()
	loadStats()
	loadRescue()
	loadAuth()
	migrateRunMode() // 老机器无 runMode 但已有密码 -> 独立, 绝不打回未定
	// 面板防爆破阈值是后加的设置: 旧设置文件里没有这个键时给默认 5;
	// 用户显式填 0 不合法, 按 5 处理(不写回, 避免覆盖用户文件原貌)。
	if settingErr == nil && !strings.Contains(string(settingRaw), "panelBanThreshold") {
		settings.PanelBanThreshold = 5
	}
	if settings.PanelSSLPort == 0 {
		settings.PanelSSLPort = 59188
	}
	// 服务器指纹: 首次启动生成 8 位 hex, 改名不变, 随设置备份走;
	// 回调数据靠它区分多服务器, 缺失时生成并写回(写回失败不影响内存值)。
	if settings.ServerID == "" {
		settings.ServerID = newServerID()
		saveSettings()
	}
	loadHoneypot()
	loadProxy()
	loadPortGuard()
	loadNodeIdentity() // 节点身份(密钥对), 缺失即生成并落盘 0600
	loadServers()      // 主服务器侧节点登记(servers.json)
	loadHomeSeen()     // 首页新设备提醒已确认集合(home-seen.json)
	loadGroupSync()    // 群控共享名单配置(groupsync.json)
	loadProtSync()     // 防护同步“已同步”标记(protsync.json)
}

// newServerID 生成 8 位 hex 服务器指纹(4 字节随机数); 失败时回落时间戳 hex, 绝不返回空。
func newServerID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return hex.EncodeToString([]byte{byte(time.Now().Unix() >> 24), byte(time.Now().Unix() >> 16), byte(time.Now().Unix() >> 8), byte(time.Now().Unix())})
}

// ensurePanelPortSeed: 面板端口默认监控条目(历史遗留, 兼容旧版本与多机同步)。
// 只在启动时补一次：已有单个/范围覆盖面板端口、或用户删过（ignoredPorts）时不补；
// 手动添加的条目一律不动（不改星标、不改名）。种子直写清单，不走 planRangeAdd，
// 因此不受星标自身端口排除影响；手动添加仍走原有排除逻辑不变。
// 换端口跟随（2026-10-27）：种子签名的旧面板条目（名=面板、Kind=ui、
// Source=manual）若端口已不是当前面板端口，随启动迁移到当前端口，
// 换端口后不再残留旧条目、不用手动删；只迁第一个匹配项，其余不动，
// 星标与备注原样保留（只改端口一位）。返回是否补了条目或迁了条目。
func ensurePanelPortSeed() bool {
	p := appPort()
	for _, w := range ports {
		if w != nil && w.Port == p {
			return false
		}
	}
	for _, g := range portRanges {
		if g != nil && p >= g.From && p <= g.To {
			return false
		}
	}
	if ignoredPorts[p] {
		return false
	}
	for _, w := range ports {
		if w != nil && w.Name == "面板" && w.Kind == "ui" && w.Source == "manual" {
			w.Port = p
			savePorts()
			return true
		}
	}
	ports = append(ports, &PortWatch{Port: p, Proto: "tcp", Name: "面板", Star: true, Source: "manual", Kind: "ui"})
	savePorts()
	return true
}

func savePorts() {
	ign := []int{}
	for p := range ignoredPorts {
		ign = append(ign, p)
	}
	sort.Ints(ign)
	saveJSON(portsFile, map[string]any{"ports": ports, "ignored": ign, "ranges": portRanges, "ignoredRanges": ignoredRanges})
	rebuildPortIndex()
}

func saveSettings() { saveJSON(settingFile, settings) }

func findPort(port int) *PortWatch {
	for _, p := range ports {
		if p.Port == port {
			return p
		}
	}
	return nil
}

// stdPrivateCIDRs 信任全部内网 IP 的四段标准私网范围(与旧按钮填入的四段一致)。
var stdPrivateCIDRs = []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fc00::/7"}

var stdPrivateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range stdPrivateCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isStdPrivateIP 是否落在四段标准私网范围(解析失败一律不算)。
func isStdPrivateIP(ip string) bool {
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, n := range stdPrivateNets {
		if n.Contains(pip) {
			return true
		}
	}
	return false
}

func isTrusted(ip string) bool {
	mu.Lock()
	defer mu.Unlock()
	// 信任全部内网 IP(第 6 项): 勾选后标准私网段隐式信任, 列表里有没有都不影响。
	if settings.TrustLAN && isStdPrivateIP(ip) {
		return true
	}
	for _, t := range settings.TrustedIPs {
		if t == ip {
			return true
		}
		// 支持 CIDR
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

// 可否拉黑: 内网/回环/信任名单一律禁止(防把自己锁在门外)
func bannable(ip string) (bool, string) {
	pip := net.ParseIP(ip)
	if pip == nil {
		return false, "IP 格式无效"
	}
	if isPrivateIP(pip) {
		return false, "内网/回环地址不可拉黑"
	}
	// 保留段(100.64/10 CGNAT、198.18/15 基准测试、240/4 未来用、
	// 224/4 组播、ff00::/8 组播等)永远不封禁: 公网不可达的地址不
	// 可能是真实入站来源, 封了只会误伤本机/运营商段。文档段除外
	// (见 isDocRange, 测试固件用)。
	if isReservedIP(pip) {
		return false, "保留地址段不可拉黑"
	}
	if isTrusted(ip) {
		return false, "该 IP 在信任名单中"
	}
	return true, ""
}

// ---------- HTTP 基础 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	writeJSON(w, 200, map[string]string{"version": appVersion})
}

// 面板监听端口: main() 里由 GUIJIA_PORT 解析后填入; 未经 main()
// (如单测)时 appPort() 再读环境变量回落, 默认 59188。
var panelPort int

// initPaths 解析数据目录并布好全部数据文件路径(CLI 与服务端共用)。
func initPaths() {
	dataDir = os.Getenv("GUIJIA_DATA_DIR")
	if dataDir == "" {
		dataDir = "/var/lib/guijia"
	}
	if v := os.Getenv("GUIJIA_CONNTRACK"); v != "" {
		ctPath = v
	}
	portsFile = filepath.Join(dataDir, "ports.json")
	bansFile = filepath.Join(dataDir, "bans.json")
	portBansFile = filepath.Join(dataDir, "portbans.json")
	settingFile = filepath.Join(dataDir, "settings.json")
	statsFile = filepath.Join(dataDir, "stats.json")
	eventsDir = filepath.Join(dataDir, "events")
	eventsSrcDir = filepath.Join(dataDir, "events-src")
	geoV6Path = filepath.Join(dataDir, "ip2region_v6.xdb")
	geoV4Path = filepath.Join(dataDir, "ip2region.xdb")
	rescueFile = filepath.Join(dataDir, "rescue.json")
	honeypotFile = filepath.Join(dataDir, "honeypot.json")
	proxyFile = filepath.Join(dataDir, "proxy.json")
	authFile = filepath.Join(dataDir, "auth.json")
	nodeFile = filepath.Join(dataDir, "node.json")
	serversFile = filepath.Join(dataDir, "servers.json")
	homeSeenFile = filepath.Join(dataDir, "home-seen.json")
	tgHubQueueFile = filepath.Join(dataDir, "tg-hub-queue.json")
	os.MkdirAll(eventsDir, 0755)
	os.MkdirAll(eventsSrcDir, 0755)
}

// saveOnExit 退出前落盘：流量账本、流量开关恢复、每日统计。统计平时每分钟
// 才落盘一次，退出时不存会丢最后一分钟增量，而封禁记录是立即落盘——两者对不上。
func saveOnExit() {
	ledgerSaveNow()
	restoreTrafficAcct()
	saveStats()
}

func main() {
	initPaths()
	// 看门狗提前分发: 它只用 marker 文件参数, 不依赖面板数据; 若先走 loadAll,
	// systemd 瞬时 service 的干净环境会让它在默认数据目录里建一堆无关文件。
	if len(os.Args) > 1 && os.Args[1] == "upgrade-watch" {
		mp := ""
		if len(os.Args) > 2 {
			mp = os.Args[2]
		}
		os.Exit(cliUpgradeWatch(mp))
	}
	panelPort = 59188
	if v := os.Getenv("GUIJIA_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 65535 {
			panelPort = n
		}
	}
	loadAll()
	upgradeReconcileOnStart() // 上次升级留下的 marker: 新鲜等看门狗, 陈旧按当前版定 done/failed
	recalibrateTodayStats()   // 启动用当日事件文件重算今日封禁数与蜜罐命中（见 events.go）
	ensurePanelPortSeed()     // 面板端口默认进清单且加星（启动补一次，用户删过的不再补）
	if tgConfigured() {
		go tgRegisterCommands() // 已绑定 TG 时启动注册一次命令菜单, 失败只记日志不卡启动
	}
	// 本地命令行急救: 在起任何监听之前分发, 只读写数据目录文件。
	if len(os.Args) > 1 {
		os.Exit(cliMain(os.Args[1:]))
	}
	if !geoLoadV4File(geoV4Path) {
		geoLoadV4Embedded() // 数据目录无下载文件时用内嵌库
	}
	geoLoadV6(geoV6Path) // IPv6 库默认不下载, 已有文件则加载, 缺失由设置页手动下载
	banInit()
	intelInit()                        // 威胁情报: 开启则用缓存恢复集合并起定时循环, 关闭则清空集合
	nginxHealTempEdits()               // 上次 nginx 临时改写未清理(崩溃): 启动先还原, 只记日志不卡启动
	honeypotStartAll()                 // 蜜罐监听(冲突端口跳过+报警, 不卡启动)
	proxyApply()                       // 反代监听(绑定失败只记错误, 不卡启动)
	go proxyHealthLoop()               // 反代后端可达复测(60 秒, 仅内存)
	rescueCheckAutoRestore(time.Now()) // 上次急救模式到期未恢复: 启动即按快照恢复
	acctStatePath = filepath.Join(dataDir, "acct-state.json")
	syncTrafficAcct() // 每连接流量统计: 应用自己打开内核字节计数(装上就能用, 不用任何人改系统)
	ledgerInit(dataDir)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		saveOnExit() // 退出前把账本、统计落盘并恢复流量开关
		os.Exit(0)
	}()
	go trafficLoop()       // 物理网卡实时流量采样(2 秒)
	go ledgerLoop()        // 流量账本采样(2 秒): 断续连接的总量持续累加, 不随流消亡丢失
	go collectLoop()       // 连接采样 + 监听快照 + 日志尾随
	go housekeepLoop()     // nft 看门狗 + 事件清理
	go tgLoop()            // TG 报警发送与机器人轮询
	go reportLoop()        // TG 日报
	startGroupSyncTicker() // 群控共享名单后台同步(仅已开启的组)
	if effectiveRunMode() == "managed" {
		startLinkLoop()   // 被群控节点: 拨号器连主服务器(CLI 模式已在前面退出, 不会误起)
		ensureHubSender() // 事件上报主服务器的发送循环(主服务器挂了本地攒着)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if useManagedPage() {
			w.Write(managedHTML) // 已配对成功: 只读状态页, 只有一行大字
			return
		}
		w.Write(indexHTML)
	})
	mux.HandleFunc("/api/overview", handleOverview)
	mux.HandleFunc("/api/connections", handleConnections)
	mux.HandleFunc("/api/ports", handlePorts)
	mux.HandleFunc("/api/ports/", handlePortItem)
	mux.HandleFunc("/api/ports/range/star", handleRangeStar)
	mux.HandleFunc("/api/ports/scan", handlePortScan)
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/bans", handleBans)
	mux.HandleFunc("/api/bans/", handleBanItem)
	mux.HandleFunc("/api/portbans/", handlePortBanItem)
	mux.HandleFunc("/api/portguard", handlePortGuard)
	mux.HandleFunc("/api/portguard/", handlePortGuardItem)
	mux.HandleFunc("/api/geo/regions", handleGeoRegions)
	mux.HandleFunc("/api/geo/countries", handleGeoCountries)
	mux.HandleFunc("/api/geo/cities", handleGeoCities)
	mux.HandleFunc("/api/geo/check/status", handleGeoCheckStatus)
	mux.HandleFunc("/api/settings", handleSettings)
	mux.HandleFunc("/api/data/clear", handleDataClear)
	mux.HandleFunc("/api/geo/download", handleGeoDownload)
	mux.HandleFunc("/api/geo/check", handleGeoCheck)
	mux.HandleFunc("/api/geo", handleGeoLookup)
	mux.HandleFunc("/api/trust", handleTrust)
	mux.HandleFunc("/api/tg/test", handleTGTest)
	mux.HandleFunc("/api/tg/mode", handleNodeTGMode)
	mux.HandleFunc("/api/tg/mode/test", handleNodeTGModeTest)
	mux.HandleFunc("/api/rescue/password", handleRescuePassword)
	mux.HandleFunc("/api/rescue/status", handleRescueStatus)
	mux.HandleFunc("/api/rescue/restore", handleRescueRestore)
	mux.HandleFunc("/api/rescue/trust-node", handleRescueNodeTrust)
	mux.HandleFunc("/api/rescue/unban-node", handleRescueNodeUnbanAll)
	mux.HandleFunc("/api/rescue/kill-node", handleRescueNodeKill)
	mux.HandleFunc("/api/rescue/restore-node", handleRescueNodeRestore)
	mux.HandleFunc("/api/honeypot", handleHoneypot)
	mux.HandleFunc("/api/backup/settings", handleBackupSettings)
	mux.HandleFunc("/api/backup/data", handleBackupData)
	mux.HandleFunc("/api/backup/restore/settings", handleBackupRestoreSettings)
	mux.HandleFunc("/api/backup/restore/data", handleBackupRestoreData)
	mux.HandleFunc("/api/defaultports", handleDefaultPorts)
	mux.HandleFunc("/api/auth/status", handleAuthStatus)
	mux.HandleFunc("/api/auth/setup", handleAuthSetup)
	mux.HandleFunc("/api/auth/login", handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", handleAuthLogout)
	mux.HandleFunc("/api/auth/sessions", handleAuthSessions)
	mux.HandleFunc("/api/auth/password", handleAuthPassword)
	mux.HandleFunc("/api/auth/totp/setup", handleAuthTOTPSetup)
	mux.HandleFunc("/api/auth/totp/enable", handleAuthTOTPEnable)
	mux.HandleFunc("/api/auth/totp/disable", handleAuthTOTPDisable)
	mux.HandleFunc("/api/auth/totp/verify", handleAuthTOTPVerify)
	mux.HandleFunc("/api/setup/mode", handleSetupMode)
	mux.HandleFunc("/api/setup/join-hub", handleSetupJoinHub)
	mux.HandleFunc("/api/node/status", handleNodeStatus)
	mux.HandleFunc("/api/nodes/pairing-code", handlePairingCode)
	mux.HandleFunc("/api/nodes/servers", handleNodeServers)
	mux.HandleFunc("/api/nodes/home-alerts", handleNodeHomeAlerts)
	mux.HandleFunc("/api/nodes/home-ack", handleNodeHomeAck)
	mux.HandleFunc("/api/nodes/approve", handleNodeApprove)
	mux.HandleFunc("/api/nodes/reject", handleNodeReject)
	mux.HandleFunc("/api/nodes/remove", handleNodeRemove)
	mux.HandleFunc("/api/nodes/location", handleNodeLocation)
	mux.HandleFunc("/api/nodes/upgrade-push-status", handleNodeUpgradePushStatus)
	mux.HandleFunc("/api/nodes/backup-download", handleNodeBackupDownload)
	mux.HandleFunc("/api/nodes/tg-test", handleNodeTGTest)
	mux.HandleFunc("/api/group-sync/settings", handleGroupSyncSettings)
	mux.HandleFunc("/api/group-sync/now", handleGroupSyncNow)
	mux.HandleFunc("/api/backup/export", handleBackupExport)
	mux.HandleFunc("/api/sync/apply-lists", handleSyncApplyLists)
	mux.HandleFunc("/api/sync/apply-protection", handleSyncApplyProtection)
	mux.HandleFunc("/api/sync/shared-state", handleSyncSharedState)
	mux.HandleFunc("/api/sync/full-bans", handleSyncFullBans)
	mux.HandleFunc("/api/local-info", handleLocalInfo)
	mux.HandleFunc("/api/nodes/hello", linkLimit(handleNodeHello))
	mux.HandleFunc("/api/nodes/challenge", linkLimit(handleNodeChallenge))
	mux.HandleFunc("/api/nodes/auth", linkLimit(handleNodeAuth))
	mux.HandleFunc("/api/nodes/ping", linkLimit(handleNodePing))
	mux.HandleFunc("/api/nodes/poll", linkLimit(handleNodePoll))
	mux.HandleFunc("/api/nodes/result", linkLimit(handleNodeResult))
	mux.HandleFunc("/api/nodes/proxy", handleNodeProxy)
	mux.HandleFunc("/api/nodes/events", linkLimit(handleNodeEvents))
	mux.HandleFunc("/api/certs/acme/apply", handleAcmeApply)
	mux.HandleFunc("/api/certs/acme/status", handleAcmeStatus)
	mux.HandleFunc("/api/certs/cf-token", handleCFToken)
	mux.HandleFunc("/api/intel", handleIntelStatus)
	mux.HandleFunc("/api/intel/save", handleIntelSave)
	mux.HandleFunc("/api/intel/refresh", handleIntelRefresh)
	mux.HandleFunc("/api/nginx-acme/status", handleNginxAcmeStatus)
	mux.HandleFunc("/api/nginx-acme/ensure", handleNginxAcmeEnsure)
	mux.HandleFunc("/api/panel/port", handlePanelPort)
	mux.HandleFunc("/api/version", handleVersion)
	mux.HandleFunc("/api/upgrade/check", handleUpgradeCheck)
	mux.HandleFunc("/api/upgrade/apply", handleUpgradeApply)
	mux.HandleFunc("/api/upgrade/status", handleUpgradeStatus)
	mux.HandleFunc("/api/nodes/upgrade-all", handleNodeUpgradeAll)
	mux.HandleFunc("/api/proxy", handleProxy)
	mux.HandleFunc("/api/proxy/retry", handleProxyRetry)
	mux.HandleFunc("/api/proxy/certs/upload", handleProxyCertUpload)
	mux.HandleFunc("/api/proxy/certs/refresh", handleProxyCertRefresh)
	mux.HandleFunc("/api/proxy/certs/", handleProxyCertItem)

	// 前置 80 服务(ACME HTTP-01 验证用; 绑定失败不致命, 申请时再报错)。
	startFront80()
	// 前置重试: 80/443 启动时被占, 占用释放后定期自动接管, 无需重启。
	go frontRetryLoop()
	go acmeRenewalLoop()
	// 通用版只走 TCP 监听(不再有 socket/桌面代理模式)。
	// 面板 HTML 外壳公开, 全部 /api/* 走登录鉴权中间件。
	rootMux = mux
	startPanelServer()
	fmt.Printf("guijia listening on http://0.0.0.0:%d, data=%s\n", panelPort, dataDir)
	select {} // 面板监听在后台 goroutine, 主 goroutine 阻塞等待
}
