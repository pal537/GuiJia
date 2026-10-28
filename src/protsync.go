package main

// 防护同步(2026-10-28, PAPA 定): 首页群控设置里新增“防护同步”组,
// 勾选哪项、哪项就跟主服务器走, 主服务器配置为准、节点本地不可改:
//   flood   重点端口洪峰防护(FloodEnabled + 窗口/不同 IP 数/关闭分钟)
//   autoban 爆破自动拉黑(AutoBanEnabled + 窗口/阈值/递进时长)
//   scan    扫描识别(ScanEnabled + 扫描自动拉黑 + 窗口/端口数)
//   intel   威胁情报(Enabled + 名单直链 + 每天更新次数)
// 不同步的留本地: 报警开关(如扫描报警)、蜜罐、防火墙规则、端口清单——
// PAPA 只点了这四项, 绝不打包相邻项。
// 节点侧“已同步”标记存 protsync.json(0600, 不进 settings.json):
// 主服务器每次推全量四项状态(勾选的带配置、未勾选的只带 synced=false),
// 节点按收到状态原样落标记, 故主服务器取消勾选/关闭整组时节点自动恢复
// 本地可改, 不靠“下次同步”自愈; 脱离(rollbackJoin)时标记清掉。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type protSyncFlags struct {
	Flood   bool `json:"flood"`
	Autoban bool `json:"autoban"`
	Scan    bool `json:"scan"`
	Intel   bool `json:"intel"`
}

var (
	protSyncMu    sync.Mutex
	protSyncState protSyncFlags
)

func protSyncFilePath() string {
	if dataDir == "" {
		return "protsync.json"
	}
	return filepath.Join(dataDir, "protsync.json")
}

func loadProtSync() {
	protSyncMu.Lock()
	defer protSyncMu.Unlock()
	protSyncState = protSyncFlags{}
	if b, err := os.ReadFile(protSyncFilePath()); err == nil {
		_ = json.Unmarshal(b, &protSyncState)
	}
}

func saveProtSyncLocked() {
	b, _ := json.MarshalIndent(protSyncState, "", "  ")
	os.WriteFile(protSyncFilePath(), b, 0600)
}

func protSyncSnapshot() protSyncFlags {
	protSyncMu.Lock()
	defer protSyncMu.Unlock()
	return protSyncState
}

// clearProtSync 脱离群控时清掉“已同步”标记, 本地恢复可改(配置值不动,
// 只恢复控制权; 下次再被群控、主服务器再推时重新标记)。
func clearProtSync() {
	protSyncMu.Lock()
	protSyncState = protSyncFlags{}
	saveProtSyncLocked()
	protSyncMu.Unlock()
}

// ---------- 同步 payload(主服务器 → 节点) ----------

type protFloodCfg struct {
	Synced      bool `json:"synced"`
	Enabled     bool `json:"enabled"`
	WindowMin   int  `json:"windowMin"`
	DistinctIPs int  `json:"distinctIps"`
	CloseMin    int  `json:"closeMin"`
}

type protAutobanCfg struct {
	Synced    bool `json:"synced"`
	Enabled   bool `json:"enabled"`
	WindowMin int  `json:"windowMin"`
	Threshold int  `json:"threshold"`
	BanHours  int  `json:"banHours"`
}

type protScanCfg struct {
	Synced        bool `json:"synced"`
	Enabled       bool `json:"enabled"`
	AutoBan       bool `json:"autoBan"`
	WindowMin     int  `json:"windowMin"`
	DistinctPorts int  `json:"distinctPorts"`
}

type protIntelCfg struct {
	Synced        bool   `json:"synced"`
	Enabled       bool   `json:"enabled"`
	PublicURL     string `json:"publicUrl"`
	UpdatesPerDay int    `json:"updatesPerDay"`
}

type protSyncPayload struct {
	Flood   protFloodCfg   `json:"flood"`
	Autoban protAutobanCfg `json:"autoban"`
	Scan    protScanCfg    `json:"scan"`
	Intel   protIntelCfg   `json:"intel"`
}

// protSyncPayloadForHub 按群控勾选项构造: 勾选的带主服务器当前配置,
// 未勾选的只带 synced=false(节点收到即恢复本地可改)。
func protSyncPayloadForHub(items protSyncItems) protSyncPayload {
	mu.Lock()
	s := settings
	mu.Unlock()
	intelMu.Lock()
	ist := intelState
	intelMu.Unlock()
	p := protSyncPayload{}
	if items.Flood {
		p.Flood = protFloodCfg{Synced: true, Enabled: s.FloodEnabled, WindowMin: s.FloodWindowMin, DistinctIPs: s.FloodDistinctIPs, CloseMin: s.FloodCloseMin}
	}
	if items.Autoban {
		p.Autoban = protAutobanCfg{Synced: true, Enabled: s.AutoBanEnabled, WindowMin: s.BruteWindowMin, Threshold: s.BruteThreshold, BanHours: s.BruteBanHours}
	}
	if items.Scan {
		p.Scan = protScanCfg{Synced: true, Enabled: s.ScanEnabled, AutoBan: s.ScanAutoBan, WindowMin: s.ScanWindowMin, DistinctPorts: s.ScanDistinctPorts}
	}
	if items.Intel {
		p.Intel = protIntelCfg{Synced: true, Enabled: ist.Enabled, PublicURL: ist.PublicURL, UpdatesPerDay: ist.UpdatesPerDay}
	}
	return p
}

// protSyncReleasePayload 整组关闭/全部取消勾选时推的释放包: 四项全 synced=false。
func protSyncReleasePayload() protSyncPayload {
	return protSyncPayload{}
}

// applyProtSyncPayload 节点侧落地: 只应用 synced=true 的项, 四项标记按收到状态原样落盘。
// 返回实际应用的项名; 情报项复用保存逻辑的副作用(新开立即拉取、关闭立即清集)。
func applyProtSyncPayload(p protSyncPayload) []string {
	applied := []string{}
	mu.Lock()
	if p.Flood.Synced {
		settings.FloodEnabled = p.Flood.Enabled
		settings.FloodWindowMin = p.Flood.WindowMin
		settings.FloodDistinctIPs = p.Flood.DistinctIPs
		settings.FloodCloseMin = p.Flood.CloseMin
		applied = append(applied, "flood")
	}
	if p.Autoban.Synced {
		settings.AutoBanEnabled = p.Autoban.Enabled
		settings.BruteWindowMin = p.Autoban.WindowMin
		settings.BruteThreshold = p.Autoban.Threshold
		settings.BruteBanHours = p.Autoban.BanHours
		applied = append(applied, "autoban")
	}
	if p.Scan.Synced {
		settings.ScanEnabled = p.Scan.Enabled
		settings.ScanAutoBan = p.Scan.AutoBan
		settings.ScanWindowMin = p.Scan.WindowMin
		settings.ScanDistinctPorts = p.Scan.DistinctPorts
		applied = append(applied, "scan")
	}
	mu.Unlock()
	if len(applied) > 0 {
		saveSettings()
	}
	if p.Intel.Synced {
		if err := applyIntelSync(p.Intel); err == nil {
			applied = append(applied, "intel")
		}
	}
	protSyncMu.Lock()
	protSyncState = protSyncFlags{Flood: p.Flood.Synced, Autoban: p.Autoban.Synced, Scan: p.Scan.Synced, Intel: p.Intel.Synced}
	saveProtSyncLocked()
	protSyncMu.Unlock()
	return applied
}

// applyIntelSync 情报项落地: 与 handleIntelSave 同副作用, 但不经过网页保存入口。
// URL 非法时整项跳过(返回错, 标记仍按 synced 落——主服务器侧 URL 已校验过,
// 这里是防脏数据的第二道, 跳过不阻塞其余三项)。
func applyIntelSync(c protIntelCfg) error {
	url := strings.TrimSpace(c.PublicURL)
	if url == "" {
		url = intelDefaultPublicURL
	}
	upd := c.UpdatesPerDay
	if upd < 1 || upd > 24 {
		upd = 4
	}
	if c.Enabled {
		if err := validateIntelInput(url); err != nil {
			return err
		}
	}
	intelMu.Lock()
	wasEnabled := intelState.Enabled
	intelState.Enabled = c.Enabled
	intelState.PublicURL = url
	intelState.UpdatesPerDay = upd
	if c.Enabled {
		intelState.NextFetchUnix = time.Now().Unix()
	}
	intelSaveState()
	intelMu.Unlock()
	if !c.Enabled {
		intelFlushSets()
	} else if !wasEnabled {
		go intelRefreshNow()
	}
	intelWakeUp()
	return nil
}

// ---------- 主服务器扇出 ----------

var protSyncResultWait = 30 * time.Second

// syncProtectionToNode 推防护状态给一台节点(内部命令通道)。
func syncProtectionToNode(fp string, p protSyncPayload) (bool, string) {
	bb, _ := json.Marshal(p)
	status, respBody, errKind := hubCallNodeInternalTimeout(fp, "POST", "api/sync/apply-protection", bb, true, protSyncResultWait)
	if errKind != "" {
		return false, proxyErrMessage(fp, errKind)
	}
	if status < 200 || status >= 300 {
		return false, "节点返回 " + itoa(status)
	}
	var v struct {
		Applied []string `json:"applied"`
	}
	_ = json.Unmarshal(respBody, &v)
	if len(v.Applied) == 0 {
		return true, "已同步（本轮无勾选项，节点恢复本地控制）"
	}
	return true, "已同步：" + strings.Join(v.Applied, "、")
}

// syncProtectionToAllOnline 推给全部在线节点, 返回(成功数, 总数, 明细)。
// enabled=false 时推释放包(节点恢复本地控制), 不跳过——关闭整组也要通知到节点。
func syncProtectionToAllOnline(enabled bool, items protSyncItems) (int, int, string) {
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
	var p protSyncPayload
	if enabled {
		p = protSyncPayloadForHub(items)
	} else {
		p = protSyncReleasePayload()
	}
	ok, details := 0, []string{}
	for _, fp := range fps {
		if good, d := syncProtectionToNode(fp, p); good {
			ok++
			details = append(details, names[fp]+"："+d)
		} else {
			details = append(details, names[fp]+"：失败("+d+")")
		}
	}
	return ok, len(fps), strings.Join(details, "；")
}
