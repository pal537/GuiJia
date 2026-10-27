package main

// 急救方案(第 2 项): TG 超级密码 + 急救菜单, 分三层。
//   第 0 层 内网永不封: 已由 bannable()/洪峰规则保证(内网/回环一律不可拉黑),
//     这里不再重复实现, 只在文档与 TG 文案里写明。
//   第 1 层 TG 急救菜单: /rescue 打开, 信任 IP / 解封全部 / 关闭所有拦截 / 恢复防护。
//     破坏性动作(解封全部、关闭所有拦截)必须输对超级密码; 日常一键拉黑、单个
//     解封不走密码。密码只存 PBKDF2 哈希, 绝不存明文。
//   第 2 层 本地 SSH/CLI 兜底: 应用挂了时 TG 也救不了, 只能 SSH 上去改 bans.json
//     或清 nft 规则(已有手动路径, 这里不另写 CLI)。
// 关闭所有拦截 = 释放全部生效封禁 + 关掉全部自动拦截开关 + 快照, 30 分钟后
// 自动按快照恢复; 监控与报警不停。快照与锁定状态落盘(data/rescue.json),
// 应用重启后急救模式与锁定不丢失。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	rescuePBKDF2Iter = 100000
	rescuePassMinLen = 6
	rescueLockFails  = 5
	rescueLockMin    = 30
	rescueKillMin    = 30
	rescuePendingMin = 10
)

var (
	rescueMu sync.Mutex
	rescueSt RescueState
)

// ProtectionSnapshot 关闭拦截前拍的开关快照, 恢复时原样还原。
// 扫描/蜜罐的自动拉黑开关在第 5/6 项接入时补进快照(见 captureProtectionSnapshot)。
type ProtectionSnapshot struct {
	AutoBanEnabled  bool `json:"autoBanEnabled"`
	FloodEnabled    bool `json:"floodEnabled"`
	ScanAutoBan     bool `json:"scanAutoBan"`     // 第 5 项补: 扫描自动拉黑开关也要快照
	HoneypotAutoBan bool `json:"honeypotAutoBan"` // 第 6 项补: 蜜罐自动拉黑开关也要快照
}

type RescueState struct {
	KillActive  bool                `json:"killActive"`
	KillUntil   int64               `json:"killUntil"`
	Snapshot    *ProtectionSnapshot `json:"snapshot,omitempty"`
	FailCount   int                 `json:"failCount"`
	LockedUntil int64               `json:"lockedUntil"`
}

func loadRescue() {
	if b, err := os.ReadFile(rescueFile); err == nil {
		json.Unmarshal(b, &rescueSt)
	}
}

func saveRescue() {
	b, _ := json.MarshalIndent(rescueSt, "", "  ")
	os.WriteFile(rescueFile, b, 0644)
}

// ---------- 超级密码哈希(PBKDF2-HMAC-SHA256, 仅标准库) ----------

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// hashRescuePassword 生成存储串: pbkdf2-sha256$迭代$saltB64$hashB64
func hashRescuePassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := pbkdf2SHA256([]byte(pw), salt, rescuePBKDF2Iter, 32)
	return "pbkdf2-sha256$" + itoa(rescuePBKDF2Iter) + "$" +
		base64.StdEncoding.EncodeToString(salt) + "$" +
		base64.StdEncoding.EncodeToString(sum), nil
}

func verifyRescuePassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[2])
	want, err2 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(pw), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---------- 锁定(输错 5 次锁定 30 分钟并报警) ----------

// rescueNoteFailure 记录一次密码错误; 返回是否刚触发锁定(调用方据此报警)。
// now 由调用方传入, 便于测试。
func rescueNoteFailure(now time.Time) bool {
	rescueMu.Lock()
	defer rescueMu.Unlock()
	rescueSt.FailCount++
	if rescueSt.FailCount >= rescueLockFails {
		rescueSt.FailCount = 0
		rescueSt.LockedUntil = now.Add(rescueLockMin * time.Minute).Unix()
		saveRescue()
		return true
	}
	saveRescue()
	return false
}

func rescueResetFailures() {
	rescueMu.Lock()
	defer rescueMu.Unlock()
	rescueSt.FailCount = 0
	saveRescue()
}

// rescueLockedUntil 返回当前锁定截止(0=未锁定)。
func rescueLockedUntil() int64 {
	rescueMu.Lock()
	defer rescueMu.Unlock()
	return rescueSt.LockedUntil
}

// ---------- 关闭拦截 / 恢复 ----------

func captureProtectionSnapshot() *ProtectionSnapshot {
	mu.Lock()
	defer mu.Unlock()
	return &ProtectionSnapshot{
		AutoBanEnabled: settings.AutoBanEnabled,
		FloodEnabled:   settings.FloodEnabled,
		ScanAutoBan:    settings.ScanAutoBan,
		HoneypotAutoBan: func() bool {
			honeypotMu.Lock()
			defer honeypotMu.Unlock()
			return honeypotCfg.AutoBan
		}(),
	}
}

func applyProtectionSnapshot(s *ProtectionSnapshot) {
	if s == nil {
		return
	}
	mu.Lock()
	settings.AutoBanEnabled = s.AutoBanEnabled
	settings.FloodEnabled = s.FloodEnabled
	settings.ScanAutoBan = s.ScanAutoBan
	mu.Unlock()
	honeypotMu.Lock()
	honeypotCfg.AutoBan = s.HoneypotAutoBan
	honeypotMu.Unlock()
	saveSettings()
	saveHoneypot()
}

// rescueUnbanAll 解封全部生效中的封禁(只改状态为 released, 记录一条不删),
// 并重开全部洪峰临时关闭的端口。返回解封的 IP 数。
func rescueUnbanAll() int {
	n := 0
	for _, b := range activeBans() {
		if releaseBan(b.IP) {
			n++
		}
	}
	for _, pb := range activePortBans() {
		reopenPort(pb.Port)
	}
	return n
}

// rescueActivateKill 关闭所有拦截: 快照 -> 解封全部 -> 关开关 -> 落盘急救状态。
func rescueActivateKill(now time.Time) {
	snap := captureProtectionSnapshot()
	rescueUnbanAll()
	mu.Lock()
	settings.AutoBanEnabled = false
	settings.FloodEnabled = false
	settings.ScanAutoBan = false
	mu.Unlock()
	saveSettings()
	honeypotMu.Lock()
	honeypotCfg.AutoBan = false
	honeypotMu.Unlock()
	saveHoneypot()
	rescueMu.Lock()
	rescueSt.KillActive = true
	rescueSt.KillUntil = now.Add(rescueKillMin * time.Minute).Unix()
	rescueSt.Snapshot = snap
	saveRescue()
	rescueMu.Unlock()
	pushEvent(Event{Type: "rescue", Detail: "急救：关闭所有拦截（监控与报警不停，30 分钟后自动恢复防护）"})
}

// rescueRestore 按快照恢复防护并清除急救状态。未处于急救模式返回 false。
func rescueRestore() bool {
	rescueMu.Lock()
	active := rescueSt.KillActive
	snap := rescueSt.Snapshot
	rescueSt.KillActive = false
	rescueSt.KillUntil = 0
	rescueSt.Snapshot = nil
	saveRescue()
	rescueMu.Unlock()
	if !active {
		return false
	}
	applyProtectionSnapshot(snap)
	pushEvent(Event{Type: "rescue", Detail: "急救：已按快照恢复防护"})
	return true
}

// rescueCheckAutoRestore 急救模式到期自动恢复(housekeep 每分钟 + 启动时各跑一次)。
// 返回是否执行了恢复(执行时附带 TG 提醒, 因为这不是用户当面操作)。
func rescueCheckAutoRestore(now time.Time) bool {
	rescueMu.Lock()
	active := rescueSt.KillActive
	until := rescueSt.KillUntil
	rescueMu.Unlock()
	if !active || now.Unix() < until {
		return false
	}
	if rescueRestore() {
		emit(Event{Type: "rescue", Detail: "急救：30 分钟已到，已自动恢复防护"}, true)
		return true
	}
	return false
}

// ---------- 信任名单(供 TG 与网页共用) ----------

func trustIP(ip string) (already bool, err error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return false, fmt.Errorf("IP 格式无效")
	}
	if isTrusted(ip) {
		return true, nil
	}
	mu.Lock()
	settings.TrustedIPs = append(settings.TrustedIPs, ip)
	mu.Unlock()
	saveSettings()
	syncTrustedSets() // 信任增删立即进内核, 链首放行即刻生效
	return false, nil
}
