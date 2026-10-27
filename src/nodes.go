package main

// 多服务器: 运行模式与节点身份(第一期)。
// - 运行模式: ""=未定(首次), "standalone"=独立用, "managed"=被主服务器群控。
// - 老机器升级保护: 设置文件里没有 runMode 但已有本地密码时, 一律视为独立,
//   绝不能把正在跑的 Oracle 这类老机器打回"未定"锁在门外。
// - 节点身份: ed25519 密钥对, 私钥落盘 node.json(0600), 指纹 = 公钥 SHA-256 hex,
//   主服务器靠指纹认节点, 换密钥 = 新节点, 须重新配对。
// - 被群控节点的本地面板只剩只读状态页, 管理接口一律 403, 本文件只做状态机
//   与接口; 长连接拨号与主服务器侧登记审批是下一增量。

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- 运行模式 ----------

func effectiveRunMode() string {
	mu.Lock()
	defer mu.Unlock()
	if settings.RunMode != "" {
		return settings.RunMode
	}
	if hasPassword() {
		return "standalone"
	}
	return ""
}

// migrateRunMode: 启动时迁移老设置(无 runMode 但已有密码 -> 独立), 只写一次。
func migrateRunMode() {
	mu.Lock()
	defer mu.Unlock()
	if settings.RunMode == "" && hasPassword() {
		settings.RunMode = "standalone"
		saveSettings()
	}
}

// ---------- 节点身份 ----------

type nodeIdentity struct {
	PrivSeed    string `json:"priv"`                  // ed25519 seed base64, 绝不外泄
	Fingerprint string `json:"fingerprint"`           // 公钥 SHA-256 hex
	PairingCode string `json:"pairingCode,omitempty"` // setup 时填的配对码, 首次 hello 成功即清除
	Token       string `json:"token,omitempty"`       // 主服务器发的长期 token, 只存这里(0600), 绝不进 settings.json
	TGEnabled   bool   `json:"tgEnabled,omitempty"`   // 独立通知开关(仅 managed + 独立模式用)
	TGToken     string `json:"tgToken,omitempty"`     // 独立通知 Bot Token, 只存这里(0600), 绝不进日志与测试
	TGChatID    string `json:"tgChatId,omitempty"`    // 独立通知 Chat ID
}

var (
	nodeMu    sync.Mutex
	nodeIdent *nodeIdentity
)

func loadNodeIdentity() {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if b, err := os.ReadFile(nodeFile); err == nil {
		var id nodeIdentity
		if json.Unmarshal(b, &id) == nil {
			if seed, err := base64.StdEncoding.DecodeString(id.PrivSeed); err == nil && len(seed) == ed25519.SeedSize {
				priv := ed25519.NewKeyFromSeed(seed)
				pub := priv.Public().(ed25519.PublicKey)
				sum := sha256.Sum256(pub)
				if id.Fingerprint == hex.EncodeToString(sum[:]) {
					nodeIdent = &id
					return
				}
			}
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	id := &nodeIdentity{
		PrivSeed:    base64.StdEncoding.EncodeToString(priv.Seed()),
		Fingerprint: hex.EncodeToString(sum[:]),
	}
	nodeIdent = id
	saveNodeIdentityLocked()
}

// saveNodeIdentityLocked 调用方须持有 nodeMu, 文件 0600。
func saveNodeIdentityLocked() {
	b, _ := json.MarshalIndent(nodeIdent, "", "  ")
	os.WriteFile(nodeFile, b, 0600)
}

// 节点凭据读写(拨号器与 CLI 共用, nodeMu 保护)。
func nodePrivKey() ed25519.PrivateKey {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return nil
	}
	seed, err := base64.StdEncoding.DecodeString(nodeIdent.PrivSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil
	}
	return ed25519.NewKeyFromSeed(seed)
}

func nodePubKeyB64() string {
	priv := nodePrivKey()
	if priv == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func nodePairingCode() string {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return ""
	}
	return nodeIdent.PairingCode
}

func setNodePairingCode(code string) {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return
	}
	nodeIdent.PairingCode = code
	saveNodeIdentityLocked()
}

func clearNodePairingCode() {
	setNodePairingCode("")
}

func nodeToken() string {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return ""
	}
	return nodeIdent.Token
}

func setNodeToken(tok string) {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return
	}
	nodeIdent.Token = tok
	saveNodeIdentityLocked()
}

func clearNodeToken() {
	setNodeToken("")
}

func nodeFingerprint() string {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return ""
	}
	return nodeIdent.Fingerprint
}

func nodeFingerprintShort() string {
	fp := nodeFingerprint()
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

// ---------- 独立通知凭据(仅 managed + 独立模式用, 存 node.json 0600) ----------

// nodeTGConfig 返回独立通知配置(启用、Token、ChatID)。
func nodeTGConfig() (bool, string, string) {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return false, "", ""
	}
	return nodeIdent.TGEnabled, nodeIdent.TGToken, nodeIdent.TGChatID
}

func setNodeTGConfig(enabled bool, token, chatID string) {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	if nodeIdent == nil {
		return
	}
	nodeIdent.TGEnabled, nodeIdent.TGToken, nodeIdent.TGChatID = enabled, token, chatID
	saveNodeIdentityLocked()
}

// nodeTGMode 节点 TG 通知模式: 仅 managed 有意义; ""(默认)=走主服务器,
// "independent"=独立通知。standalone 返回 ""(走本机原有 TG 配置)。
func nodeTGMode() string {
	if effectiveRunMode() != "managed" {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	if settings.NodeTGMode == "independent" {
		return "independent"
	}
	return "hub"
}

// ---------- 与主服务器的链路状态(内存态, 拨号器维护) ----------

var (
	linkMu          sync.Mutex
	linkState       = "idle" // idle | joining | pending | connected | disconnected
	linkLastContact int64
	linkLastError   string
)

func setLinkState(s, errMsg string) {
	linkMu.Lock()
	defer linkMu.Unlock()
	linkState = s
	linkLastError = errMsg
	if s == "connected" {
		linkLastContact = time.Now().Unix()
	}
}

func linkSnapshot() (string, int64, string) {
	linkMu.Lock()
	defer linkMu.Unlock()
	return linkState, linkLastContact, linkLastError
}

// ---------- 显示名 ----------

func nodeDisplayName() string {
	mu.Lock()
	defer mu.Unlock()
	if settings.ServerName != "" {
		return settings.ServerName
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "guijia"
}

// ---------- 接口 ----------

// handleSetupMode 首次运行模式二选一(公开接口, 未登录时就要能选)。
// GET: 当前模式与选择状态; POST: 只能选一次, 选定后 403。
func handleSetupMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		mu.Lock()
		hubURL, hubName := settings.HubURL, settings.HubName
		mu.Unlock()
		st, last, _ := linkSnapshot()
		writeJSON(w, 200, map[string]any{
			"runMode":       effectiveRunMode(),
			"decided":       effectiveRunMode() != "",
			"setupRequired": !hasPassword() && effectiveRunMode() != "managed",
			"hubUrl":        hubURL,
			"hubName":       hubName,
			"linkState":     st,
			"lastContact":   last,
		})
		return
	}
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if effectiveRunMode() != "" {
		errJSON(w, 403, "运行模式已确定")
		return
	}
	var in struct {
		Mode   string `json:"mode"`
		HubURL string `json:"hubUrl"`
		Code   string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	switch in.Mode {
	case "standalone":
		mu.Lock()
		settings.RunMode = "standalone"
		saveSettings()
		mu.Unlock()
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "managed":
		hubURL := strings.TrimSpace(in.HubURL)
		code := strings.TrimSpace(in.Code)
		if hubURL == "" || code == "" {
			errJSON(w, 400, "主服务器地址与配对码不能为空")
			return
		}
		if len(hubURL) > 512 || len(code) > 128 {
			errJSON(w, 400, "地址或配对码过长")
			return
		}
		u, err := url.Parse(hubURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errJSON(w, 400, "主服务器地址无效, 须为 http(s) 地址")
			return
		}
		hubURL = strings.TrimRight(hubURL, "/")
		mu.Lock()
		settings.RunMode = "managed"
		settings.HubURL = hubURL
		settings.HubName = ""
		settings.HubID = ""
		saveSettings()
		mu.Unlock()
		setNodePairingCode(code) // 配对码落 node.json(0600), 供拨号器使用
		setLinkState("joining", "")
		startLinkLoop() // 本进程内立即起拨号器, 不等重启
		writeJSON(w, 200, map[string]any{"ok": true, "linkState": "joining"})
	default:
		errJSON(w, 400, "mode 须为 standalone 或 managed")
	}
}

// handleNodeStatus 被群控节点的只读状态页数据(公开接口, 无管理操作)。
func handleNodeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	mu.Lock()
	hubURL, hubName := settings.HubURL, settings.HubName
	mu.Unlock()
	st, last, lastErr := linkSnapshot()
	writeJSON(w, 200, map[string]any{
		"runMode":     effectiveRunMode(),
		"serverName":  nodeDisplayName(),
		"serverId":    settings.ServerID,
		"fingerprint": nodeFingerprintShort(),
		"hubName":     hubName,
		"hubUrl":      hubURL,
		"engine":      "running",
		"linkState":   st,
		"lastContact": last,
		"lastError":   lastErr,
		"version":     appVersion,
	})
}
