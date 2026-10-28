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
	"errors"
	"fmt"
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

// useManagedPage 群控状态页只给已配对成功（持有 token）的节点；
// managed 但无 token（正在等确认、或已被回退途中）一律走加入页，绝不进状态页。
func useManagedPage() bool {
	return effectiveRunMode() == "managed" && nodeToken() != ""
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

// validatePairingCode 向主服务器同步校验一次配对码（hello 一次），供加入提交在落盘翻转模式前调用。
// 返回 hub 状态 pending/approved；码无效/过期、连不上、返回异常都以 error 回给加入页 inline 显示。
// 注意：校验成功即消耗了码（hub 侧 pending 已建），调用方不要再把码留盘；拨号器凭指纹 hello 即回 pending。
func validatePairingCode(hubURL, code string) (string, error) {
	fp := nodeFingerprint()
	if fp == "" {
		loadNodeIdentity()
		fp = nodeFingerprint()
	}
	if fp == "" {
		return "", errors.New("节点身份缺失")
	}
	c := &http.Client{Timeout: 15 * time.Second}
	st, body, err := linkPost(c, hubURL+"/api/nodes/hello", "", map[string]any{
		"fingerprint": fp, "pubKey": nodePubKeyB64(), "name": nodeDisplayName(), "version": appVersion,
		"code": code,
	})
	if err != nil {
		return "", errors.New("无法连接主服务器，请检查地址与网络")
	}
	if st == 403 {
		if msg := linkErrBody(body); msg != "" {
			return "", errors.New(msg)
		}
		return "", errors.New("配对码无效")
	}
	if st != 200 {
		return "", fmt.Errorf("主服务器校验失败(HTTP %d)", st)
	}
	var v struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &v) != nil || (v.Status != "pending" && v.Status != "approved") {
		return "", errors.New("主服务器返回异常")
	}
	return v.Status, nil
}

// rollbackJoin 加入失败回退：清掉 managed 模式与凭据，回到加入页重输。
// reason: "rejected"（主服务器拒绝）或 "revoked"（曾配对成功后被移除）；
// HubURL 保留，供加入页回填。仅网络不通等临时失败不走这里（拨号器继续重试）。
func rollbackJoin(reason string) {
	mu.Lock()
	if settings.RunMode == "managed" {
		settings.RunMode = ""
		settings.HubName = ""
		settings.HubID = ""
		settings.JoinError = reason
		saveSettings()
	}
	mu.Unlock()
	clearNodeToken()
	clearNodePairingCode()
}

// handleSetupMode 首次运行模式二选一(公开接口, 未登录时就要能选)。
// GET: 当前模式与选择状态; POST: 只能选一次, 选定后 403。
func handleSetupMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		mu.Lock()
		hubURL, hubName, joinErr := settings.HubURL, settings.HubName, settings.JoinError
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
			"paired":        nodeToken() != "",
			"joinError":     joinErr,
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
		// 本次重输为准：先清掉上次回退残留的失败标记。
		mu.Lock()
		settings.JoinError = ""
		saveSettings()
		mu.Unlock()
		// 落盘翻转模式前先向主服务器同步校验一次码：错码直接回错误，
		// 不写 managed 模式、不进状态页，加入页 inline 显示错误、可无限重输。
		if _, err := validatePairingCode(hubURL, code); err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		mu.Lock()
		settings.RunMode = "managed"
		settings.HubURL = hubURL
		settings.HubName = ""
		settings.HubID = ""
		saveSettings()
		mu.Unlock()
		// 码已被主服务器接受并消耗（pending 已建），本地不再留盘；
		// 拨号器凭指纹 hello 即回 pending，等确认。
		setLinkState("joining", "")
		startLinkLoop() // 本进程内立即起拨号器, 不等重启
		writeJSON(w, 200, map[string]any{"ok": true, "linkState": "joining"})
	default:
		errJSON(w, 400, "mode 须为 standalone 或 managed")
	}
}

// hubRegisteredCount: 本机作为主服务器已登记的子服务器数（待添加不算）。
func hubRegisteredCount() int {
	hubMu.Lock()
	defer hubMu.Unlock()
	n := 0
	for _, s := range hubServers {
		if s != nil {
			n++
		}
	}
	return n
}

// handleSetupJoinHub: 已登录管理员把独立面板转为被控节点（设置页“接入主服务器”弹窗）。
// 未登录由中间件挡（不在 authPublic 里）；被控节点由中间件先 403，这里再防一层。
// 流程与首次加入一致：先同步校验配对码（错码模式不动、凭证不动）→ 通过才翻转模式并起拨号器，
// 接入同时立即取消本地登录凭证（密码与 2FA 清掉）；防护数据不动。
// 本机已有已登记子服务器时直接拒绝：接入后原有子服务器会失去主服务器，不许静默孤儿化。
func handleSetupJoinHub(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	mode := effectiveRunMode()
	if mode == "managed" {
		errJSON(w, 403, "本机已被主服务器群控，管理请去主服务器面板")
		return
	}
	if mode == "" {
		errJSON(w, 400, "请先选择运行模式")
		return
	}
	if hubRegisteredCount() > 0 {
		errJSON(w, 400, "请先移除全部子服务器")
		return
	}
	var in struct {
		HubURL string `json:"hubUrl"`
		Code   string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
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
		errJSON(w, 400, "主服务器地址无效，须为 http(s) 地址")
		return
	}
	hubURL = strings.TrimRight(hubURL, "/")
	// 本次接入为准：先清掉上次回退残留的失败标记。
	mu.Lock()
	settings.JoinError = ""
	saveSettings()
	mu.Unlock()
	// 落盘翻转模式前先向主服务器同步校验一次码：错码直接回错误，
	// 不写 managed 模式，弹窗 inline 显示错误、可无限重输。
	if _, err := validatePairingCode(hubURL, code); err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	mu.Lock()
	settings.RunMode = "managed"
	settings.HubURL = hubURL
	settings.HubName = ""
	settings.HubID = ""
	saveSettings()
	mu.Unlock()
	// 加入即取消本地登录凭证：密码与 2FA 立即清掉（现存 session 一并作废），
	// 被控期间本地无登录入口；脱离后无密码回落，须重新设置密码。
	clearLocalCredentialsForManaged()
	// 码已被主服务器接受并消耗（pending 已建），本地不再留盘；
	// 拨号器凭指纹 hello 即回 pending，等确认。
	setLinkState("joining", "")
	startLinkLoop() // 本进程内立即起拨号器，不等重启
	writeJSON(w, 200, map[string]any{"ok": true, "linkState": "joining"})
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
