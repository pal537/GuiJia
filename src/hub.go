package main

// 主服务器侧: 节点登记、配对码、待添加审批、节点身份鉴权(第一期)。
// - 只有独立面板能当主服务器; 被群控节点上 /api/nodes/* 一律被中间件 403。
// - 配对码: 登录后生成, 一次性, 30 分钟有效, 用完即废。
// - 审批: 待添加 -> 服务器登记; token 不在审批时明文落盘, 节点凭私钥签名
//   换 token(首次 auth 时签发, 只存 SHA-256; 丢了重签即换新)。
// - 节点后续调用凭 X-Node-Fingerprint + X-Node-Token; token 只存哈希,
//   指纹 = 公钥 SHA-256, 换密钥 = 新节点, 须重新配对。

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- 登记数据(servers.json, 0600) ----------

type hubServer struct {
	Fingerprint string `json:"fingerprint"`
	PubKey      string `json:"pubKey"` // base64, 验签用; 不向面板接口外泄
	Name        string `json:"name"`
	Status      string `json:"status"` // online | offline
	LastSeen    int64  `json:"lastSeen"`
	Version     string `json:"version"`
	TGMode      string `json:"tgMode"` // hub | independent
	TokenHash   string `json:"tokenHash"`
	CreatedAt   int64  `json:"createdAt"`
	IP          string `json:"ip,omitempty"`       // 节点上报的主 IP, 老版本节点为空
	OS          string `json:"os,omitempty"`       // 节点上报的操作系统, 如 Debian 13
	Arch        string `json:"arch,omitempty"`     // 节点上报的架构, 如 x86_64
	Location    string `json:"location,omitempty"` // 手动归属地(管理员在卡片上设), 优先于自动解析
}

type hubPendingEntry struct {
	Fingerprint string `json:"fingerprint"`
	PubKey      string `json:"pubKey"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	FirstSeen   int64  `json:"firstSeen"`
}

var (
	hubMu      sync.Mutex
	hubServers []*hubServer
	hubPending []*hubPendingEntry
)

func loadServers() {
	hubMu.Lock()
	defer hubMu.Unlock()
	hubServers = nil
	hubPending = nil
	if b, err := os.ReadFile(serversFile); err == nil {
		var wrap struct {
			Servers []*hubServer       `json:"servers"`
			Pending []*hubPendingEntry `json:"pending"`
		}
		if json.Unmarshal(b, &wrap) == nil {
			hubServers = wrap.Servers
			hubPending = wrap.Pending
		}
	}
	if hubServers == nil {
		hubServers = []*hubServer{}
	}
	if hubPending == nil {
		hubPending = []*hubPendingEntry{}
	}
}

// saveServersLocked 调用方须持有 hubMu, 文件 0600。
func saveServersLocked() {
	b, _ := json.MarshalIndent(map[string]any{"servers": hubServers, "pending": hubPending}, "", "  ")
	os.WriteFile(serversFile, b, 0600)
}

// ---------- 首页新设备提醒(服务端持久化, home-seen.json, 0600) ----------
// homeSeen: 已由管理员在首页点“知道了”的服务器指纹集合。判断只认登记,
// 待添加不算; 指纹一律小写比对。文件缺失 = 空集合, 不报错。

var homeSeen = map[string]bool{}

func loadHomeSeen() {
	hubMu.Lock()
	defer hubMu.Unlock()
	homeSeen = map[string]bool{}
	if b, err := os.ReadFile(homeSeenFile); err == nil {
		var wrap struct {
			Seen []string `json:"seen"`
		}
		if json.Unmarshal(b, &wrap) == nil {
			for _, fp := range wrap.Seen {
				if validFingerprint(fp) {
					homeSeen[strings.ToLower(fp)] = true
				}
			}
		}
	}
}

// saveHomeSeenLocked 调用方须持有 hubMu, 文件 0600。
func saveHomeSeenLocked() {
	seen := []string{}
	for fp := range homeSeen {
		seen = append(seen, fp)
	}
	b, _ := json.MarshalIndent(map[string]any{"seen": seen}, "", "  ")
	os.WriteFile(homeSeenFile, b, 0600)
}

// handleNodeHomeAlerts: 未确认的新接入服务器(已登记且指纹不在 homeSeen 里)。
func handleNodeHomeAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	news := []map[string]any{}
	for _, s := range hubServers {
		if s == nil || homeSeen[strings.ToLower(s.Fingerprint)] {
			continue
		}
		news = append(news, map[string]any{
			"fingerprint": s.Fingerprint, "name": s.Name, "status": s.Status,
			"createdAt": s.CreatedAt, "lastSeen": s.LastSeen,
		})
	}
	writeJSON(w, 200, map[string]any{"new": news})
}

// handleNodeHomeAck: 把一批指纹记为已确认, 落盘后不再提醒。
func handleNodeHomeAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	n := 0
	for _, fp := range in.Fingerprints {
		if !validFingerprint(fp) {
			continue
		}
		fp = strings.ToLower(fp)
		// 只确认当前已登记的服务器: 未登记的指纹不进集合, 以后它真接入时仍会提醒。
		registered := false
		for _, s := range hubServers {
			if s != nil && strings.ToLower(s.Fingerprint) == fp {
				registered = true
				break
			}
		}
		if !registered {
			continue
		}
		if !homeSeen[fp] {
			homeSeen[fp] = true
			n++
		}
	}
	saveHomeSeenLocked()
	writeJSON(w, 200, map[string]any{"acked": n})
}

func findHubServer(fp string) *hubServer {
	for _, s := range hubServers {
		if s != nil && s.Fingerprint == fp {
			return s
		}
	}
	return nil
}

func findHubPending(fp string) *hubPendingEntry {
	for _, p := range hubPending {
		if p != nil && p.Fingerprint == fp {
			return p
		}
	}
	return nil
}

func hubServerPublic(s *hubServer) map[string]any {
	st := "offline"
	if hubNodeOnline(s) {
		st = "online"
	}
	loc, country, flag := serverLocationDisplay(s.Location, s.IP)
	return map[string]any{
		"fingerprint": s.Fingerprint, "name": s.Name, "status": st,
		"lastSeen": s.LastSeen, "version": s.Version, "tgMode": s.TGMode,
		"createdAt": s.CreatedAt,
		"ip":        s.IP, "os": s.OS, "arch": s.Arch,
		"location": loc, "country": country, "flag": flag,
		"countryCode":    serverLocationCode(s.Location, s.IP),
		"manualLocation": s.Location,
	}
}

// serverLocationCode 卡片国旗图用国家代码(小写, flagcdn 用):
// 手动值按手动名匹配, 自动值按 IP 库的国家代码, 都没有则按国家名匹配,
// 仍没有返回 ""(前端不画旗, 绝不显示裸国家码)。
func serverLocationCode(manual, ip string) string {
	if m := strings.TrimSpace(manual); m != "" {
		if c := countryCodeForName(m); c != "" {
			return strings.ToLower(c)
		}
		return ""
	}
	if ip != "" {
		if g := geoLookup(ip); g.Code != "" {
			return strings.ToLower(g.Code)
		} else if g.Country != "" && g.Country != "内网" {
			if c := countryCodeForName(g.Country); c != "" {
				return strings.ToLower(c)
			}
		}
	}
	return ""
}

// serverLocationDisplay 卡片归属地三件套: 手动值优先, 否则按 IP 自动解析
// 国家, 都没有则“未知”; 内网 IP 显示“内网”且无旗; 命中不了的国家名无旗不猜。
// 注意: 手动值一旦设定, 返回的 location 就是手动值本身, 绝不带自动码/自动名;
// 前端国旗图另走 serverLocationCode, 不再用 emoji(Windows 下 emoji 旗只显示字母)。
func serverLocationDisplay(manual, ip string) (location, country, flag string) {
	if m := strings.TrimSpace(manual); m != "" {
		return m, m, flagEmojiForCountry(m)
	}
	if ip != "" {
		if c := geoLookup(ip).Country; c != "" {
			if c == "内网" {
				return "内网", "内网", ""
			}
			return c, c, flagEmojiForCountry(c)
		}
	}
	return "未知", "", ""
}

func hubPendingPublic(p *hubPendingEntry) map[string]any {
	return map[string]any{
		"fingerprint": p.Fingerprint, "name": p.Name, "version": p.Version,
		"firstSeen": p.FirstSeen,
	}
}

// ---------- 配对码(内存态, 一次性 30 分钟) ----------

type pairingCode struct {
	code      string
	expiresAt int64
	used      bool
}

var (
	codeMu sync.Mutex
	codes  = map[string]*pairingCode{}
)

const pairingAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"

func newPairingCode() (string, int64) {
	var b [12]byte
	rand.Read(b[:])
	var sb strings.Builder
	for _, v := range b {
		sb.WriteByte(pairingAlphabet[int(v)%len(pairingAlphabet)])
	}
	exp := time.Now().Add(30 * time.Minute).Unix()
	codeMu.Lock()
	// 重新生成即作废旧码: 此前未用的码一律标记已用, 旧码再填即 403。
	for _, c := range codes {
		c.used = true
	}
	codes[sb.String()] = &pairingCode{code: sb.String(), expiresAt: exp}
	codeMu.Unlock()
	return sb.String(), exp
}

// consumePairingCode 校验并核销(一次性); 失败原因返回 false。
func consumePairingCode(code string) bool {
	codeMu.Lock()
	defer codeMu.Unlock()
	c, ok := codes[code]
	if !ok || c.used || time.Now().Unix() > c.expiresAt {
		return false
	}
	c.used = true
	return true
}

// ---------- 挑战(内存态, 一次性 5 分钟) ----------

type nodeChallenge struct {
	nonce     string
	expiresAt int64
}

var (
	chalMu sync.Mutex
	chals  = map[string]*nodeChallenge{}
)

func newChallenge(fp string) string {
	var b [32]byte
	rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	chalMu.Lock()
	chals[fp] = &nodeChallenge{nonce: nonce, expiresAt: time.Now().Add(5 * time.Minute).Unix()}
	chalMu.Unlock()
	return nonce
}

func consumeChallenge(fp, nonce string) bool {
	chalMu.Lock()
	defer chalMu.Unlock()
	c, ok := chals[fp]
	if !ok || c.nonce != nonce || time.Now().Unix() > c.expiresAt {
		return false
	}
	delete(chals, fp)
	return true
}

// ---------- 指纹与 token ----------

func validFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func fingerprintOfPub(pubB64 string) (string, bool) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", false
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:]), true
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func newNodeToken() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// nodeAuth 校验节点后续调用: 指纹 + token(与存量哈希比对)。
func nodeAuth(r *http.Request) *hubServer {
	fp := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Node-Fingerprint")))
	tok := strings.TrimSpace(r.Header.Get("X-Node-Token"))
	if fp == "" || tok == "" {
		return nil
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	s := findHubServer(fp)
	if s == nil || s.TokenHash == "" || s.TokenHash != hashToken(tok) {
		return nil
	}
	return s
}

// ---------- 主服务器面板接口(登录鉴权由中间件负责) ----------

func handlePairingCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	code, exp := newPairingCode()
	writeJSON(w, 200, map[string]any{"code": code, "expiresAt": exp})
}

func handleNodeServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	servers := []map[string]any{}
	for _, s := range hubServers {
		if s != nil {
			servers = append(servers, hubServerPublic(s))
		}
	}
	pending := []map[string]any{}
	for _, p := range hubPending {
		if p != nil {
			pending = append(pending, hubPendingPublic(p))
		}
	}
	writeJSON(w, 200, map[string]any{"servers": servers, "pending": pending})
}

// handleNodeLocation 首页卡片手动归属地: fingerprint 为 "local" 时改本机
// (存 settings.ManualLocation), 否则改注册表里该节点的 Location 并持久化;
// location 为空 = 清除手动值, 回到自动解析。登录鉴权由中间件负责。
func handleNodeLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
		Location    string `json:"location"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	loc := strings.TrimSpace(in.Location)
	if len([]rune(loc)) > 64 {
		errJSON(w, 400, "归属地过长")
		return
	}
	if in.Fingerprint == "local" || in.Fingerprint == "" {
		mu.Lock()
		settings.ManualLocation = loc
		saveSettings()
		mu.Unlock()
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if !validFingerprint(in.Fingerprint) {
		errJSON(w, 400, "指纹无效")
		return
	}
	fp := strings.ToLower(in.Fingerprint)
	hubMu.Lock()
	defer hubMu.Unlock()
	s := findHubServer(fp)
	if s == nil {
		errJSON(w, 404, "没有该节点")
		return
	}
	s.Location = loc
	saveServersLocked()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// handleLocalInfo 本机卡片信息: 名称、主 IP、操作系统、架构、归属地与国旗。
// 归属地 = 手动值优先, 否则按本机主 IP 自动解析, 都没有则“未知”。
func handleLocalInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	// 本机卡片 IP: 公网优先(异步回显服务, 不阻塞), NAT 机不再只显示内网 IP。
	ip := localDisplayIP()
	_, osName, arch := nodeSysInfo()
	mu.Lock()
	manual := settings.ManualLocation
	mu.Unlock()
	loc, country, flag := serverLocationDisplay(manual, ip)
	writeJSON(w, 200, map[string]any{
		"name": nodeDisplayName(), "ip": ip, "os": osName, "arch": arch,
		"location": loc, "country": country, "flag": flag,
		"countryCode":    serverLocationCode(manual, ip),
		"manualLocation": manual,
	})
}

func handleNodeApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validFingerprint(in.Fingerprint) {
		errJSON(w, 400, "请求无效")
		return
	}
	fp := strings.ToLower(in.Fingerprint)
	hubMu.Lock()
	defer hubMu.Unlock()
	if findHubServer(fp) != nil {
		errJSON(w, 400, "该节点已登记")
		return
	}
	p := findHubPending(fp)
	if p == nil {
		errJSON(w, 404, "待添加中没有该节点")
		return
	}
	now := time.Now().Unix()
	s := &hubServer{
		Fingerprint: fp, PubKey: p.PubKey, Name: p.Name, Status: "offline",
		Version: p.Version, TGMode: "hub", CreatedAt: now,
	}
	hubServers = append(hubServers, s)
	for i, q := range hubPending {
		if q != nil && q.Fingerprint == fp {
			hubPending = append(hubPending[:i], hubPending[i+1:]...)
			break
		}
	}
	saveServersLocked()
	// 群控共享已开启时, 新节点批准后立即自动同步一次(后台等上线, 不阻塞返回)。
	maybeAutoSyncNewNode(fp, p.Name)
	writeJSON(w, 200, map[string]any{"ok": true, "server": hubServerPublic(s)})
}

func handleNodeReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validFingerprint(in.Fingerprint) {
		errJSON(w, 400, "请求无效")
		return
	}
	fp := strings.ToLower(in.Fingerprint)
	hubMu.Lock()
	defer hubMu.Unlock()
	for i, p := range hubPending {
		if p != nil && p.Fingerprint == fp {
			hubPending = append(hubPending[:i], hubPending[i+1:]...)
			saveServersLocked()
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	errJSON(w, 404, "待添加中没有该节点")
}

func handleNodeRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validFingerprint(in.Fingerprint) {
		errJSON(w, 400, "请求无效")
		return
	}
	fp := strings.ToLower(in.Fingerprint)
	hubMu.Lock()
	defer hubMu.Unlock()
	for i, s := range hubServers {
		if s != nil && s.Fingerprint == fp {
			hubServers = append(hubServers[:i], hubServers[i+1:]...)
			saveServersLocked()
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	errJSON(w, 404, "没有该节点")
}

// ---------- 节点接入接口(公开, 节点无面板 session) ----------

// handleNodeHello 节点首次报到: 已登记 -> 走挑战; 未登记 -> 凭配对码进待添加。
func handleNodeHello(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
		PubKey      string `json:"pubKey"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Code        string `json:"code"`
		IP          string `json:"ip"`
		OS          string `json:"os"`
		Arch        string `json:"arch"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	fp := strings.ToLower(strings.TrimSpace(in.Fingerprint))
	if !validFingerprint(fp) {
		errJSON(w, 400, "指纹无效")
		return
	}
	want, ok := fingerprintOfPub(in.PubKey)
	if !ok || want != fp {
		errJSON(w, 400, "公钥与指纹不符")
		return
	}
	name := normalizeServerName(in.Name)
	if name == "" {
		name = fp[:12]
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	if s := findHubServer(fp); s != nil {
		// 已登记节点每次 hello 都同步名称与系统信息(改名、换 IP 即随下次 hello/ping 同步)。
		s.Name = name
		if in.IP != "" {
			s.IP = in.IP
		}
		if in.OS != "" {
			s.OS = in.OS
		}
		if in.Arch != "" {
			s.Arch = in.Arch
		}
		if in.Version != "" {
			s.Version = in.Version
		}
		saveServersLocked()
		writeJSON(w, 200, map[string]any{"status": "approved"})
		return
	}
	if p := findHubPending(fp); p != nil {
		p.Name = name
		p.Version = in.Version
		p.PubKey = in.PubKey
		saveServersLocked()
		writeJSON(w, 200, map[string]any{"status": "pending"})
		return
	}
	if !consumePairingCode(strings.TrimSpace(in.Code)) {
		errJSON(w, 403, "配对码无效或已过期")
		return
	}
	hubPending = append(hubPending, &hubPendingEntry{
		Fingerprint: fp, PubKey: in.PubKey, Name: name, Version: in.Version,
		FirstSeen: time.Now().Unix(),
	})
	saveServersLocked()
	writeJSON(w, 200, map[string]any{"status": "pending"})
}

func handleNodeChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validFingerprint(in.Fingerprint) {
		errJSON(w, 400, "请求无效")
		return
	}
	fp := strings.ToLower(in.Fingerprint)
	hubMu.Lock()
	approved := findHubServer(fp) != nil
	hubMu.Unlock()
	if !approved {
		errJSON(w, 403, "节点未获批准")
		return
	}
	writeJSON(w, 200, map[string]any{"nonce": newChallenge(fp)})
}

// handleNodeAuth 节点凭私钥签名换 token: 验签通过即签发(丢了重签即换新)。
func handleNodeAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
		Nonce       string `json:"nonce"`
		Signature   string `json:"signature"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validFingerprint(in.Fingerprint) {
		errJSON(w, 400, "请求无效")
		return
	}
	fp := strings.ToLower(in.Fingerprint)
	hubMu.Lock()
	s := findHubServer(fp)
	hubMu.Unlock()
	if s == nil {
		errJSON(w, 403, "节点未获批准")
		return
	}
	if !consumeChallenge(fp, in.Nonce) {
		errJSON(w, 403, "挑战无效或已过期")
		return
	}
	pub, err := base64.StdEncoding.DecodeString(s.PubKey)
	sig, err2 := base64.StdEncoding.DecodeString(in.Signature)
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(pub), []byte(in.Nonce), sig) {
		errJSON(w, 401, "签名验证失败")
		return
	}
	tok := newNodeToken()
	hubMu.Lock()
	s.TokenHash = hashToken(tok)
	s.Status = "online"
	s.LastSeen = time.Now().Unix()
	saveServersLocked()
	hubMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"token": tok, "hubName": nodeDisplayName(), "hubId": settings.ServerID,
	})
}

// handleNodePing 节点心跳(凭 token): 刷新在线状态与最后在线。
func handleNodePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	s := nodeAuth(r)
	if s == nil {
		errJSON(w, 401, "节点鉴权失败")
		return
	}
	var in struct {
		Version string `json:"version"`
		TGMode  string `json:"tgMode"`
		Name    string `json:"name"`
		IP      string `json:"ip"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	hubMu.Lock()
	s.Status = "online"
	s.LastSeen = time.Now().Unix()
	if in.Version != "" {
		s.Version = in.Version
	}
	// 节点每次 ping 都同步名称与系统信息: 节点改名后随下次 ping 同步到首页与顶部标识。
	if n := normalizeServerName(in.Name); n != "" {
		s.Name = n
	}
	if in.IP != "" {
		s.IP = in.IP
	}
	if in.OS != "" {
		s.OS = in.OS
	}
	if in.Arch != "" {
		s.Arch = in.Arch
	}
	// 节点上报的 TG 模式即事实来源(节点自己决定事件走哪条路), 主服务器只做镜像。
	if in.TGMode == "hub" || in.TGMode == "independent" {
		s.TGMode = in.TGMode
	}
	saveServersLocked()
	hubMu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------- link 端点限流(只限流, 永不封禁) ----------

// 每 IP 每分钟失败上限; 超限只回 429, 绝不进 nft 封禁。
const linkFailLimit = 20

type ipFailWindow struct {
	count int
	start int64
}

var (
	limMu   sync.Mutex
	limFail = map[string]*ipFailWindow{}
)

func linkFailLimited(ip string) bool {
	if ip == "" {
		return false
	}
	now := time.Now().Unix()
	limMu.Lock()
	defer limMu.Unlock()
	w, ok := limFail[ip]
	if !ok || now-w.start >= 60 {
		limFail[ip] = &ipFailWindow{count: 0, start: now}
		return false
	}
	return w.count >= linkFailLimit
}

func noteLinkFail(ip string) {
	if ip == "" {
		return
	}
	now := time.Now().Unix()
	limMu.Lock()
	defer limMu.Unlock()
	w, ok := limFail[ip]
	if !ok || now-w.start >= 60 {
		limFail[ip] = &ipFailWindow{count: 1, start: now}
		return
	}
	w.count++
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// linkLimit 包装节点接入端点: 失败计数超限回 429, 成功清零窗口;
// 只限流, 不调任何封禁逻辑。
func linkLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		if linkFailLimited(ip) {
			errJSON(w, 429, "请求过于频繁")
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next(rec, r)
		if rec.status >= 400 {
			noteLinkFail(ip)
		}
	}
}

// ---------- 命令通道(长轮询, 标准库) ----------

type hubCommand struct {
	ID       string          `json:"id"`
	Method   string          `json:"method"`
	Path     string          `json:"path"`
	Body     json.RawMessage `json:"body,omitempty"`
	Internal bool            `json:"internal,omitempty"` // 主服务器内部命令(群控同步等):
	// 面板代理与 TG 回调绝不置位; 节点执行时据此打内部头, 内部接口只认该头。
}

type hubCmdResult struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// 同一节点同一时间最多一个 poll 在等; 新 poll 顶掉旧的。
var (
	cmdMu      sync.Mutex
	cmdWaiters = map[string]chan hubCommand{}
	cmdResults = map[string]chan hubCmdResult{}
)

// hubNodeOnline 在线判定: 90 秒内有 ping 或 poll 即在线, 否则离线
// (不靠后台扫表, 状态由最后在线时间实时算出)。
func hubNodeOnline(s *hubServer) bool {
	if s == nil || s.LastSeen <= 0 {
		return false
	}
	return time.Now().Unix()-s.LastSeen <= 90
}

// isProxyablePath 只放行管理类 API; 节点/鉴权/模式接口一律不放行。
func isProxyablePath(p string) bool {
	if i := strings.Index(p, "?"); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // 前端常发无斜杠的 api/overview, 归一化后再判断
	}
	if !strings.HasPrefix(p, "/api/") {
		return false
	}
	for _, pre := range []string{"/api/nodes/", "/api/auth/", "/api/setup/", "/api/node/"} {
		if strings.HasPrefix(p, pre) {
			return false
		}
	}
	return true
}

func newCmdID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// linkPollHold 节点 poll 在主服务器的 hold 上限(默认 25 秒, 测试可调小)。
var linkPollHold = 25 * time.Second

// handleNodePoll 节点取命令: 主服务器 hold 最长 linkPollHold, 有命令即回, 否则 204。
func handleNodePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	s := nodeAuth(r)
	if s == nil {
		errJSON(w, 401, "节点鉴权失败")
		return
	}
	hubMu.Lock()
	s.Status = "online"
	s.LastSeen = time.Now().Unix()
	saveServersLocked()
	hubMu.Unlock()
	wch := make(chan hubCommand, 1)
	cmdMu.Lock()
	cmdWaiters[s.Fingerprint] = wch
	cmdMu.Unlock()
	select {
	case cmd := <-wch:
		writeJSON(w, 200, cmd)
	case <-time.After(linkPollHold):
		w.WriteHeader(204)
	}
	cmdMu.Lock()
	if cur := cmdWaiters[s.Fingerprint]; cur == wch {
		delete(cmdWaiters, s.Fingerprint)
	}
	cmdMu.Unlock()
}

// handleNodeResult 节点回结果: 投递给等待中的代理请求, 无等待者则丢弃。
func handleNodeResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if nodeAuth(r) == nil {
		errJSON(w, 401, "节点鉴权失败")
		return
	}
	var in struct {
		ID     string          `json:"id"`
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.ID == "" {
		errJSON(w, 400, "请求无效")
		return
	}
	cmdMu.Lock()
	ch, ok := cmdResults[in.ID]
	if ok {
		delete(cmdResults, in.ID)
	}
	cmdMu.Unlock()
	if ok {
		select {
		case ch <- hubCmdResult{Status: in.Status, Body: in.Body}:
		default:
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// hubCallNode 经命令通道调节点管理接口(面板代理与 TG 回调路由共用)。
// 返回 (状态码, Body, 错误种): 错误种 ""=已拿到节点响应(按状态码处理),
// "notfound"=无此节点, "offline"=节点离线, "nochan"=未建立命令通道,
// "timeout"=节点响应超时。调用方按场景映射 HTTP 状态或提示文案。
func hubCallNode(fp, method, path string, body json.RawMessage) (int, []byte, string) {
	return hubCallNodeInternal(fp, method, path, body, false)
}

// hubCallNodeInternal 命令通道通用发送: internal=true 时跳过面板代理放行
// 集检查(只给主服务器内部命令用, 如群控同步; 面板代理一律走 false)。
// 内部命令执行时节点侧打 X-Guijia-Internal 头, 内部接口只认该头,
// 面板用户无法伪造(代理入口不接受 internal 字段)。
func hubCallNodeInternal(fp, method, path string, body json.RawMessage, internal bool) (int, []byte, string) {
	if !internal && !isProxyablePath(path) {
		return 403, []byte(`{"error":"该接口不允许跨节点调用"}`), ""
	}
	hubMu.Lock()
	s := findHubServer(fp)
	online := hubNodeOnline(s)
	hubMu.Unlock()
	if s == nil {
		return 404, nil, "notfound"
	}
	if !online {
		return 502, nil, "offline"
	}
	cmdMu.Lock()
	wch, ok := cmdWaiters[fp]
	cmdMu.Unlock()
	if !ok {
		// 节点处理完一条命令会立刻再 poll, 并发请求等一等而不是直接 502。
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			cmdMu.Lock()
			wch, ok = cmdWaiters[fp]
			cmdMu.Unlock()
			if ok {
				break
			}
		}
	}
	if !ok {
		return 502, nil, "nochan"
	}
	id := newCmdID()
	resCh := make(chan hubCmdResult, 1)
	cmdMu.Lock()
	cmdResults[id] = resCh
	cmdMu.Unlock()
	cleanup := func() {
		cmdMu.Lock()
		if ch, ok := cmdResults[id]; ok && ch == resCh {
			delete(cmdResults, id)
		}
		cmdMu.Unlock()
	}
	select {
	case wch <- hubCommand{ID: id, Method: method, Path: path, Body: body, Internal: internal}:
	case <-time.After(10 * time.Second):
		cleanup()
		return 504, nil, "timeout"
	}
	select {
	case res := <-resCh:
		if res.Status < 100 || res.Status > 599 {
			res.Status = 502
		}
		return res.Status, res.Body, ""
	case <-time.After(20 * time.Second):
		cleanup()
		return 504, nil, "timeout"
	}
}

// sanitizeBackupServerName 备份文件名用服务器名: 只留字母数字、中文与 -_,
// / 其余字符换 _, 超长截断, 为空回落指纹前 8 位。文件名绝不带路径分隔符。
func sanitizeBackupServerName(name, fp string) string {
	var sb strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r >= 0x4e00 && r <= 0x9fff {
			sb.WriteRune(r)
		} else if r == ' ' {
			sb.WriteRune('_')
		} else {
			sb.WriteRune('_')
		}
	}
	out := sb.String()
	if len([]rune(out)) > 32 {
		out = string([]rune(out)[:32])
	}
	if strings.Trim(out, "_") == "" {
		if len(fp) >= 8 {
			return fp[:8]
		}
		return "node"
	}
	return out
}

// handleNodeBackupDownload 主服务器代下载节点备份(第 9 项):
// 此前面板在节点视图下点“下载备份”仍是相对路径, 实际下的是主服务器自己
// 的备份(窜了)。现在: 节点视图下载走本接口, 经命令通道取节点导出
// (base64 JSON), 落盘文件名带节点名, 内容确为该节点数据。
func handleNodeBackupDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	fp := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("fp")))
	kind := r.URL.Query().Get("kind")
	if !validFingerprint(fp) || (kind != "settings" && kind != "data") {
		errJSON(w, 400, "请求无效")
		return
	}
	hubMu.Lock()
	s := findHubServer(fp)
	var name string
	if s != nil {
		name = s.Name
	}
	hubMu.Unlock()
	if s == nil {
		errJSON(w, 404, "没有该节点")
		return
	}
	status, respBody, errKind := hubCallNode(fp, "GET", "api/backup/export?kind="+kind, nil)
	if errKind != "" {
		switch errKind {
		case "notfound":
			errJSON(w, 404, "没有该节点")
		case "offline":
			errJSON(w, 502, "节点离线")
		case "nochan":
			errJSON(w, 502, "节点未建立命令通道")
		case "timeout":
			errJSON(w, 504, "节点响应超时")
		default:
			errJSON(w, 502, errKind)
		}
		return
	}
	if status < 200 || status >= 300 {
		errJSON(w, status, "节点备份导出失败")
		return
	}
	var exp struct {
		Mime string `json:"mime"`
		Ext  string `json:"ext"`
		Data string `json:"data"`
	}
	if json.Unmarshal(respBody, &exp) != nil || exp.Data == "" {
		errJSON(w, 502, "节点备份导出返回异常")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(exp.Data)
	if err != nil {
		errJSON(w, 502, "节点备份解码失败")
		return
	}
	mime := exp.Mime
	if mime == "" {
		mime = "application/octet-stream"
	}
	ext := exp.Ext
	if ext == "" {
		ext = ".bin"
	}
	fname := "guijia-" + kind + "-" + sanitizeBackupServerName(name, fp) + "-" +
		time.Now().Format("20060102-150405") + ext
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", "attachment; filename="+fname)
	w.Write(raw)
}

// handleNodeProxy 面板登录后转发管理请求给节点, 节点原样状态 + Body 回传。
func handleNodeProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var in struct {
		Fingerprint string          `json:"fingerprint"`
		Method      string          `json:"method"`
		Path        string          `json:"path"`
		Body        json.RawMessage `json:"body"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validFingerprint(in.Fingerprint) {
		errJSON(w, 400, "请求无效")
		return
	}
	fp := strings.ToLower(in.Fingerprint)
	switch in.Method {
	case "GET", "POST", "PUT", "DELETE":
	default:
		errJSON(w, 400, "不支持的方法")
		return
	}
	if !isProxyablePath(in.Path) {
		errJSON(w, 403, "该接口不允许跨节点调用")
		return
	}
	status, respBody, errKind := hubCallNode(fp, in.Method, in.Path, in.Body)
	switch errKind {
	case "notfound":
		errJSON(w, 404, "没有该节点")
	case "offline":
		errJSON(w, 502, "节点离线")
	case "nochan":
		errJSON(w, 502, "节点未建立命令通道")
	case "timeout":
		errJSON(w, 504, "节点响应超时")
	default:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(respBody)
	}
}
