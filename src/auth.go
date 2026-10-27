package main

// 面板登录鉴权(单管理员, 不做多用户):
// - 首次登录强制设密(两次确认, 12 位起 + 大写 + 小写 + 数字 + 符号)
// - session + 保存登录(记住我); 不绑定 IP, 换 IP 不掉线
// - 面板防爆破默认开: 密码连续错 N 次(设置可调, 默认 5)封 IP 7 天,
//   成功一次清零; 内网/信任名单豁免; 进统一黑名单, 到期自动解封
// - 密码只存 PBKDF2 哈希(复用 rescue.go 的哈希格式), 绝不存明文
// - 所有 /api/* 走登录鉴权, 仅 /api/auth/status|setup|login|totp/verify 例外

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "guijia_session"
	sessionTTL        = 24 * time.Hour
	rememberTTL       = 30 * 24 * time.Hour
)

// 面板鉴权持久化(0600, 存数据目录 auth.json)。
type adminAuth struct {
	PassHash      string   `json:"passHash"`
	TOTPSecret    string   `json:"totpSecret,omitempty"`
	TOTPEnabled   bool     `json:"totpEnabled"`
	RecoveryCodes []string `json:"recoveryCodes,omitempty"` // sha256 hex, 一次性, 用掉即删
	SessionGen    int      `json:"sessionGen"`              // 改密即 +1, 旧 session 全失效
}

var (
	authMu sync.Mutex
	auth   adminAuth
)

func loadAuth() {
	authMu.Lock()
	defer authMu.Unlock()
	if b, err := os.ReadFile(authFile); err == nil {
		json.Unmarshal(b, &auth)
	}
}

// saveAuthLocked 调用方须持有 authMu。
func saveAuthLocked() {
	b, _ := json.MarshalIndent(auth, "", "  ")
	os.WriteFile(authFile, b, 0600)
}

func hasPassword() bool {
	authMu.Lock()
	defer authMu.Unlock()
	return auth.PassHash != ""
}

// ---------- 强密码规则 ----------

// checkStrongPassword: 12 位起 + 大写 + 小写 + 数字 + 符号, 不满足返回原因。
func checkStrongPassword(pw string) string {
	if len([]rune(pw)) < 12 {
		return "密码至少 12 位"
	}
	var up, low, dig, sym bool
	for _, c := range pw {
		switch {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			low = true
		case c >= '0' && c <= '9':
			dig = true
		default:
			sym = true
		}
	}
	if !up || !low || !dig || !sym {
		return "密码须含大写、小写、数字、符号"
	}
	return ""
}

// ---------- session ----------

type session struct {
	token     string
	gen       int
	expires   time.Time
	remember  bool
	ip        string // 登录时真实 IP(反代后为反代头里的 IP, 见 realIP)
	createdAt int64  // 登录时间(unix 秒)
	lastSeen  int64  // 最后活跃(unix 秒, 每次鉴权刷新, 仅内存)
}

var (
	sessMu   sync.Mutex
	sessions = map[string]*session{}
)

func newSessionToken() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// newSessionLocked 创建 session 并顺带清掉已过期旧 session(调用方须持有 sessMu)。
func newSessionLocked(remember bool, ip string) *session {
	now := time.Now()
	for tok, s := range sessions {
		if now.After(s.expires) {
			delete(sessions, tok)
		}
	}
	ttl := sessionTTL
	if remember {
		ttl = rememberTTL
	}
	authMu.Lock()
	gen := auth.SessionGen
	authMu.Unlock()
	s := &session{token: newSessionToken(), gen: gen, expires: now.Add(ttl), remember: remember, ip: ip, createdAt: now.Unix(), lastSeen: now.Unix()}
	sessions[s.token] = s
	return s
}

func setSessionCookie(w http.ResponseWriter, s *session) {
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  s.expires,
		Secure:   panelTLSEnabled(),
	}
	http.SetCookie(w, c)
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
}

func sessionOf(r *http.Request) *session {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessions[c.Value]
	if !ok {
		return nil
	}
	if time.Now().After(s.expires) {
		delete(sessions, c.Value)
		return nil
	}
	authMu.Lock()
	gen := auth.SessionGen
	authMu.Unlock()
	if s.gen != gen {
		return nil
	}
	s.lastSeen = time.Now().Unix()
	return s
}

func validSession(r *http.Request) bool { return sessionOf(r) != nil }

// panelTLSEnabled: 面板是否走 HTTPS(决定 session cookie 是否加 Secure)。
// 阶段 4 实现 SSL 模式后按设置返回; 现阶段模式恒为 off, 返回 false。
func panelTLSEnabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return settings.PanelSSLMode != "" && settings.PanelSSLMode != "off"
}

// ---------- 面板防爆破 ----------

// panelBanThreshold: 设置可调, 默认 5, 钳制 1..100。
func panelBanThreshold() int {
	mu.Lock()
	defer mu.Unlock()
	n := settings.PanelBanThreshold
	if n < 1 {
		return 5
	}
	if n > 100 {
		return 100
	}
	return n
}

var (
	panelFailMu sync.Mutex
	panelFails  = map[string][]int64{} // ip -> 连续失败计数(成功清零, 不设时间窗口)
)

func resetPanelFails(ip string) {
	panelFailMu.Lock()
	defer panelFailMu.Unlock()
	delete(panelFails, ip)
}

// notePanelFail 记录一次面板密码错误; 达到阈值即封 IP 7 天, 返回是否刚触发封禁。
// 内网/信任名单豁免: 不计数、不封禁。
func notePanelFail(ip string) bool {
	if ip == "" {
		return false
	}
	if ok, _ := bannable(ip); !ok {
		return false
	}
	panelFailMu.Lock()
	panelFails[ip] = append(panelFails[ip], time.Now().Unix())
	cnt := len(panelFails[ip])
	panelFailMu.Unlock()
	if cnt < panelBanThreshold() {
		return false
	}
	// 进统一黑名单: 固定 7 天, 不走 SSH 递进阶梯, 不碰 Offenses。
	if _, err := applyBan(ip, "面板登录爆破", "panel", 7*24); err == nil {
		panelFailMu.Lock()
		delete(panelFails, ip)
		panelFailMu.Unlock()
		emit(Event{Type: "ban", IP: ip, Detail: "面板登录爆破自动拉黑: 连续失败 " + itoa(cnt) + " 次, 封禁 7 天"}, true)
		return true
	}
	// 封禁失败(如中途被信任名单收录): 清计数, 不再累计。
	panelFailMu.Lock()
	delete(panelFails, ip)
	panelFailMu.Unlock()
	return false
}

// ---------- 客户端 IP ----------

// clientIP 登录鉴权用的客户端 IP(封禁判定、爆破计数、登录事件都用它)。
// 2026-10-27 修: 原先只读连接地址, 走 nginx 反代时永远是 127.0.0.1,
// 导致面板防爆破与登录事件全失效; 现直接复用 2FA 信任设备的 realIP
// (回环来源才信反代头, 直连不信, 防伪造)。调用面只剩登录与 2FA 成功事件。
func clientIP(r *http.Request) string {
	return realIP(r)
}

// ---------- 中间件 ----------

// authPublic 不需要登录即可访问的鉴权接口(其余 /api/* 一律要 session)。
// 注意: 被群控模式下中间件先拦截, 下面这些公开口也不放行本地登录/设密。
func authPublic(path string) bool {
	switch path {
	case "/api/auth/status", "/api/auth/setup", "/api/auth/login", "/api/auth/totp/verify",
		"/api/version",
		"/api/setup/mode", "/api/node/status",
		"/api/nodes/hello", "/api/nodes/challenge", "/api/nodes/auth", "/api/nodes/ping",
		"/api/nodes/poll", "/api/nodes/result", "/api/nodes/events":
		return true
	}
	return false
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// 被群控节点: 本地没有任何管理入口, 只放行只读状态与模式查询;
		// 登录/设密/全部管理接口一律 403, 管理请去主服务器面板。
		if effectiveRunMode() == "managed" {
			if p == "/api/node/status" || (p == "/api/setup/mode" && r.Method == "GET") {
				next.ServeHTTP(w, r)
				return
			}
			errJSON(w, 403, "本机已被主服务器群控，管理请去主服务器面板")
			return
		}
		if authPublic(p) {
			next.ServeHTTP(w, r)
			return
		}
		if !validSession(r) {
			errJSON(w, 401, "请先登录")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- 接口 ----------

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	authMu.Lock()
	totpOn := auth.TOTPEnabled
	authMu.Unlock()
	mode := effectiveRunMode()
	writeJSON(w, 200, map[string]any{
		"setupRequired":      !hasPassword() && mode != "managed",
		"modeChoiceRequired": mode == "",
		"managed":            mode == "managed",
		"loggedIn":           validSession(r),
		"totpEnabled":        totpOn,
	})
}

func handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	// 模式检查在前: 被群控节点不设本地密码; 未定模式先选模式再设密。
	if mode := effectiveRunMode(); mode == "managed" {
		errJSON(w, 403, "被群控节点不设本地密码")
		return
	} else if mode == "" {
		errJSON(w, 400, "请先选择运行模式")
		return
	}
	if hasPassword() {
		errJSON(w, 403, "已设置密码")
		return
	}
	var in struct {
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	if in.Password != in.Confirm {
		errJSON(w, 400, "两次输入不一致")
		return
	}
	if msg := checkStrongPassword(in.Password); msg != "" {
		errJSON(w, 400, msg)
		return
	}
	h, err := hashRescuePassword(in.Password)
	if err != nil {
		errJSON(w, 500, "设置失败")
		return
	}
	authMu.Lock()
	auth.PassHash = h
	saveAuthLocked()
	authMu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	ip := clientIP(r)
	if !hasPassword() {
		errJSON(w, 403, "尚未设置密码, 请先完成首次设置")
		return
	}
	if isGloballyBanned(ip) {
		errJSON(w, 403, "该 IP 已被封禁")
		return
	}
	authMu.Lock()
	stored := auth.PassHash
	authMu.Unlock()
	if !verifyRescuePassword(in.Password, stored) {
		emit(Event{Type: "panel_fail", IP: ip, Detail: "面板登录失败"}, false)
		if notePanelFail(ip) {
			errJSON(w, 403, "密码连续错误, 该 IP 已被封禁 7 天")
			return
		}
		errJSON(w, 401, "密码错误")
		return
	}
	resetPanelFails(ip)
	// 2FA 已开通: 信任设备(同 IP 同设备)凭密码直接登, 否则密码只换
	// 5 分钟临时凭证, 第二步凭动态码或恢复码换 session。
	authMu.Lock()
	totpOn := auth.TOTPEnabled
	authMu.Unlock()
	if totpOn {
		if trustedDevice(r) {
			sessMu.Lock()
			s := newSessionLocked(in.Remember, ip)
			sessMu.Unlock()
			setSessionCookie(w, s)
			emit(Event{Type: "ui_login", IP: ip, Detail: "面板登录成功(信任设备)"}, settings.AlertUILogin && !isTrusted(ip))
			writeJSON(w, 200, map[string]any{"ok": true, "need2fa": false})
			return
		}
		tok := newPending2FA(in.Remember)
		writeJSON(w, 200, map[string]any{"ok": true, "need2fa": true, "pending": tok})
		return
	}
	sessMu.Lock()
	s := newSessionLocked(in.Remember, ip)
	sessMu.Unlock()
	setSessionCookie(w, s)
	emit(Event{Type: "ui_login", IP: ip, Detail: "面板登录成功"}, settings.AlertUILogin && !isTrusted(ip))
	writeJSON(w, 200, map[string]any{"ok": true, "need2fa": false})
}

func handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		sessMu.Lock()
		delete(sessions, c.Value)
		sessMu.Unlock()
	}
	clearSessionCookie(w)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// handleAuthSessions 当前登录会话(总览卡片用): 只返回登录 IP/归属地/
// 登录时间/最后活跃/记住登录/是否当前会话, 绝不返回 token。
func handleAuthSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	cur := ""
	if c, err := r.Cookie(sessionCookieName); err == nil {
		cur = c.Value
	}
	type snap struct {
		tok string
		ip  string
		ca  int64
		ls  int64
		exp int64
		rem bool
	}
	snaps := []snap{}
	now := time.Now()
	sessMu.Lock()
	for tok, s := range sessions {
		if now.After(s.expires) {
			delete(sessions, tok)
			continue
		}
		snaps = append(snaps, snap{tok, s.ip, s.createdAt, s.lastSeen, s.expires.Unix(), s.remember})
	}
	sessMu.Unlock()
	out := []map[string]any{}
	for _, s := range snaps {
		geo := ""
		if s.ip != "" {
			geo = geoLookup(s.ip).Text
		}
		out = append(out, map[string]any{
			"ip": s.ip, "geo": geo, "createdAt": s.ca, "lastSeen": s.ls,
			"expires": s.exp, "remember": s.rem, "current": s.tok == cur,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["current"] != out[j]["current"] {
			return out[i]["current"].(bool)
		}
		return out[i]["lastSeen"].(int64) > out[j]["lastSeen"].(int64)
	})
	writeJSON(w, 200, out)
}

func handleAuthPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Current  string `json:"current"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	authMu.Lock()
	stored := auth.PassHash
	authMu.Unlock()
	if !verifyRescuePassword(in.Current, stored) {
		errJSON(w, 401, "当前密码错误")
		return
	}
	if in.Password != in.Confirm {
		errJSON(w, 400, "两次输入不一致")
		return
	}
	if msg := checkStrongPassword(in.Password); msg != "" {
		errJSON(w, 400, msg)
		return
	}
	h, err := hashRescuePassword(in.Password)
	if err != nil {
		errJSON(w, 500, "设置失败")
		return
	}
	// 改密即废旧 session, 但当前 session 续用新代次(改密不把自己踢掉)。
	// 注意: 必须在抬代次之前先取当前 session, 否则 sessionOf 会因代次不符取不到。
	cur := sessionOf(r)
	authMu.Lock()
	auth.PassHash = h
	auth.SessionGen++
	gen := auth.SessionGen
	saveAuthLocked()
	authMu.Unlock()
	if cur != nil {
		sessMu.Lock()
		cur.gen = gen
		sessMu.Unlock()
		setSessionCookie(w, cur)
	}
	// 改密即废全部信任设备: 下次登录一律重新输码(当前 session 续用, 不踢自己)。
	clearDeviceTrusts()
	clearDeviceCookie(w)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
