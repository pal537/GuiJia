package main

// 二次验证(TOTP, SecretDock 套路):
// - 默认关闭, 手动开通; 开通须在已登录态下输对一次动态码才生效
// - 生效后登录分两步: 密码对 -> 返回 5 分钟临时凭证 -> 凭动态码或恢复码换 session
// - 信任设备: 验证通过即信任该设备(绑定真实 IP, 90 天); 之后同 IP 同设备
//   凭密码直接登, 换 IP 或换设备才重新输动态码(见 trusted_device.go)
// - 一次性恢复码 10 个(8 位数字, 只存 sha256, 用掉即作废, 开通时只展示一次)
// - 纯标准库实现(RFC 6238, HMAC-SHA1, 30 秒步长, ±1 步容差)
// - 不绑定 IP, 换 IP 不掉线; 保存登录(remember)由第一步登录请求携带

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	totpStep      = 30 * time.Second
	totpWindow    = 1 // 前后各容差 1 步
	pending2FATTL = 5 * time.Minute
	recoveryCount = 10
	totpIssuer    = "Guijia"
	totpAccount   = "Guijia"
)

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateTOTPSecret: 20 字节随机 -> base32(无填充, 32 字符)。
func generateTOTPSecret() (string, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return b32NoPad.EncodeToString(b[:]), nil
}

func totpCodeAt(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := b32NoPad.DecodeString(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / int64(totpStep/time.Second))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

// verifyTOTP: 动态码在 ±1 步内任一匹配即通过。
func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for d := -totpWindow; d <= totpWindow; d++ {
		if c, err := totpCodeAt(secret, now.Add(time.Duration(d)*totpStep)); err == nil && hmac.Equal([]byte(c), []byte(code)) {
			return true
		}
	}
	return false
}

func otpauthURL(secret string) string {
	return "otpauth://totp/" + totpIssuer + ":" + totpAccount + "?secret=" + secret + "&issuer=" + totpIssuer
}

// totpQRCodePNG: 把 otpauth URL 编成二维码 PNG 的 data URI(本地生成,
// 绝不走任何外部在线二维码 API)。尺寸 256, 纠错 Medium。
func totpQRCodePNG(secret string) (string, error) {
	png, err := qrcode.Encode(otpauthURL(secret), qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// ---------- 恢复码 ----------

func generateRecoveryCodes() (plain []string, hashed []string, err error) {
	for i := 0; i < recoveryCount; i++ {
		var b [4]byte
		if _, err = rand.Read(b[:]); err != nil {
			return nil, nil, err
		}
		code := fmt.Sprintf("%08d", binary.BigEndian.Uint32(b[:])%100000000)
		plain = append(plain, code)
		h := sha256.Sum256([]byte(code))
		hashed = append(hashed, hex.EncodeToString(h[:]))
	}
	return plain, hashed, nil
}

// consumeRecoveryCode: 命中则删掉并写盘, 返回是否命中。
func consumeRecoveryCode(code string) bool {
	h := sha256.Sum256([]byte(strings.TrimSpace(code)))
	want := hex.EncodeToString(h[:])
	authMu.Lock()
	defer authMu.Unlock()
	for i, c := range auth.RecoveryCodes {
		if hmac.Equal([]byte(c), []byte(want)) {
			auth.RecoveryCodes = append(auth.RecoveryCodes[:i], auth.RecoveryCodes[i+1:]...)
			saveAuthLocked()
			return true
		}
	}
	return false
}

// ---------- 待开通密钥(仅内存, 重启即丢, 需重新获取) ----------

var (
	totpPendingMu     sync.Mutex
	totpPendingSecret string
)

// ---------- 两步登录临时凭证 ----------

type pending2FA struct {
	expires  time.Time
	remember bool
}

var (
	pendingMu sync.Mutex
	pending   = map[string]*pending2FA{}
)

func newPending2FA(remember bool) string {
	tok := newSessionToken()
	pendingMu.Lock()
	defer pendingMu.Unlock()
	now := time.Now()
	for k, v := range pending {
		if now.After(v.expires) {
			delete(pending, k)
		}
	}
	pending[tok] = &pending2FA{expires: now.Add(pending2FATTL), remember: remember}
	return tok
}

// ---------- 接口 ----------

func handleAuthTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	authMu.Lock()
	enabled := auth.TOTPEnabled
	authMu.Unlock()
	if enabled {
		errJSON(w, 400, "2FA 已开通, 请先关闭再重新开通")
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		errJSON(w, 500, "生成失败")
		return
	}
	qr, err := totpQRCodePNG(secret)
	if err != nil {
		errJSON(w, 500, "生成失败")
		return
	}
	totpPendingMu.Lock()
	totpPendingSecret = secret
	totpPendingMu.Unlock()
	writeJSON(w, 200, map[string]string{"secret": secret, "otpauth_url": otpauthURL(secret), "qr": qr})
}

func handleAuthTOTPEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	totpPendingMu.Lock()
	secret := totpPendingSecret
	totpPendingMu.Unlock()
	if secret == "" {
		errJSON(w, 400, "请先获取密钥")
		return
	}
	if !verifyTOTP(secret, in.Code, time.Now()) {
		errJSON(w, 401, "动态码不正确")
		return
	}
	plain, hashed, err := generateRecoveryCodes()
	if err != nil {
		errJSON(w, 500, "生成失败")
		return
	}
	authMu.Lock()
	auth.TOTPSecret = secret
	auth.TOTPEnabled = true
	auth.RecoveryCodes = hashed
	saveAuthLocked()
	authMu.Unlock()
	totpPendingMu.Lock()
	totpPendingSecret = ""
	totpPendingMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "recoveryCodes": plain})
}

func handleAuthTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	authMu.Lock()
	stored := auth.PassHash
	authMu.Unlock()
	if !verifyRescuePassword(in.Password, stored) {
		errJSON(w, 401, "密码错误")
		return
	}
	authMu.Lock()
	auth.TOTPSecret = ""
	auth.TOTPEnabled = false
	auth.RecoveryCodes = nil
	saveAuthLocked()
	authMu.Unlock()
	// 关 2FA 即废全部信任设备: 重开后旧设备一律重新输码。
	clearDeviceTrusts()
	clearDeviceCookie(w)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func handleAuthTOTPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Pending string `json:"pending"`
		Code    string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	pendingMu.Lock()
	p, ok := pending[in.Pending]
	if ok {
		delete(pending, in.Pending)
	}
	pendingMu.Unlock()
	if !ok || time.Now().After(p.expires) {
		errJSON(w, 401, "临时凭证已过期, 请重新登录")
		return
	}
	code := strings.TrimSpace(in.Code)
	authMu.Lock()
	secret := auth.TOTPSecret
	enabled := auth.TOTPEnabled
	authMu.Unlock()
	passed := false
	if enabled && len(code) == 6 {
		passed = verifyTOTP(secret, code, time.Now())
	} else if len(code) == 8 {
		passed = consumeRecoveryCode(code)
	}
	if !passed {
		errJSON(w, 401, "验证码不正确")
		return
	}
	sessMu.Lock()
	s := newSessionLocked(p.remember, clientIP(r))
	sessMu.Unlock()
	setSessionCookie(w, s)
	// 验证通过即信任该设备(绑定当前真实 IP): 下次同 IP 同设备免输动态码。
	recordDeviceTrust(w, r, realIP(r))
	emit(Event{Type: "ui_login", IP: clientIP(r), Detail: "面板登录成功(2FA)"}, settings.AlertUILogin && !isTrusted(clientIP(r)))
	writeJSON(w, 200, map[string]any{"ok": true, "need2fa": false})
}
