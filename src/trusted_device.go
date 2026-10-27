// 信任设备(2FA 免输): SecretDock 定法, 面板同样适用——
// 2FA 开通后, 只有换 IP 或换设备才重新输动态码, 同 IP 同设备凭密码直接登。
//
// 实现:
//   - 设备 = 一枚随机 cookie(guijia_device), 服务端只存其 SHA-256,
//     记录绑定首次验证通过时的真实 IP, 90 天有效;
//   - 登录时 2FA 已开且设备 cookie 有效、绑定 IP 与当前真实 IP 一致,
//     直接发 session, 不走动态码; 任一条件不符就走正常 2FA, 验证通过
//     后刷新该设备的绑定 IP(设备换了出口 IP, 认一次码就重新信任);
//   - 改密、关 2FA 时清空全部信任记录(改密不踢当前 session, 但下次
//     登录一律重新输码); 登出不清信任(信任针对设备, 不是会话);
//   - 真实 IP 取法见 realIP: 只有经本机回环来的请求(即 nginx 反代)
//     才信 X-Real-IP/X-Forwarded-For, 直连面板端口的请求一律不信,
//     防止伪造头绕过 IP 绑定; 取不到可信 IP 时默认不信任(宁可多输一次码)。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const deviceCookieName = "guijia_device"
const deviceTrustTTL = 90 * 24 * time.Hour

type deviceTrust struct {
	Hash     string `json:"hash"`
	IP       string `json:"ip"`
	Expires  int64  `json:"expires"`
	LastSeen int64  `json:"lastSeen"`
}

var (
	deviceTrustMu     sync.Mutex
	deviceTrusts      []*deviceTrust
	deviceTrustLoaded bool
)

func deviceTrustPath() string { return filepath.Join(dataDir, "device_trust.json") }

func ensureDeviceTrustsLoaded() {
	deviceTrustMu.Lock()
	defer deviceTrustMu.Unlock()
	if deviceTrustLoaded {
		return
	}
	deviceTrustLoaded = true
	if b, err := os.ReadFile(deviceTrustPath()); err == nil {
		json.Unmarshal(b, &deviceTrusts)
	}
	now := time.Now().Unix()
	kept := deviceTrusts[:0]
	for _, d := range deviceTrusts {
		if d != nil && d.Expires >= now {
			kept = append(kept, d)
		}
	}
	deviceTrusts = kept
}

// saveDeviceTrustsLocked 落盘(0600, 与 auth.json 同级; 调用方须持有 deviceTrustMu)。
func saveDeviceTrustsLocked() {
	b, _ := json.MarshalIndent(deviceTrusts, "", "  ")
	os.WriteFile(deviceTrustPath(), b, 0600)
}

func deviceTokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// realIP 取真实客户端 IP: 回环来源才信反代头, 其余一律用连接地址。
func realIP(r *http.Request) string {
	host := remoteHost(r.RemoteAddr)
	if ip := net.ParseIP(stripZone(host)); ip != nil && ip.IsLoopback() {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			if pip := net.ParseIP(v); pip != nil {
				return pip.String()
			}
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			for _, part := range strings.Split(v, ",") {
				if pip := net.ParseIP(strings.TrimSpace(part)); pip != nil {
					return pip.String()
				}
			}
		}
	}
	return host
}

func remoteHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// trustedDevice: 设备 cookie 有效、未过期、绑定 IP 与当前真实 IP 一致。
func trustedDevice(r *http.Request) bool {
	ensureDeviceTrustsLoaded()
	c, err := r.Cookie(deviceCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	ip := realIP(r)
	if ip == "" {
		return false
	}
	h := deviceTokenHash(c.Value)
	deviceTrustMu.Lock()
	defer deviceTrustMu.Unlock()
	now := time.Now().Unix()
	for _, d := range deviceTrusts {
		if d.Hash == h {
			if d.Expires < now || d.IP != ip {
				return false
			}
			d.LastSeen = now
			return true
		}
	}
	return false
}

// recordDeviceTrust: 2FA 验证通过后信任该设备。请求里已有设备 cookie
// 则复用(只更新绑定 IP 与有效期, 不堆积记录), 否则发新 cookie。
func recordDeviceTrust(w http.ResponseWriter, r *http.Request, ip string) {
	if ip == "" {
		return
	}
	ensureDeviceTrustsLoaded()
	tok := ""
	if c, err := r.Cookie(deviceCookieName); err == nil {
		tok = c.Value
	}
	if tok == "" {
		tok = newSessionToken()
	}
	h := deviceTokenHash(tok)
	now := time.Now()
	deviceTrustMu.Lock()
	var d *deviceTrust
	for _, x := range deviceTrusts {
		if x.Hash == h {
			d = x
			break
		}
	}
	if d == nil {
		d = &deviceTrust{Hash: h}
		deviceTrusts = append(deviceTrusts, d)
	}
	d.IP = ip
	d.Expires = now.Add(deviceTrustTTL).Unix()
	d.LastSeen = now.Unix()
	saveDeviceTrustsLocked()
	deviceTrustMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     deviceCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  now.Add(deviceTrustTTL),
		Secure:   panelTLSEnabled(),
	})
}

// clearDeviceTrusts 清空全部信任记录(改密、关 2FA 时调用)。
func clearDeviceTrusts() {
	ensureDeviceTrustsLoaded()
	deviceTrustMu.Lock()
	deviceTrusts = []*deviceTrust{}
	saveDeviceTrustsLocked()
	deviceTrustMu.Unlock()
}

func clearDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: deviceCookieName, Value: "", Path: "/", MaxAge: -1})
}
