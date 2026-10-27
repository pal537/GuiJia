package main

// 面板设置与面板监听:
// - 设置集中三样: 登录封禁次数(默认 5, 可调 1..100, 时长固定 7 天)、改密码、SSL
// - SSL 模式: off=HTTP 原端口; port=同端口或指定端口只走 HTTPS(HTTP 不保留);
//   domain=域名直访, 经 443 前置服务按 SNI 分发(阶段 6 接入; 本阶段只保存+校验,
//   面板仍走 HTTP 原端口, 避免设置一保存面板就失联)
// - 证书复用反代证书表(上传/acme); port 模式证书握手时用构建期快照,
//   续期后由续期流程重建面板监听(阶段 5)
// - 面板监听重建: 设置保存后若面板相关字段变化, 关闭旧监听、按新设置起新监听;
//   证书不可用时回落 HTTP 并记日志, 绝不让面板起不来

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	rootMux      http.Handler
	panelSrvMu   sync.Mutex
	panelSrv     *http.Server
	panelSrvMode string
	panelSrvPort int
)

// validatePanelSettings 校验并归一面板设置(就地改写钳制/归一化后的值)。
func validatePanelSettings(in *Settings) error {
	if in.PanelBanThreshold == 0 {
		in.PanelBanThreshold = 5 // 老客户端不传此键 = 缺省 5
	} else if in.PanelBanThreshold < 1 {
		in.PanelBanThreshold = 1
	} else if in.PanelBanThreshold > 100 {
		in.PanelBanThreshold = 100
	}
	switch in.PanelSSLMode {
	case "", "off":
		in.PanelSSLMode = "off"
	case "port":
		if in.PanelSSLPort < 1 || in.PanelSSLPort > 65535 {
			return errors.New("SSL 端口须在 1-65535")
		}
		if in.PanelSSLCert == "" {
			return errors.New("端口模式须选择证书")
		}
		if _, serving := scanProxyCerts(); serving[in.PanelSSLCert] == nil {
			return errors.New("所选证书不可用(已过期或不存在)")
		}
	case "domain":
		d, err := normalizeDomain(in.PanelDomain)
		if err != nil || d == "" {
			return errors.New("域名直访须填写有效域名")
		}
		in.PanelDomain = d
		if proxyUsesDomain(d) {
			return errors.New("该域名已被反代规则占用")
		}
		if in.PanelSSLCert != "" {
			metas, _ := scanProxyCerts()
			covers := false
			for _, m := range metas {
				if m.ID == in.PanelSSLCert {
					covers = certCoversDomain(m, d)
					break
				}
			}
			if !covers {
				return errors.New("所选证书不覆盖该域名")
			}
		}
		// 证书为空 = 自动匹配: 阶段 6 按域名自动选证书。
	default:
		return errors.New("未知的面板 SSL 模式")
	}
	return nil
}

// proxyUsesDomain: 域名是否已被任一反代规则占用(不论启用与否, 避免启用时才冲突)。
func proxyUsesDomain(d string) bool {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for _, r := range proxyCfg.Rules {
		if r.Domain == d {
			return true
		}
	}
	return false
}

// panelTLSConfig: 端口模式的 TLS 配置(选定证书的构建期快照)。
func panelTLSConfig() (*tls.Config, error) {
	mu.Lock()
	certID := settings.PanelSSLCert
	mu.Unlock()
	if certID == "" {
		return nil, errors.New("未选择证书")
	}
	if _, serving := scanProxyCerts(); serving[certID] != nil {
		return &tls.Config{Certificates: []tls.Certificate{serving[certID].cert}, MinVersion: tls.VersionTLS12}, nil
	}
	return nil, errors.New("所选证书不可用(已过期或不存在)")
}

// startPanelServerLocked 按当前设置起面板监听(调用方须持有 panelSrvMu)。
func startPanelServerLocked() {
	mu.Lock()
	mode := settings.PanelSSLMode
	port := panelPort
	if mode == "port" {
		port = settings.PanelSSLPort
		if port <= 0 {
			port = 59188
		}
	}
	mu.Unlock()
	handler := authMiddleware(rootMux)
	if mode == "domain" {
		frontApply()
		if on, _ := front443Status(); on {
			// 面板走 443 前置(SNI 分发), 不再另起 HTTP 监听。
			panelSrvMode, panelSrvPort = "domain", 443
			panelSrv = nil
			return
		}
		// 443 起不来(被占用等): 回落 HTTP 原端口, 绝不让面板失联。
		fmt.Fprintln(os.Stderr, "panel domain mode: front443 unavailable, falling back to HTTP")
	}
	if mode == "port" {
		if tlsCfg, err := panelTLSConfig(); err == nil {
			panelSrv = &http.Server{Addr: "0.0.0.0:" + itoa(port), Handler: handler, TLSConfig: tlsCfg}
			panelSrvMode, panelSrvPort = "port", port
			// 关键: goroutine 必须捕获局部 server, 绝不能读全局 panelSrv——
			// 重建时全局会被先置 nil 再换新对象, 晚启动的旧 goroutine 读到 nil 会 panic、
			// 读到新对象会用错协议(HTTP 对 TLS 端口)。
			srv := panelSrv
			go func() {
				if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					fmt.Fprintln(os.Stderr, "panel TLS server:", err)
				}
			}()
			return
		} else {
			// 证书不可用: 回落 HTTP, 绝不让面板起不来。
			fmt.Fprintln(os.Stderr, "panel TLS unavailable, falling back to HTTP:", err)
		}
	}
	// off, 以及 domain 模式下 443 前置起不来的回落: 面板仍走 HTTP 原端口。
	panelSrv = &http.Server{Addr: "0.0.0.0:" + itoa(panelPort), Handler: handler}
	panelSrvMode, panelSrvPort = mode, panelPort
	srv := panelSrv
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "panel server:", err)
		}
	}()
}

func startPanelServer() {
	panelSrvMu.Lock()
	defer panelSrvMu.Unlock()
	startPanelServerLocked()
}

// rebuildPanelServer: 设置变更后重建面板监听(旧监听优雅关闭, 最多等 5 秒)。
func rebuildPanelServer() {
	panelSrvMu.Lock()
	defer panelSrvMu.Unlock()
	if panelSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		panelSrv.Shutdown(ctx)
		cancel()
		panelSrv = nil
	}
	startPanelServerLocked()
}

// panelRunning 供测试与状态查询: 当前面板监听模式与端口。
func panelRunning() (string, int) {
	panelSrvMu.Lock()
	defer panelSrvMu.Unlock()
	return panelSrvMode, panelSrvPort
}

// panelInHTTPFallback: 面板域名模式但 443 前置未起、实际走 HTTP 回落时为真。
// (域名模式成功时 panelSrv 为 nil; 回落时 panelSrv 是 HTTP 监听。)
func panelInHTTPFallback() bool {
	panelSrvMu.Lock()
	defer panelSrvMu.Unlock()
	return panelSrvMode == "domain" && panelSrv != nil
}
