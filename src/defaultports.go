package main

// 默认端口实时状态(第 4 项安全建议 + 第 6 项蜜罐警告共用):
// SSH: sshd_config 的 Port(首个生效; 无指令 = 默认 22) > ss 监听 22 的启发式 > 未检测到。
// WEBUI: GUIJIA_WEBUI_PORT 环境变量 > ports.json 中唯一的 kind=ui 端口 > 未检测到。
// 面板端口没有可靠的配置源时, 宁可报"未检测到"也不猜一个错的数字。

import (
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type defaultPortInfo struct {
	Port     int  `json:"port"`
	Detected bool `json:"detected"`
}

func sshdConfigPath() string {
	if p := os.Getenv("GUIJIA_SSHD_CONFIG"); p != "" {
		return p
	}
	return "/etc/ssh/sshd_config"
}

// parseSshdConfig 读 sshd_config 的 Port: OpenSSH 对同一关键字取首个值,
// 注释行跳过。返回 (端口, 是否有明确指令)。
func parseSshdConfig(data []byte) (int, bool) {
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) >= 2 && strings.EqualFold(f[0], "Port") {
			if p, err := strconv.Atoi(f[1]); err == nil && p >= 1 && p <= 65535 {
				return p, true
			}
		}
	}
	return 0, false
}

func detectSSHPort() defaultPortInfo {
	if b, err := os.ReadFile(sshdConfigPath()); err == nil {
		if p, ok := parseSshdConfig(b); ok {
			return defaultPortInfo{Port: p, Detected: true}
		}
		// 配置文件在、无 Port 指令 = 用的就是默认 22
		return defaultPortInfo{Port: 22, Detected: true}
	}
	// 配置文件读不到: 22 在监听 => 启发式认定 22
	if out, err := exec.Command("ss", "-H", "-tln").CombinedOutput(); err == nil {
		if _, listeners := parseSS(string(out), true); listeners != nil {
			if _, ok := listeners[22]; ok {
				return defaultPortInfo{Port: 22, Detected: true}
			}
		}
	}
	return defaultPortInfo{}
}

func detectWebUIPort() defaultPortInfo {
	if p := os.Getenv("GUIJIA_WEBUI_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			return defaultPortInfo{Port: n, Detected: true}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	var ui []int
	for _, p := range ports {
		if p != nil && p.Kind == "ui" {
			ui = append(ui, p.Port)
		}
	}
	if len(ui) == 1 {
		return defaultPortInfo{Port: ui[0], Detected: true}
	}
	return defaultPortInfo{}
}

func handleDefaultPorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", 405)
		return
	}
	writeJSON(w, 200, map[string]any{
		"ssh":   detectSSHPort(),
		"webui": detectWebUIPort(),
	})
}
