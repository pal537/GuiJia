package main

// 面板端口改动: 写环境文件 + 延迟自重启。
// - 只改 GUIJIA_PORT 一行, 保留 DATA_DIR 等已有项; 文件不存在则新建。
// - 端口校验 1-65535, 且未被其他进程占用(起监听探一下即放);
//   与当前面板端口相同视为未改动, 只同步文件、不重启。
// - 先回包成功, 再 goroutine 睡 1 秒执行 systemctl restart guijia
//   (与 cli.go 的 cliTryRestart 同一条命令, 只是延迟到回包之后);
//   无 systemctl 时只保存文件, 回包明确告知需手动重启, 绝不静默失败。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// panelEnvFile: systemd 单元 EnvironmentFile 读的面板环境文件, 测试可替换。
var panelEnvFile = "/etc/default/guijia"

// panelRestartFunc: 延迟自重启(默认睡 1 秒后 systemctl restart guijia)。
// 抽成变量只为测试可拦截, 生产行为不变。
var panelRestartFunc = func() {
	time.Sleep(time.Second)
	cmd := exec.Command("systemctl", "restart", "guijia")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintln(os.Stderr, "panel port restart failed:", strings.TrimSpace(string(out)))
	}
}

// probePortFree: 尝试监听一下, 能绑上即空闲(立即释放)。
func probePortFree(port int) error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return errors.New("端口已被占用")
	}
	ln.Close()
	return nil
}

// writePanelEnvPort: 改写环境文件里的 GUIJIA_PORT, 其余行原样保留。
func writePanelEnvPort(path string, port int) error {
	var out []string
	found := false
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "GUIJIA_PORT=") {
				out = append(out, fmt.Sprintf("GUIJIA_PORT=%d", port))
				found = true
			} else {
				out = append(out, line)
			}
		}
	}
	if !found {
		out = append(out, fmt.Sprintf("GUIJIA_PORT=%d", port))
	}
	data := strings.Join(out, "\n")
	if !strings.HasSuffix(data, "\n") {
		data += "\n"
	}
	return os.WriteFile(path, []byte(data), 0644)
}

// isDockerEnv: 是否跑在容器里(/.dockerenv 存在即判定)。
func isDockerEnv() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// handlePanelPort: 改面板端口。回包 restart: none(未变)/auto(将自动重启)/manual(需手动重启)。
func handlePanelPort(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Port int `json:"port"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	if in.Port < 1 || in.Port > 65535 {
		errJSON(w, 400, "端口须在 1-65535")
		return
	}
	cur := appPort()
	if in.Port != cur {
		if err := probePortFree(in.Port); err != nil {
			errJSON(w, 400, err.Error())
			return
		}
	}
	if err := writePanelEnvPort(panelEnvFile, in.Port); err != nil {
		errJSON(w, 500, "写入面板环境文件失败: "+err.Error())
		return
	}
	if in.Port == cur {
		writeJSON(w, 200, map[string]any{"ok": true, "port": in.Port, "restart": "none"})
		return
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		writeJSON(w, 200, map[string]any{"ok": true, "port": in.Port, "restart": "manual", "docker": isDockerEnv()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "port": in.Port, "restart": "auto"})
	go panelRestartFunc()
}
