package main

// TG 急救全网化(2026-10-28, PAPA 定):
//   超级密码只在主服务器设一个, 子服务器不单独设——被控期间子服务器本地
//   面板本就是只读状态页, TG 也走主服务器 bot, 本地密码够不着;
//   脱离后本地密码(如曾设置过)恢复效力, 数据不删, 只改效力范围。
//   主服务器 bot 的急救菜单默认作用于本机 + 全部在线子服务器:
//   信任 IP / 解封全部 / 关闭所有拦截 / 恢复防护, 逐台执行、逐台汇报,
//   离线节点只跳过不报错(下次在线不补做, 急救是当面动作不是同步任务)。
//   面板上的“恢复防护”按钮仍是单台视图语义(看哪台恢复哪台), 与 TG 全网
//   菜单区分, 不混用。节点侧接口只认 X-Guijia-Internal 头, 与群控同步
//   同 guard: 面板代理调它只会拿到 403, 无法伪造。

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// rescueOnlineNodes 在线子服务器快照(名 + 指纹), 供急救扇出与菜单文案共用。
func rescueOnlineNodes() []struct {
	Name string
	FP   string
} {
	hubMu.Lock()
	defer hubMu.Unlock()
	var out []struct {
		Name string
		FP   string
	}
	for _, s := range hubServers {
		if s != nil && hubNodeOnline(s) {
			out = append(out, struct {
				Name string
				FP   string
			}{s.Name, s.Fingerprint})
		}
	}
	return out
}

// rescueScopeSuffix 急救菜单的作用范围后缀: 无在线节点时为空(行为与单机完全一致)。
func rescueScopeSuffix() string {
	nodes := rescueOnlineNodes()
	if len(nodes) == 0 {
		return ""
	}
	return "\n作用范围：本机 + 全部在线子服务器（" + itoa(len(nodes)) + " 台，离线跳过）"
}

func rescueMenuText() string {
	return "🆘 急救菜单\n\n信任 IP：解封并加入信任名单（不再自动拉黑）。\n解封全部：放掉全部生效封禁，记录保留。\n关闭所有拦截：解封全部 + 关掉自动拦截开关，30 分钟后自动恢复。" + rescueScopeSuffix()
}

// ---------- 节点侧内部接口(主服务器扇出用) ----------

func rescueInternalGuard(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Guijia-Internal") != "1" {
		errJSON(w, 403, "仅主服务器内部急救可调用")
		return false
	}
	return true
}

func handleRescueNodeTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if !rescueInternalGuard(w, r) {
		return
	}
	var in struct {
		IP string `json:"ip"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	ip := strings.TrimSpace(in.IP)
	if net.ParseIP(ip) == nil {
		errJSON(w, 400, "IP 格式无效")
		return
	}
	released := releaseBan(ip)
	already, err := trustIP(ip)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	pushEvent(Event{Type: "rescue", IP: ip, Detail: "急救：信任 IP " + ip + "（主服务器扇出）"})
	writeJSON(w, 200, map[string]any{"ok": true, "released": released, "already": already})
}

func handleRescueNodeUnbanAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if !rescueInternalGuard(w, r) {
		return
	}
	n := rescueUnbanAll()
	pushEvent(Event{Type: "rescue", Detail: "急救：解封全部（" + itoa(n) + " 条，记录保留，主服务器扇出）"})
	writeJSON(w, 200, map[string]any{"ok": true, "count": n})
}

func handleRescueNodeKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if !rescueInternalGuard(w, r) {
		return
	}
	rescueActivateKill(time.Now())
	writeJSON(w, 200, map[string]any{"ok": true})
}

func handleRescueNodeRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if !rescueInternalGuard(w, r) {
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "restored": rescueRestore()})
}

// ---------- 主服务器扇出(本机先执行, 再逐台推在线节点) ----------

// rescueTrustLocal 本机信任一行(供扇出与已先做本机的分支共用)。
func rescueTrustLocal(ip string) string {
	released := releaseBan(ip)
	already, _ := trustIP(ip)
	suffix := ""
	if released {
		suffix = "（已同时解封）"
	} else if already {
		suffix = "（已在信任名单）"
	}
	pushEvent(Event{Type: "rescue", IP: ip, Detail: "急救：信任 IP " + ip})
	return "本机：已信任 " + ip + suffix
}

// rescueTrustNodes 只推在线节点, 返回节点汇报行(本机已另行处理时用)。
func rescueTrustNodes(ip string) []string {
	lines := []string{}
	for _, nd := range rescueOnlineNodes() {
		body, _ := json.Marshal(map[string]any{"ip": ip})
		status, respBody, errKind := hubCallNodeInternal(nd.FP, "POST", "/api/rescue/trust-node", body, true)
		if errKind != "" || status != 200 {
			lines = append(lines, nd.Name+"：失败（"+proxyErrMessage(nd.FP, errKind)+"）")
			continue
		}
		var v struct {
			Released bool `json:"released"`
			Already  bool `json:"already"`
		}
		_ = json.Unmarshal(respBody, &v)
		s := ""
		if v.Released {
			s = "（已同时解封）"
		} else if v.Already {
			s = "（已在信任名单）"
		}
		lines = append(lines, nd.Name+"：已信任 "+ip+s)
	}
	return lines
}

// rescueFanoutTrust 信任 IP: 本机 + 全部在线节点。返回逐台汇报行。
func rescueFanoutTrust(ip string) []string {
	return append([]string{rescueTrustLocal(ip)}, rescueTrustNodes(ip)...)
}

// rescueFanoutUnbanAll 解封全部: 本机 + 全部在线节点。返回逐台汇报行。
func rescueFanoutUnbanAll() []string {
	lines := []string{}
	n := rescueUnbanAll()
	pushEvent(Event{Type: "rescue", Detail: "急救：解封全部（" + itoa(n) + " 条，记录保留）"})
	lines = append(lines, "本机：已解封 "+itoa(n)+" 条")
	for _, nd := range rescueOnlineNodes() {
		status, respBody, errKind := hubCallNodeInternal(nd.FP, "POST", "/api/rescue/unban-node", nil, true)
		if errKind != "" || status != 200 {
			lines = append(lines, nd.Name+"：失败（"+proxyErrMessage(nd.FP, errKind)+"）")
			continue
		}
		var v struct {
			Count int `json:"count"`
		}
		_ = json.Unmarshal(respBody, &v)
		lines = append(lines, nd.Name+"：已解封 "+itoa(v.Count)+" 条")
	}
	return lines
}

// rescueFanoutKill 关闭所有拦截: 本机 + 全部在线节点, 各机 30 分钟后按各自快照自动恢复。
func rescueFanoutKill() []string {
	lines := []string{}
	rescueActivateKill(time.Now())
	lines = append(lines, "本机：已关闭所有拦截")
	for _, nd := range rescueOnlineNodes() {
		status, _, errKind := hubCallNodeInternal(nd.FP, "POST", "/api/rescue/kill-node", nil, true)
		if errKind != "" || status != 200 {
			lines = append(lines, nd.Name+"：失败（"+proxyErrMessage(nd.FP, errKind)+"）")
			continue
		}
		lines = append(lines, nd.Name+"：已关闭所有拦截")
	}
	return lines
}

// rescueFanoutRestore 恢复防护: 本机 + 全部在线节点, 未处于急救模式的台只汇报不动作。
func rescueFanoutRestore() []string {
	lines := []string{}
	if rescueRestore() {
		lines = append(lines, "本机：已按快照恢复防护")
	} else {
		lines = append(lines, "本机：当前未处于急救模式")
	}
	for _, nd := range rescueOnlineNodes() {
		status, respBody, errKind := hubCallNodeInternal(nd.FP, "POST", "/api/rescue/restore-node", nil, true)
		if errKind != "" || status != 200 {
			lines = append(lines, nd.Name+"：失败（"+proxyErrMessage(nd.FP, errKind)+"）")
			continue
		}
		var v struct {
			Restored bool `json:"restored"`
		}
		_ = json.Unmarshal(respBody, &v)
		if v.Restored {
			lines = append(lines, nd.Name+"：已按快照恢复防护")
		} else {
			lines = append(lines, nd.Name+"：当前未处于急救模式")
		}
	}
	return lines
}
