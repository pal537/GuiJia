package main

// TG 双模式(多服务器第一期):
// - 默认走主服务器: 节点事件上报主服务器, 主服务器用自己的 bot 统一发,
// 标题带节点服务器名, 按钮带节点指纹(回调路由回节点执行, 不串台)。
// - 可切独立: 节点在设置里切独立通知后用自己的 bot 发, 主服务器收到该
// 节点事件只回绝不发(防双发); 切回走主服务器后恢复。
// - 主服务器挂了: 节点事件本地攒着(ring, 上限 200 条, 落盘), 重连后补推。
// - 独立通知 Token/ChatID 只存 node.json(0600), 绝不进 settings.json、
// 日志与测试; 面板接口只返回 hasToken, 永不回显明文。
// - 边界: 只路由事件(tgSendEvent); 情报失败直发(intel.go tgSend)与日报
// (reportLoop)不走这条路, 被群控 + 走主服务器模式下它们静默(与未配
// 置 bot 的独立机行为一致)。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- 上报队列(ring, 落盘, 主服务器挂了攒着) ----------

const tgHubQueueCap = 200

var tgHubQueueFile string // initPaths 赋值; 单测可直接改写

var (
	hubEvMu      sync.Mutex
	hubEvQueue   []Event
	hubEvLoaded  bool
	hubEvPoke    = make(chan struct{}, 1)
	hubEvRunMu   sync.Mutex
	hubEvRunning bool
)

func hubQueuePath() string {
	if tgHubQueueFile != "" {
		return tgHubQueueFile
	}
	return filepath.Join(dataDir, "tg-hub-queue.json")
}

func hubQueueLoadLocked() {
	if hubEvLoaded {
		return
	}
	hubEvLoaded = true
	b, err := os.ReadFile(hubQueuePath())
	if err != nil {
		return
	}
	var q []Event
	if json.Unmarshal(b, &q) == nil {
		if len(q) > tgHubQueueCap {
			q = q[len(q)-tgHubQueueCap:]
		}
		hubEvQueue = q
	}
}

func hubQueueSaveLocked() {
	b, _ := json.Marshal(hubEvQueue)
	os.WriteFile(hubQueuePath(), b, 0644)
}

func enqueueHubEvent(ev Event) {
	hubEvMu.Lock()
	hubQueueLoadLocked()
	hubEvQueue = append(hubEvQueue, ev)
	if len(hubEvQueue) > tgHubQueueCap {
		hubEvQueue = hubEvQueue[len(hubEvQueue)-tgHubQueueCap:]
	}
	hubQueueSaveLocked()
	hubEvMu.Unlock()
	ensureHubSender()
	pokeHubSender()
}

func hubQueuePopFront() (Event, bool) {
	hubEvMu.Lock()
	defer hubEvMu.Unlock()
	hubQueueLoadLocked()
	if len(hubEvQueue) == 0 {
		return Event{}, false
	}
	ev := hubEvQueue[0]
	hubEvQueue = hubEvQueue[1:]
	hubQueueSaveLocked()
	return ev, true
}

func hubQueuePushFront(ev Event) {
	hubEvMu.Lock()
	defer hubEvMu.Unlock()
	hubEvQueue = append([]Event{ev}, hubEvQueue...)
	hubQueueSaveLocked()
}

func hubQueueLen() int {
	hubEvMu.Lock()
	defer hubEvMu.Unlock()
	hubQueueLoadLocked()
	return len(hubEvQueue)
}

func ensureHubSender() {
	hubEvRunMu.Lock()
	defer hubEvRunMu.Unlock()
	if hubEvRunning {
		return
	}
	hubEvRunning = true
	go tgHubSenderLoop()
}

func pokeHubSender() {
	select {
	case hubEvPoke <- struct{}{}:
	default:
	}
}

func tgHubSenderLoop() {
	for {
		ev, ok := hubQueuePopFront()
		if !ok {
			select {
			case <-hubEvPoke:
			case <-time.After(30 * time.Second):
			}
			continue
		}
		switch postHubEvent(ev) {
		case "local":
			// 主服务器以独立模式回绝: 它不会发, 节点自己在本地发, 不丢不双发。
			hubEventToLocal(ev)
		case "retry":
			hubQueuePushFront(ev)
			time.Sleep(5 * time.Second)
		}
	}
}

// hubEventToLocal 把事件转成本地 TG 消息(标题与指纹走本机)。
func hubEventToLocal(ev Event) {
	text, banBtn, unbanBtn := buildEventText(ev)
	select {
	case tgQueue <- tgMsg{text: text, ip: ev.IP, banOK: banBtn, unbanOK: unbanBtn}:
	default:
	}
}

// flushHubQueueToLocal 切独立时把未上报的事件全部转本地发(已上报成功
// 的不在队列里, 不会重发; 在途的由主服务器侧独立模式回绝后本地补发)。
func flushHubQueueToLocal() {
	hubEvMu.Lock()
	q := hubEvQueue
	hubEvQueue = nil
	hubQueueSaveLocked()
	hubEvMu.Unlock()
	for _, ev := range q {
		hubEventToLocal(ev)
	}
}

// postHubEvent 上报一条事件给主服务器, 返回动作:
// "done"=主服务器已发或确认丢弃, "local"=主服务器以独立模式回绝(本地补发),
// "retry"=传输失败(保留重推)。
func postHubEvent(ev Event) string {
	mu.Lock()
	hubURL := settings.HubURL
	mu.Unlock()
	hubURL = strings.TrimRight(hubURL, "/")
	tok := nodeToken()
	if hubURL == "" || tok == "" {
		return "retry"
	}
	cli := &http.Client{Timeout: 15 * time.Second}
	st, body, err := linkPost(cli, hubURL+"/api/nodes/events", tok, ev)
	if err != nil {
		return "retry"
	}
	if st == 401 || st == 403 {
		// token 已被主服务器吊销(节点被移除): 重推无意义, 丢弃;
		// 拨号循环会处理重配对。
		return "done"
	}
	if st != 200 {
		return "retry"
	}
	var v struct {
		Sent   bool   `json:"sent"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(body, &v) == nil {
		if v.Sent {
			return "done"
		}
		if v.Reason == "independent" {
			return "local"
		}
		return "done" // 主服务器 bot 未配置等不可达原因: 丢弃, 不无限重推
	}
	return "done"
}

// reportTGModeToHub 切模式后立即向主服务器报一次新模式(不等 30 秒心跳),
// 缩小主服务器侧模式镜像滞后的窗口; 失败由下次心跳兜底。
func reportTGModeToHub() {
	if effectiveRunMode() != "managed" {
		return
	}
	mu.Lock()
	hubURL := settings.HubURL
	mu.Unlock()
	hubURL = strings.TrimRight(hubURL, "/")
	tok := nodeToken()
	if hubURL == "" || tok == "" {
		return
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	linkPost(cli, hubURL+"/api/nodes/ping", tok, map[string]any{"version": appVersion, "tgMode": nodeTGMode()})
}

// ---------- 节点 TG 模式接口(仅被群控节点可用, 走主服务器面板代理调用) ----------

func handleNodeTGMode(w http.ResponseWriter, r *http.Request) {
	if effectiveRunMode() != "managed" {
		errJSON(w, 400, "仅被群控节点可用")
		return
	}
	if r.Method == "GET" {
		en, tok, chat := nodeTGConfig()
		mask := ""
		if tok != "" {
			mask = tgTokenMask
		}
		writeJSON(w, 200, map[string]any{
			"mode": nodeTGMode(), "enabled": en, "chatId": chat,
			"hasToken": tok != "", "token": mask,
		})
		return
	}
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Mode    string `json:"mode"`
		Enabled bool   `json:"enabled"`
		Token   string `json:"token"`
		ChatID  string `json:"chatId"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errJSON(w, 400, "请求无效")
		return
	}
	mode := strings.TrimSpace(in.Mode)
	if mode != "hub" && mode != "independent" {
		errJSON(w, 400, "mode 须为 hub 或 independent")
		return
	}
	token := strings.TrimSpace(in.Token)
	chatID := strings.TrimSpace(in.ChatID)
	_, oldTok, oldChat := nodeTGConfig()
	if token == "" || token == tgTokenMask {
		token = oldTok
	}
	if chatID == "" {
		chatID = oldChat
	}
	if len(token) > 200 || len(chatID) > 32 {
		errJSON(w, 400, "参数过长")
		return
	}
	if chatID != "" {
		if _, err := strconv.ParseInt(chatID, 10, 64); err != nil {
			errJSON(w, 400, "Chat ID 须为数字")
			return
		}
	}
	if mode == "independent" && in.Enabled && (token == "" || chatID == "") {
		errJSON(w, 400, "独立通知需填写 Bot Token 与 Chat ID")
		return
	}
	setNodeTGConfig(in.Enabled, token, chatID)
	mu.Lock()
	settings.NodeTGMode = mode
	saveSettings()
	mu.Unlock()
	if mode == "independent" {
		flushHubQueueToLocal()
	}
	go reportTGModeToHub()
	writeJSON(w, 200, map[string]any{"ok": true, "mode": mode})
}

func handleNodeTGModeTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	if effectiveRunMode() != "managed" {
		errJSON(w, 400, "仅被群控节点可用")
		return
	}
	var in struct {
		Token  string `json:"token"`
		ChatID string `json:"chatId"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	token := strings.TrimSpace(in.Token)
	chatID := strings.TrimSpace(in.ChatID)
	_, oldTok, oldChat := nodeTGConfig()
	if token == "" || token == tgTokenMask {
		token = oldTok
	}
	if chatID == "" {
		chatID = oldChat
	}
	if msg := tgModeTestSend(token, chatID); msg != "" {
		if msg == tgRateMsg {
			errJSON(w, 429, msg)
			return
		}
		errJSON(w, 400, msg)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// tgModeTestSend 独立通知连通性测试(走 tgAPICall, 单测可 mock)。
func tgModeTestSend(token, chatID string) string {
	if token == "" || chatID == "" {
		return "Token 或 Chat ID 为空"
	}
	cid, err := strconv.ParseInt(chatID, 10, 64)
	if err != nil {
		return "Chat ID 格式不对(应为数字)"
	}
	tgTestMu.Lock()
	if time.Since(tgTestLast) < 10*time.Second {
		tgTestMu.Unlock()
		return tgRateMsg
	}
	tgTestLast = time.Now()
	tgTestMu.Unlock()
	out, err := tgAPICall(token, "sendMessage", map[string]any{"chat_id": cid, "text": tgWithTitle("测试消息：节点独立通知可用。")}, 15*time.Second)
	if err != nil {
		return "连接 Telegram 失败: " + err.Error()
	}
	if out != nil {
		if ok, _ := out["ok"].(bool); !ok {
			if d, _ := out["description"].(string); d != "" {
				return "Telegram 返回: " + d
			}
			return "Telegram 返回失败"
		}
	}
	return ""
}

// ---------- 主服务器侧: 接收节点事件并代发 ----------

func handleNodeEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	s := nodeAuth(r)
	if s == nil {
		errJSON(w, 401, "节点鉴权失败")
		return
	}
	var ev Event
	if json.NewDecoder(r.Body).Decode(&ev) != nil || ev.Type == "" {
		errJSON(w, 400, "请求无效")
		return
	}
	if ev.IP != "" && net.ParseIP(ev.IP) == nil {
		errJSON(w, 400, "IP 无效")
		return
	}
	if ev.Port < 0 || ev.Port > 65535 {
		ev.Port = 0
	}
	if len(ev.Detail) > 2000 {
		ev.Detail = ev.Detail[:2000]
	}
	if ev.Ts == 0 {
		ev.Ts = nowMs()
	}
	hubMu.Lock()
	s.LastSeen = time.Now().Unix()
	s.Status = "online"
	tgMode, name, fp := s.TGMode, s.Name, s.Fingerprint
	saveServersLocked()
	hubMu.Unlock()
	if tgMode == "independent" {
		// 节点已切独立通知: 它自己发, 主服务器只回绝不发, 防双发。
		writeJSON(w, 200, map[string]any{"ok": true, "sent": false, "reason": "independent"})
		return
	}
	if settings.TGEnabled && settings.TGBotToken != "" && settings.TGChatID != "" {
		hubSendNodeEvent(name, fp, ev)
		writeJSON(w, 200, map[string]any{"ok": true, "sent": true})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "sent": false, "reason": "hub-tg-unconfigured"})
}

// hubSendNodeEvent 主服务器用自己的 bot 代发节点事件: 标题带节点名,
// 按钮带节点指纹(回调经 parseNodeCallback 路由回节点执行)。
func hubSendNodeEvent(nodeName, nodeFP string, ev Event) {
	body, banBtn, unbanBtn := buildEventText(ev)
	title := ""
	if nodeName != "" {
		title = "\n"
	}
	sendTGButtons(settings.TGBotToken, settings.TGChatID, title+body, ev.IP, banBtn, unbanBtn, nodeFP)
}

// ---------- 主服务器代发消息的回调路由(防串台) ----------

// parseNodeCallback: 回调后缀是已登记节点指纹时返回 (指纹, 剥离后数据, true)。
// 本机 serverId 只有 8 位 hex, 节点指纹 64 位, 不会误判; IPv6 地址含冒号
// 也不影响(只看末尾 ":<64 位 hex>")。
func parseNodeCallback(data string) (string, string, bool) {
	if len(data) <= 65 || data[len(data)-65] != ':' {
		return "", "", false
	}
	cand := strings.ToLower(data[len(data)-64:])
	if !validFingerprint(cand) {
		return "", "", false
	}
	hubMu.Lock()
	s := findHubServer(cand)
	hubMu.Unlock()
	if s == nil {
		return "", "", false
	}
	return cand, data[:len(data)-65], true
}

// handleNodeRoutedCallback 主服务器代发节点消息的回调: 拉黑/解封动作经
// 命令通道在节点上执行, 绝不在主服务器本机执行。离线节点只提示不执行。
func handleNodeRoutedCallback(fp, data string, chatID, msgID int64, origText string, answer func(string), editMarkup func(any), editText func(string)) {
	hubMu.Lock()
	online := hubNodeOnline(findHubServer(fp))
	hubMu.Unlock()
	if !online {
		answer("节点离线，无法执行")
		return
	}
	switch {
	case data == "bc":
		editMarkup(nil)
		answer("已取消")
	case strings.HasPrefix(data, "ban:"):
		ip := strings.TrimPrefix(data, "ban:")
		var row []map[string]string
		for _, d := range banDurations {
			row = append(row, map[string]string{"text": d.Label, "callback_data": tgCBFp(fmt.Sprintf("bd:%s:%d", ip, d.Hours), fp)})
		}
		rows := [][]map[string]string{
			row[:4], row[4:],
			{{"text": "取消", "callback_data": tgCBFp("bc", fp)}},
		}
		editMarkup(map[string]any{"inline_keyboard": rows})
		answer("请选择拉黑时长")
	case strings.HasPrefix(data, "bd:"):
		parts := strings.Split(data, ":")
		if len(parts) < 3 {
			return
		}
		hours, _ := strconv.Atoi(parts[len(parts)-1])
		ip := strings.Join(parts[1:len(parts)-1], ":")
		body, _ := json.Marshal(map[string]any{"ip": ip, "hours": hours, "reason": "TG 一键拉黑（主服务器代发）"})
		status, respBody, errKind := hubCallNode(fp, "POST", "/api/bans", body)
		if errKind != "" {
			if errKind == "timeout" {
				answer("节点响应超时")
			} else {
				answer("节点离线，无法执行")
			}
			return
		}
		if status != 200 {
			answer("拉黑失败: " + linkErrBody(respBody))
			return
		}
		var b struct {
			Until int64 `json:"until"`
		}
		json.Unmarshal(respBody, &b)
		until := "永久"
		if b.Until > 0 {
			until = "至 " + time.Unix(b.Until, 0).Format("01-02 15:04")
		}
		editText(origText + "\n—— 已拉黑(" + until + ")")
		answer("已拉黑")
	case strings.HasPrefix(data, "ub:"):
		ip := strings.TrimPrefix(data, "ub:")
		status, _, errKind := hubCallNode(fp, "DELETE", "/api/bans/"+ip, nil)
		if errKind != "" {
			if errKind == "timeout" {
				answer("节点响应超时")
			} else {
				answer("节点离线，无法执行")
			}
			return
		}
		if status == 200 {
			editText(origText + "\n—— 已解封 " + ip)
			answer("已解封")
		} else {
			answer("该 IP 不在黑名单")
		}
	default:
		answer("该操作属于另一台服务器，本服务器不会执行")
	}
}
