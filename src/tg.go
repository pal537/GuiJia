package main

// Telegram: 报警推送(带一键拉黑两段式按钮)、机器人长轮询(只认配置的 Chat ID)、每日日报
// 拉黑流程: 报警消息按钮「拉黑此 IP」-> 原消息键盘切换为时长选择 -> 点时长执行 ipset 拉黑

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type tgMsg struct {
	text    string
	ip      string // 非空时附拉黑按钮
	banOK   bool
	unbanOK bool // 非空时附解封按钮(防火墙封禁用: 只解封, 不加信任)
}

var tgQueue = make(chan tgMsg, 100)

func tgConfigured() bool {
	// 被群控节点: 走主服务器模式下本机无 bot(事件上报主服务器), 本地判定为未配置;
	// 独立模式下用 node.json 里的独立配置判定。
	if effectiveRunMode() == "managed" {
		if nodeTGMode() == "independent" {
			en, tok, chat := nodeTGConfig()
			return en && tok != "" && chat != ""
		}
		return false
	}
	return settings.TGEnabled && settings.TGBotToken != "" && settings.TGChatID != ""
}

// tgActiveToken/tgActiveChatID 生效中的 bot 凭据: 被群控 + 独立模式用
// node.json 的独立配置, 其余走 settings(独立机与主服务器本机)。
func tgActiveToken() string {
	if effectiveRunMode() == "managed" && nodeTGMode() == "independent" {
		_, tok, _ := nodeTGConfig()
		return tok
	}
	return settings.TGBotToken
}

func tgActiveChatID() string {
	if effectiveRunMode() == "managed" && nodeTGMode() == "independent" {
		_, _, chat := nodeTGConfig()
		return chat
	}
	return settings.TGChatID
}

// tgAPICall 是 var 而非 func, 便于单测 mock 注入(生产走真实 Telegram API)。
// token 由调用方显式传入: 本机路径用 tgActiveToken(), 主服务器代发节点事件
// 时用主服务器自己的 settings Token。
var tgAPICall = func(token, method string, payload any, timeout time.Duration) (map[string]any, error) {
	b, _ := json.Marshal(payload)
	cli := &http.Client{Timeout: timeout}
	resp, err := cli.Post("https://api.telegram.org/bot"+token+"/"+method, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return out, nil
}

// tgAPI 本机 bot 调用(兼容旧 mock: 单测可整体替换 tgAPI)。
var tgAPI = func(method string, payload any, timeout time.Duration) (map[string]any, error) {
	return tgAPICall(tgActiveToken(), method, payload, timeout)
}

// ---------- TG 通知标题与服务器指纹 ----------

// tgHostname 可注入(单测 stub 失败/空值); 生产走 os.Hostname。
var tgHostname = os.Hostname

// tgServerDisplayName: 用户填的服务器名优先, 否则系统 hostname, 都取不到则空。
func tgServerDisplayName() string {
	if s := strings.TrimSpace(settings.ServerName); s != "" {
		return s
	}
	if h, err := tgHostname(); err == nil {
		return strings.TrimSpace(h)
	}
	return ""
}

// tgTitlePrefix: 标题行「【<服务器名>】\n」; 无名时返回空(绝不发「【】」空标题)。
func tgTitlePrefix() string {
	if name := tgServerDisplayName(); name != "" {
		return "【" + name + "】\n"
	}
	return ""
}

// tgWithTitle: 给一条新 TG 消息加标题; 已带当前标题的不重复加。
func tgWithTitle(text string) string {
	p := tgTitlePrefix()
	if p == "" || strings.HasPrefix(text, p) {
		return text
	}
	return p + text
}

// tgCB: 回调数据加服务器指纹(多台服务器共用一个机器人时防串台)。
// 指纹空时原样返回(生产里 loadAll 已生成, 正常走不到这支)。
func tgCB(data string) string {
	if settings.ServerID == "" {
		return data
	}
	return data + ":" + settings.ServerID
}

// tgCheckCallback: 校验并剥离回调指纹。指纹不符(含缺失)时拒绝执行;
// 本机指纹空时无法校验, 原样放行(生产里 loadAll 已生成, 正常走不到这支)。
func tgCheckCallback(data string) (string, bool) {
	fp := settings.ServerID
	if fp == "" {
		return data, true
	}
	suffix := ":" + fp
	if !strings.HasSuffix(data, suffix) {
		return "", false
	}
	return strings.TrimSuffix(data, suffix), true
}

// tgCBFp 回调数据加指定指纹后缀(主服务器代发节点事件时用节点指纹,
// 本机消息用 tgCB 走本机 serverId)。指纹空时原样返回。
func tgCBFp(data, fp string) string {
	if fp == "" {
		return data
	}
	return data + ":" + fp
}

func tgSend(text string, ip string, banBtn bool) {
	tgSendButtons(text, ip, banBtn, false)
}

// tgSendButtons 本机 bot 发送: 标题用本机名、回调后缀用本机 serverId。
func tgSendButtons(text string, ip string, banBtn bool, unbanBtn bool) {
	sendTGButtons(tgActiveToken(), tgActiveChatID(), tgWithTitle(text), ip, banBtn, unbanBtn, settings.ServerID)
}

// sendTGButtons 通用发送: 标题与回调后缀由调用方显式给定(主服务器代发
// 节点事件时标题=节点名、后缀=节点指纹; 本机路径由 tgSendButtons 包装)。
func sendTGButtons(token, chatIDStr, fullText, ip string, banBtn, unbanBtn bool, cbSuffix string) {
	chatID, _ := strconv.ParseInt(chatIDStr, 10, 64)
	payload := map[string]any{
		"chat_id": chatID, "text": fullText, "disable_web_page_preview": true,
	}
	if banBtn && ip != "" {
		payload["reply_markup"] = map[string]any{
			"inline_keyboard": [][]map[string]string{
				{{"text": "拉黑此 IP", "callback_data": tgCBFp("ban:"+ip, cbSuffix)}},
			},
		}
	} else if unbanBtn && ip != "" {
		payload["reply_markup"] = map[string]any{
			"inline_keyboard": [][]map[string]string{
				{{"text": "解除封禁", "callback_data": tgCBFp("ub:"+ip, cbSuffix)}},
			},
		}
	}
	tgAPICall(token, "sendMessage", payload, 15*time.Second)
}

func eventTitle(t string) string {
	switch t {
	case "ssh_login":
		return "SSH 登录成功"
	case "ui_login":
		return "面板登录"
	case "autoban":
		return "爆破自动拉黑"
	case "new_conn":
		return "重点端口新连接"
	case "new_listener":
		return "新监听端口"
	case "port_flood":
		return "🚨 重点端口洪峰告警(疑似分布式爆破)"
	case "rescue":
		return "🆘 急救操作"
	case "port_scan":
		return "端口扫描"
	case "honeypot_hit":
		return "蜜罐命中"
	case "honeypot_ban":
		return "蜜罐封禁"
	case "honeypot_status":
		return "蜜罐状态"
	case "portguard_ban":
		return "防火墙封禁"
	}
	return t
}

// buildEventText 事件通知正文(不含标题): 本机发送与主服务器代发共用。
// 归属地优先用事件自带的 Geo(节点已查好), 没有再本地查。
func buildEventText(ev Event) (string, bool, bool) {
	var sb strings.Builder
	sb.WriteString(eventTitle(ev.Type) + "\n")
	sb.WriteString("时间: " + time.UnixMilli(ev.Ts).Format("2006-01-02 15:04:05") + "\n")
	if ev.IP != "" {
		sb.WriteString("IP: " + ev.IP + "\n")
		geo := ev.Geo
		if geo == "" {
			geo = geoLookup(ev.IP).Text
		}
		sb.WriteString("归属地: " + geo + "\n")
	}
	if ev.Port > 0 {
		sb.WriteString("端口: " + strconv.Itoa(ev.Port) + "\n")
	}
	sb.WriteString(ev.Detail)
	banBtn := (ev.Type == "ssh_login" || ev.Type == "ui_login" || ev.Type == "new_conn") && ev.IP != ""
	unbanBtn := ev.Type == "portguard_ban" && ev.IP != ""
	return sb.String(), banBtn, unbanBtn
}

// 报警入口(采集层调用): 入队异步发送, 不阻塞采样。
// 路由在事件进入时定一次: 被群控 + 走主服务器模式 -> 上报主服务器队列
// (主服务器挂了本地攒着, 不走本机 bot); 其余走本机 tgQueue。
// 注意: 切独立后本机队列里已排队的消息仍会按旧路径发出, 属亚秒级竞态,
// 不会双发(主服务器侧收到独立模式事件只回绝不发, 见 handleNodeEvents)。
func tgSendEvent(ev Event) {
	if ev.Ts == 0 {
		ev.Ts = nowMs() // 双保险: 无论哪条路径进来, 通知时间都不许是 1970
	}
	if effectiveRunMode() == "managed" && nodeTGMode() == "hub" {
		enqueueHubEvent(ev)
		return
	}
	if !tgConfigured() {
		return
	}
	text, banBtn, unbanBtn := buildEventText(ev)
	select {
	case tgQueue <- tgMsg{text: text, ip: ev.IP, banOK: banBtn, unbanOK: unbanBtn}:
	default:
	}
}

var banDurations = []struct {
	Label string
	Hours int
}{
	{"1 小时", 1}, {"6 小时", 6}, {"24 小时", 24},
	{"3 天", 72}, {"7 天", 168}, {"30 天", 720}, {"永久", 0},
}

func tgLoop() {
	go tgPoller()
	for m := range tgQueue {
		if tgConfigured() {
			tgSendButtons(m.text, m.ip, m.banOK, m.unbanOK)
		}
	}
}

func tgPoller() {
	var offset int64
	for {
		if !tgConfigured() {
			time.Sleep(10 * time.Second)
			continue
		}
		res, err := tgAPI("getUpdates", map[string]any{
			"offset": offset, "timeout": 25, "allowed_updates": []string{"callback_query", "message"},
		}, 35*time.Second)
		if err != nil || res == nil {
			time.Sleep(5 * time.Second)
			continue
		}
		arr, _ := res["result"].([]any)
		for _, it := range arr {
			u, _ := it.(map[string]any)
			if u == nil {
				continue
			}
			if id, ok := u["update_id"].(float64); ok {
				offset = int64(id) + 1
			}
			cb, _ := u["callback_query"].(map[string]any)
			if cb == nil {
				if m, ok := u["message"].(map[string]any); ok {
					handleTGMessage(m)
				}
				continue
			}
			handleCallback(cb)
		}
	}
}

func handleCallback(cb map[string]any) {
	data, _ := cb["data"].(string)
	cbID, _ := cb["id"].(string)
	msg, _ := cb["message"].(map[string]any)
	if msg == nil {
		return
	}
	chat, _ := msg["chat"].(map[string]any)
	chatID := int64(0)
	if chat != nil {
		if f, ok := chat["id"].(float64); ok {
			chatID = int64(f)
		}
	}
	want, _ := strconv.ParseInt(tgActiveChatID(), 10, 64)
	if chatID != want {
		tgAPI("answerCallbackQuery", map[string]any{"callback_query_id": cbID, "text": "无权操作"}, 10*time.Second)
		return
	}
	msgID := int64(0)
	if f, ok := msg["message_id"].(float64); ok {
		msgID = int64(f)
	}
	origText, _ := msg["text"].(string)
	answer := func(text string) {
		tgAPI("answerCallbackQuery", map[string]any{"callback_query_id": cbID, "text": text}, 10*time.Second)
	}
	editMarkup := func(kb any) {
		p := map[string]any{"chat_id": chatID, "message_id": msgID}
		if kb != nil {
			p["reply_markup"] = kb
		} else {
			p["reply_markup"] = map[string]any{"inline_keyboard": []any{}}
		}
		tgAPI("editMessageReplyMarkup", p, 10*time.Second)
	}
	editText := func(text string) {
		tgAPI("editMessageText", map[string]any{"chat_id": chatID, "message_id": msgID, "text": text}, 10*time.Second)
	}
	// 多服务器防串台: 指纹不符的回调只提示, 绝不执行任何解封/拉黑/信任动作。
	// 例外: 后缀是已登记节点的指纹时, 属主服务器代发该节点的消息, 路由到节点执行。
	if data != "" {
		stripped, ok := tgCheckCallback(data)
		if !ok {
			if fp, rest, ok := parseNodeCallback(data); ok {
				handleNodeRoutedCallback(fp, rest, chatID, msgID, origText, answer, editMarkup, editText)
				return
			}
			answer("该操作属于另一台服务器，本服务器不会执行")
			return
		}
		data = stripped
	}

	if data == "rescue" {
		editText(rescueMenuText())
		editMarkup(map[string]any{"inline_keyboard": rescueMenuKB()})
		answer("急救菜单")
		return
	}
	if data == "res:trust" {
		active := activeBans()
		var rows [][]map[string]string
		shown := 0
		for _, b := range active {
			if shown >= 30 {
				break
			}
			rows = append(rows, []map[string]string{{"text": "信任 " + b.IP, "callback_data": tgCB("rt:" + b.IP)}})
			shown++
		}
		rows = append(rows, []map[string]string{{"text": "取消", "callback_data": tgCB("res:cancel")}})
		txt := "点一个解封并信任，或直接发送一个 IP（10 分钟内有效）。"
		if len(rescueOnlineNodes()) > 0 {
			txt += "信任将同时作用于本机与全部在线子服务器。"
		}
		if len(active) == 0 {
			txt = "当前没有生效中的封禁。直接发送一个 IP 即可解封并信任（10 分钟内有效）。"
		} else if len(active) > 30 {
			txt = "点一个解封并信任（仅显示前 30 条），或直接发送一个 IP（10 分钟内有效）。"
		}
		setRescuePendingTrust()
		editText(txt)
		editMarkup(map[string]any{"inline_keyboard": rows})
		answer("请选择或直接发送 IP")
		return
	}
	if strings.HasPrefix(data, "rt:") {
		ip := strings.TrimPrefix(data, "rt:")
		if len(rescueOnlineNodes()) > 0 {
			lines := rescueFanoutTrust(ip)
			editText(origText + "\n—— " + strings.Join(lines, "\n—— "))
			answer("已信任")
			clearRescuePendingTrust()
			return
		}
		released := releaseBan(ip)
		already, _ := trustIP(ip)
		suffix := "（已在信任名单）"
		if released {
			suffix = "（已同时解封）"
		} else if !already {
			suffix = ""
		}
		editText(origText + "\n—— 已信任 " + ip + suffix)
		answer("已信任")
		pushEvent(Event{Type: "rescue", IP: ip, Detail: "急救：信任 IP " + ip})
		clearRescuePendingTrust()
		return
	}
	if strings.HasPrefix(data, "tc:") {
		ip := strings.TrimPrefix(data, "tc:")
		if len(rescueOnlineNodes()) > 0 {
			lines := rescueFanoutTrust(ip)
			editText(origText + "\n—— " + strings.Join(lines, "\n—— "))
			answer("已信任")
			return
		}
		already, err := trustIP(ip)
		if err != nil {
			answer("信任失败：" + err.Error())
			return
		}
		released := releaseBan(ip)
		suffix := ""
		if released {
			suffix = "（已同时解封）"
		} else if already {
			suffix = "（已在信任名单）"
		}
		editText(origText + "\n—— 已信任 " + ip + suffix)
		answer("已信任")
		pushEvent(Event{Type: "rescue", IP: ip, Detail: "急救：信任 IP " + ip})
		return
	}
	if strings.HasPrefix(data, "ub:") {
		ip := strings.TrimPrefix(data, "ub:")
		if releaseBan(ip) {
			editText(origText + "\n—— 已解封 " + ip)
			answer("已解封")
			pushEvent(Event{Type: "unban", IP: ip, Detail: "TG 解除封禁"})
		} else {
			answer("该 IP 不在黑名单")
		}
		return
	}
	if data == "res:unbanall" || data == "res:kill" {
		mu.Lock()
		hasPw := settings.RescuePassHash != ""
		mu.Unlock()
		if !hasPw {
			answer("请先在网页端设置急救超级密码")
			return
		}
		if time.Now().Unix() < rescueLockedUntil() {
			answer("急救功能已锁定，请稍后再试")
			return
		}
		act := "unbanall"
		if data == "res:kill" {
			act = "kill"
		}
		setRescuePendingPass(act)
		answer("请发送超级密码")
		tgSendDirect(chatID, "请输入超级密码（10 分钟内有效；验证后机器人会删除这条消息）", nil)
		return
	}
	if data == "res:restore" {
		if len(rescueOnlineNodes()) > 0 {
			lines := rescueFanoutRestore()
			editText(origText + "\n—— " + strings.Join(lines, "\n—— "))
			answer("已恢复防护")
			return
		}
		if rescueRestore() {
			editText(origText + "\n—— 已按快照恢复防护")
			answer("已恢复防护")
		} else {
			answer("当前未处于急救模式")
		}
		return
	}
	if data == "res:cancel" {
		clearRescuePendingPass()
		clearRescuePendingTrust()
		editMarkup(nil)
		answer("已取消")
		return
	}
	if strings.HasPrefix(data, "ban:") {
		ip := strings.TrimPrefix(data, "ban:")
		if ok, why := bannable(ip); !ok {
			answer(why)
			return
		}
		var row []map[string]string
		for _, d := range banDurations {
			row = append(row, map[string]string{"text": d.Label, "callback_data": tgCB(fmt.Sprintf("bd:%s:%d", ip, d.Hours))})
		}
		rows := [][]map[string]string{
			row[:4], row[4:],
			{{"text": "取消", "callback_data": tgCB("bc")}},
		}
		editMarkup(map[string]any{"inline_keyboard": rows})
		answer("请选择拉黑时长")
		return
	}
	if strings.HasPrefix(data, "bd:") {
		parts := strings.Split(data, ":")
		// bd:<ip>:<hours> — IPv6 地址含冒号, 从末尾取 hours, 中间拼回 IP
		if len(parts) < 3 {
			return
		}
		hours, _ := strconv.Atoi(parts[len(parts)-1])
		ip := strings.Join(parts[1:len(parts)-1], ":")
		b, err := applyBan(ip, "TG 一键拉黑", "tg", hours)
		if err != nil {
			answer("拉黑失败: " + err.Error())
			return
		}
		until := "永久"
		if b.Until > 0 {
			until = "至 " + time.Unix(b.Until, 0).Format("01-02 15:04")
		}
		editText(origText + "\n—— 已拉黑(" + until + ")")
		answer("已拉黑")
		pushEvent(Event{Type: "ban", IP: ip, Detail: "TG 一键拉黑 (" + until + ")"})
		return
	}
	if data == "bc" {
		editMarkup(nil)
		answer("已取消")
		return
	}
}

// ---------- TG 急救菜单(第 2 项) ----------

var (
	rescuePendingMu      sync.Mutex
	rescuePendingPass    string // "" | "unbanall" | "kill"
	rescuePendingPassAt  int64
	rescuePendingTrust   bool
	rescuePendingTrustAt int64
)

func setRescuePendingPass(act string) {
	rescuePendingMu.Lock()
	defer rescuePendingMu.Unlock()
	rescuePendingPass, rescuePendingPassAt = act, time.Now().Unix()
}

func clearRescuePendingPass() {
	rescuePendingMu.Lock()
	defer rescuePendingMu.Unlock()
	rescuePendingPass, rescuePendingPassAt = "", 0
}

func setRescuePendingTrust() {
	rescuePendingMu.Lock()
	defer rescuePendingMu.Unlock()
	rescuePendingTrust, rescuePendingTrustAt = true, time.Now().Unix()
}

func clearRescuePendingTrust() {
	rescuePendingMu.Lock()
	defer rescuePendingMu.Unlock()
	rescuePendingTrust, rescuePendingTrustAt = false, 0
}

func rescueMenuKB() [][]map[string]string {
	return [][]map[string]string{
		{{"text": "信任 IP", "callback_data": tgCB("res:trust")}},
		{{"text": "解封全部（需超级密码）", "callback_data": tgCB("res:unbanall")}},
		{{"text": "关闭所有拦截（需超级密码）", "callback_data": tgCB("res:kill")}},
		{{"text": "恢复防护", "callback_data": tgCB("res:restore")}},
		{{"text": "取消", "callback_data": tgCB("res:cancel")}},
	}
}

// tgSendDirect 直接发一条 TG 消息(不走报警队列, 交互回复需要立即发出)。
func tgSendDirect(chatID int64, text string, kb any) {
	payload := map[string]any{"chat_id": chatID, "text": tgWithTitle(text), "disable_web_page_preview": true}
	if kb != nil {
		payload["reply_markup"] = map[string]any{"inline_keyboard": kb}
	}
	tgAPI("sendMessage", payload, 15*time.Second)
}

// tgDeleteMessage 尽力删除一条消息(私聊里机器人可能删不掉用户消息, 失败忽略)。
func tgDeleteMessage(chatID, msgID int64) {
	tgAPI("deleteMessage", map[string]any{"chat_id": chatID, "message_id": msgID}, 10*time.Second)
}

func sendRescueMenu(chatID int64) {
	tgSendDirect(chatID, rescueMenuText(), rescueMenuKB())
}

// handleTGMessage 处理机器人收到的文字消息(命令 + 急救待处理状态)。
// 只认配置的 Chat ID, 其他会话一律忽略。
func handleTGMessage(msg map[string]any) {
	chat, _ := msg["chat"].(map[string]any)
	chatID := int64(0)
	if chat != nil {
		if f, ok := chat["id"].(float64); ok {
			chatID = int64(f)
		}
	}
	want, _ := strconv.ParseInt(tgActiveChatID(), 10, 64)
	if chatID != want || chatID == 0 {
		return
	}
	text, _ := msg["text"].(string)
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	msgID := int64(0)
	if f, ok := msg["message_id"].(float64); ok {
		msgID = int64(f)
	}
	if strings.HasPrefix(text, "/") {
		fields := strings.Fields(text)
		switch fields[0] {
		case "/rescue":
			sendRescueMenu(chatID)
		case "/cancel":
			clearRescuePendingPass()
			clearRescuePendingTrust()
			tgSendDirect(chatID, "已取消急救操作", nil)
		case "/trust":
			if len(fields) < 2 {
				tgSendDirect(chatID, "用法：/trust <IP>", nil)
				return
			}
			ip := fields[1]
			// 直接执行改成先确认: 确认按钮带服务器指纹, 串台点按会被指纹校验挡住。
			if net.ParseIP(ip) == nil {
				tgSendDirect(chatID, "IP 格式不对："+ip, nil)
				return
			}
			kb := [][]map[string]string{
				{{"text": "确认信任 " + ip, "callback_data": tgCB("tc:" + ip)}},
				{{"text": "取消", "callback_data": tgCB("bc")}},
			}
			tgSendDirect(chatID, "确认信任 IP "+ip+" 吗？（解封并加入信任名单，不再自动拉黑）", kb)
		case "/start", "/help":
			tgSendDirect(chatID, "龟甲机器人：发送 /rescue 打开急救菜单；/trust <IP> 解封并信任一个 IP。", nil)
		}
		return
	}
	now := time.Now().Unix()
	rescuePendingMu.Lock()
	passAct, passAt := rescuePendingPass, rescuePendingPassAt
	trustPend, trustAt := rescuePendingTrust, rescuePendingTrustAt
	rescuePendingMu.Unlock()
	if passAct != "" {
		if now-passAt > rescuePendingMin*60 {
			clearRescuePendingPass()
			return
		}
		// 当作密码尝试: 无论对错都尽力删掉这条消息, 不让密码猜测留在聊天记录里
		if msgID != 0 {
			tgDeleteMessage(chatID, msgID)
		}
		if now < rescueLockedUntil() {
			tgSendDirect(chatID, "急救功能已锁定至 "+time.Unix(rescueLockedUntil(), 0).Format("15:04")+"，请稍后再试", nil)
			return
		}
		mu.Lock()
		hash := settings.RescuePassHash
		mu.Unlock()
		if hash == "" {
			tgSendDirect(chatID, "未设置急救超级密码，请先在网页端设置", nil)
			return
		}
		if !verifyRescuePassword(text, hash) {
			if rescueNoteFailure(time.Now()) {
				emit(Event{Type: "rescue", Detail: "急救：超级密码连续错误 5 次，急救功能已锁定 30 分钟"}, true)
				tgSendDirect(chatID, "密码错误已达 5 次，急救功能已锁定 30 分钟", nil)
			} else {
				tgSendDirect(chatID, "密码错误，请重新发送", nil)
			}
			return
		}
		rescueResetFailures()
		clearRescuePendingPass()
		switch passAct {
		case "unbanall":
			if len(rescueOnlineNodes()) > 0 {
				lines := rescueFanoutUnbanAll()
				tgSendDirect(chatID, "已解封全部（记录保留，仅状态改为已解封）：\n"+strings.Join(lines, "\n"), nil)
				return
			}
			n := rescueUnbanAll()
			pushEvent(Event{Type: "rescue", Detail: "急救：解封全部（" + itoa(n) + " 条，记录保留）"})
			tgSendDirect(chatID, "已解封全部 "+itoa(n)+" 条（记录保留，仅状态改为已解封）", nil)
		case "kill":
			if len(rescueOnlineNodes()) > 0 {
				lines := rescueFanoutKill()
				tgSendDirect(chatID, "已关闭所有拦截（监控与报警不停），各机 30 分钟后自动恢复防护；也可发送 /rescue 点「恢复防护」提前恢复：\n"+strings.Join(lines, "\n"), nil)
				return
			}
			rescueActivateKill(time.Now())
			tgSendDirect(chatID, "已关闭所有拦截（监控与报警不停），30 分钟后自动恢复防护；也可发送 /rescue 点「恢复防护」提前恢复", nil)
		}
		return
	}
	if trustPend {
		if now-trustAt > rescuePendingMin*60 {
			clearRescuePendingTrust()
			return
		}
		already, err := trustIP(text)
		if err != nil {
			tgSendDirect(chatID, "IP 格式不对，请重新发送一个 IP，或发送 /cancel 取消", nil)
			return
		}
		released := releaseBan(text)
		clearRescuePendingTrust()
		if len(rescueOnlineNodes()) > 0 {
			// 本机已信任, 只需把节点侧补齐(不重复推本机事件)。
			suffix := ""
			if released {
				suffix = "（已同时解封）"
			} else if already {
				suffix = "（已在信任名单）"
			}
			lines := append([]string{"本机：已信任 " + text + suffix}, rescueTrustNodes(text)...)
			pushEvent(Event{Type: "rescue", IP: text, Detail: "急救：信任 IP " + text})
			tgSendDirect(chatID, strings.Join(lines, "\n"), nil)
			return
		}
		suffix := ""
		if released {
			suffix = "（已同时解封）"
		} else if already {
			suffix = "（已在信任名单）"
		}
		pushEvent(Event{Type: "rescue", IP: text, Detail: "急救：信任 IP " + text})
		tgSendDirect(chatID, "已信任 "+text+suffix, nil)
		return
	}
	// 无待处理状态的普通消息: 忽略
}

const tgRateMsg = "测试消息 10 秒内只能发送一次, 请稍后再试"

var (
	tgTestMu   sync.Mutex
	tgTestLast time.Time
)

// 用指定(或已保存)的 Token/ChatID 发一条测试消息, 返回错误说明(空=成功)
// 防连点: 真正发出前记时间戳, 10 秒内第二次直接拒绝(2026-10-18 SecretDock 同款教训)
func tgTestSend(token, chatID string) string {
	if token == "" {
		token = settings.TGBotToken
	}
	if chatID == "" {
		chatID = settings.TGChatID
	}
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
	b, _ := json.Marshal(map[string]any{"chat_id": cid, "text": tgWithTitle("测试消息：Telegram 配置可用。")})
	cli := &http.Client{Timeout: 15 * time.Second}
	resp, err := cli.Post("https://api.telegram.org/bot"+token+"/sendMessage", "application/json", bytes.NewReader(b))
	if err != nil {
		return "连接 Telegram 失败: " + err.Error()
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if ok, _ := out["ok"].(bool); !ok {
		if d, _ := out["description"].(string); d != "" {
			return "Telegram 返回: " + d
		}
		return "Telegram 返回失败"
	}
	return ""
}

// ---------- TG 机器人命令菜单 ----------

// tgCommands: setMyCommands 注册表, 只含现有已处理的命令, 不发明新命令。
var tgCommands = []map[string]string{
	{"command": "rescue", "description": "急救菜单"},
	{"command": "trust", "description": "解封并信任一个 IP"},
	{"command": "start", "description": "查看帮助"},
}

// tgRegisterCommands: 向 Telegram 注册命令菜单(TG App 里点 / 可见)。
// 失败只记日志, 绝不阻断保存与启动; 调用方只在保存 TG 设置变化时与启动时各调一次,
// 不要在每次轮询里重复调用。
func tgRegisterCommands() {
	if !tgConfigured() {
		return
	}
	if _, err := tgAPI("setMyCommands", map[string]any{"commands": tgCommands}, 15*time.Second); err != nil {
		log.Printf("tg setMyCommands failed: %v", err)
	}
}

// ---------- TG 日报 ----------

var lastReportDay string

func reportLoop() {
	for {
		time.Sleep(30 * time.Second)
		if !tgConfigured() || !settings.ReportEnabled {
			continue
		}
		now := time.Now()
		if now.Format("15:04") != settings.ReportTime {
			continue
		}
		day := now.Format("2006-01-02")
		if lastReportDay == day {
			continue
		}
		lastReportDay = day
		ds := todayStats()
		statsMu.Lock()
		sshL, sshF, uiL, bn, srcN := ds.SSHLogins, ds.SSHFails, ds.UILogins, ds.Bans, len(ds.Sources)
		statsMu.Unlock()
		text := fmt.Sprintf("%s\n今日 SSH 登录 %d 次 · 失败 %d 次\nUI 登录 %d 次 · 拉黑 %d 次\n新来源 IP %d 个 · 当前黑名单 %d 条",
			day, sshL, sshF, uiL, bn, srcN, len(activeBans()))
		select {
		case tgQueue <- tgMsg{text: text}:
		default:
		}
	}
}
