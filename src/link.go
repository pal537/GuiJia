package main

// 节点拨号器(第一期): RunMode=managed 的节点启动后自动连主服务器。
// 流程: hello(配对码/已登记)→pending 轮询→challenge→私钥签名 auth→token→
// ping(30 秒)+命令轮询; 断线按 1s/2s/5s/10s/30s 退避重连。
// 配对码与 token 只存 node.json(0600); 命令执行走本机 rootMux 直调
// (命令本身已凭节点 token 鉴权), 只放行管理类 API, 绝不执行
// /api/nodes/* 与 /api/auth/*。

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// ---------- 启动守卫(同一进程只跑一个拨号循环) ----------

var (
	linkRunMu   sync.Mutex
	linkRunning bool
)

func startLinkLoop() {
	linkRunMu.Lock()
	defer linkRunMu.Unlock()
	if linkRunning || effectiveRunMode() != "managed" {
		return
	}
	linkRunning = true
	go linkLoop()
}

// rejectReason 加入被拒时的回退原因：
// 明确拒绝时节点若还持有 token，说明此前配对成功过，如今 hello 403 只能是
// 主服务器删了记录（移除常发生在断网退避期，下一轮从 hello 开始，
// 到不了 ping 401 的吊销路径），按“被移除”提示；否则按“被拒绝”。
func rejectReason() string {
	if nodeToken() != "" {
		return "revoked"
	}
	return "rejected"
}

func linkLoop() {
	defer func() {
		linkRunMu.Lock()
		linkRunning = false
		linkRunMu.Unlock()
	}()
	backoffs := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}
	bi := 0
	for {
		if effectiveRunMode() != "managed" {
			return
		}
		if err := linkSession(); err != nil {
			// 明确拒绝/吊销：回退到加入页重输，不在死页面上重试；
			// 网络等临时失败才继续退避重连。
			if errors.Is(err, errLinkRejected) {
				rollbackJoin(rejectReason())
			} else if errors.Is(err, errLinkRevoked) {
				rollbackJoin("revoked")
			} else {
				setLinkState("disconnected", err.Error())
			}
		}
		if effectiveRunMode() != "managed" {
			return
		}
		d := backoffs[bi]
		if bi < len(backoffs)-1 {
			bi++
		}
		time.Sleep(d)
	}
}

// touchLink 只刷新最后联系时间, 不改状态。
func touchLink() {
	linkMu.Lock()
	defer linkMu.Unlock()
	linkLastContact = time.Now().Unix()
}

var errLinkRevoked = errors.New("节点已被主服务器移除，需重新配对（本机命令行 hub-code）")

// errLinkRejected 主服务器明确拒绝加入（码无效/过期、待添加被拒绝、指纹未登记）：
// 拨号器不再重试，由 linkLoop 回退到加入页重输（JoinError=rejected）。
var errLinkRejected = errors.New("link-rejected")

// linkPost 节点侧 POST 助手: 自动带指纹头, token 为空则不带。
func linkPost(client *http.Client, url, token string, payload any) (int, []byte, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Fingerprint", nodeFingerprint())
	if token != "" {
		req.Header.Set("X-Node-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

func linkErrBody(body []byte) string {
	var v struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &v) == nil && v.Error != "" {
		return v.Error
	}
	return strings.TrimSpace(string(body))
}

// linkSession 一次完整会话: hello→(pending 轮询)→challenge→auth→ping+轮询,
// 会话断开即返回错误, 由 linkLoop 退避重连。
func linkSession() error {
	mu.Lock()
	hubURL := settings.HubURL
	mu.Unlock()
	hubURL = strings.TrimRight(hubURL, "/")
	if hubURL == "" {
		return errors.New("未配置主服务器地址")
	}
	fp := nodeFingerprint()
	if fp == "" {
		return errors.New("节点身份缺失")
	}
	pub := nodePubKeyB64()
	name := nodeDisplayName()
	c15 := &http.Client{Timeout: 15 * time.Second}
	cPoll := &http.Client{Timeout: 35 * time.Second}

	hello := func() (string, error) {
		st, body, err := linkPost(c15, hubURL+"/api/nodes/hello", "", map[string]any{
			"fingerprint": fp, "pubKey": pub, "name": name, "version": appVersion,
			"code": nodePairingCode(),
		})
		if err != nil {
			return "", err
		}
		if st == 403 {
			// 主服务器明确拒绝：不再重试，由 linkLoop 回退到加入页重输。
			return "", errLinkRejected
		}
		if st != 200 {
			return "", fmt.Errorf("hello 失败(HTTP %d): %s", st, linkErrBody(body))
		}
		var v struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(body, &v) != nil || (v.Status != "pending" && v.Status != "approved") {
			return "", errors.New("hello 返回异常")
		}
		return v.Status, nil
	}

	status, err := hello()
	if err != nil {
		return err
	}
	if status == "pending" {
		clearNodePairingCode() // 码已被主服务器接受, 不再留盘
		setLinkState("pending", "")
		for {
			if effectiveRunMode() != "managed" {
				return errors.New("运行模式已变更")
			}
			time.Sleep(5 * time.Second)
			status, err = hello()
			if err != nil {
				return err
			}
			if status == "approved" {
				break
			}
			setLinkState("pending", "")
		}
	}

	// 挑战 + 签名换 token
	st, body, err := linkPost(c15, hubURL+"/api/nodes/challenge", "", map[string]any{"fingerprint": fp})
	if err != nil {
		return err
	}
	if st == 403 {
		// 批准后又被移除：同样是明确拒绝，回退到加入页重输。
		return errLinkRejected
	}
	if st != 200 {
		return fmt.Errorf("challenge 失败(HTTP %d): %s", st, linkErrBody(body))
	}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(body, &ch) != nil || ch.Nonce == "" {
		return errors.New("challenge 返回异常")
	}
	priv := nodePrivKey()
	if priv == nil {
		return errors.New("节点私钥缺失")
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(ch.Nonce)))
	st, body, err = linkPost(c15, hubURL+"/api/nodes/auth", "", map[string]any{
		"fingerprint": fp, "nonce": ch.Nonce, "signature": sig,
	})
	if err != nil {
		return err
	}
	if st == 401 || st == 403 {
		return fmt.Errorf("auth 失败(HTTP %d): %s", st, linkErrBody(body))
	}
	if st != 200 {
		return fmt.Errorf("auth 失败(HTTP %d): %s", st, linkErrBody(body))
	}
	var av struct {
		Token   string `json:"token"`
		HubName string `json:"hubName"`
		HubID   string `json:"hubId"`
	}
	if json.Unmarshal(body, &av) != nil || av.Token == "" {
		return errors.New("auth 返回异常")
	}
	setNodeToken(av.Token)
	mu.Lock()
	settings.HubName = av.HubName
	settings.HubID = av.HubID
	saveSettings()
	mu.Unlock()
	setLinkState("connected", "")
	pokeHubSender() // 接通即补推主服务器挂掉期间攒下的事件

	// 已连接: ping + 命令轮询双循环, 任一出错即断开重连。
	stop := make(chan struct{})
	errCh := make(chan error, 2)
	go func() { errCh <- linkPingLoop(c15, hubURL, av.Token, stop) }()
	go func() { errCh <- linkPollLoop(cPoll, hubURL, av.Token, stop) }()
	err = <-errCh
	close(stop)
	if errors.Is(err, errLinkRevoked) {
		clearNodeToken()
		return errLinkRevoked
	}
	return err
}

func linkPingLoop(client *http.Client, hubURL, token string, stop chan struct{}) error {
	// 先 ping 一次确认, 再每 30 秒一次。
	for first := true; ; first = false {
		if !first {
			select {
			case <-stop:
				return nil
			case <-time.After(30 * time.Second):
			}
		}
		if effectiveRunMode() != "managed" {
			return errors.New("运行模式已变更")
		}
		st, body, err := linkPost(client, hubURL+"/api/nodes/ping", token, map[string]any{"version": appVersion, "tgMode": nodeTGMode()})
		if err != nil {
			return err
		}
		if st == 401 {
			return errLinkRevoked
		}
		if st != 200 {
			return fmt.Errorf("ping 失败(HTTP %d): %s", st, linkErrBody(body))
		}
		touchLink()
	}
}

func linkPollLoop(client *http.Client, hubURL, token string, stop chan struct{}) error {
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		if effectiveRunMode() != "managed" {
			return errors.New("运行模式已变更")
		}
		st, body, err := linkPost(client, hubURL+"/api/nodes/poll", token, map[string]any{})
		if err != nil {
			return err
		}
		if st == 401 {
			return errLinkRevoked
		}
		if st == 204 {
			touchLink()
			continue
		}
		if st != 200 {
			return fmt.Errorf("poll 失败(HTTP %d): %s", st, linkErrBody(body))
		}
		touchLink()
		var cmd hubCommand
		if json.Unmarshal(body, &cmd) != nil || cmd.ID == "" {
			continue
		}
		status, respBody := executeNodeCommand(cmd)
		_, _, _ = linkPost(client, hubURL+"/api/nodes/result", token, map[string]any{
			"id": cmd.ID, "status": status, "body": json.RawMessage(respBody),
		})
	}
}

// executeNodeCommand 在本地执行主服务器发来的管理命令: 只放行管理类 API。
func executeNodeCommand(cmd hubCommand) (int, []byte) {
	path := cmd.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !isProxyablePath(path) {
		return 403, []byte(`{"error":"该接口不允许跨节点调用"}`)
	}
	switch cmd.Method {
	case "GET", "POST", "PUT", "DELETE":
	default:
		return 400, []byte(`{"error":"不支持的方法"}`)
	}
	if rootMux == nil {
		return 500, []byte(`{"error":"本地面板未就绪"}`)
	}
	var rdr io.Reader
	if len(cmd.Body) > 0 {
		rdr = bytes.NewReader(cmd.Body)
	}
	req := httptest.NewRequest(cmd.Method, path, rdr)
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	rootMux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}
