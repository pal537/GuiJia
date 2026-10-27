package main

// 本地命令行急救: cert-off / reset-password / unban。
// 注意: CLI 改的是数据目录里的文件, 运行中的面板进程持有的是内存态,
// 因此改密/关 SSL 后必须重启面板进程才生效——本命令会尝试 systemctl restart,
// 失败则提示手动重启, 绝不静默。

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

func cliMain(args []string) int {
	switch args[0] {
	case "cert-off":
		return cliCertOff()
	case "reset-password":
		return cliResetPassword()
	case "unban":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "用法: guijia unban <ip>")
			return 2
		}
		return cliUnban(args[1])
	case "nginx-ensure":
		return cliNginxEnsure()
	case "nginx-status":
		return cliNginxStatus()
	case "hub-code":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "用法: guijia hub-code <配对码>")
			return 2
		}
		return cliHubCode(args[1])
	case "leave":
		return cliLeave()
	case "upgrade-watch":
		mp := ""
		if len(args) > 1 {
			mp = args[1]
		}
		return cliUpgradeWatch(mp)
	default:
		fmt.Fprintln(os.Stderr, "未知命令:", args[0])
		fmt.Fprintln(os.Stderr, "可用命令: cert-off, reset-password, unban <ip>, nginx-ensure, nginx-status, hub-code <配对码>, leave, upgrade-watch <标记文件>")
		return 2
	}
}

// cliTryRestart: 尝试重启面板服务; 失败只提示, 不改变命令本身的成功与否。
func cliTryRestart() {
	cmd := exec.Command("systemctl", "restart", "guijia")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Println("未能自动重启面板服务:", strings.TrimSpace(string(out)))
		fmt.Println("请手动重启: systemctl restart guijia")
		return
	}
	fmt.Println("面板服务已重启")
}

// cliCertOff: 面板 SSL 关回 HTTP(证书出问题进不去时的回退)。
func cliCertOff() int {
	mu.Lock()
	settings.PanelSSLMode = "off"
	mu.Unlock()
	saveSettings()
	fmt.Println("面板 SSL 已关闭(改回 HTTP)")
	cliTryRestart()
	return 0
}

// cliResetPasswordCore: 改密核心(可单测): 两次一致 + 强密码规则 + 写盘 + 代次 +1。
func cliResetPasswordCore(pw1, pw2 string) error {
	if pw1 != pw2 {
		return errors.New("两次输入不一致")
	}
	if msg := checkStrongPassword(pw1); msg != "" {
		return errors.New(msg)
	}
	h, err := hashRescuePassword(pw1)
	if err != nil {
		return err
	}
	authMu.Lock()
	defer authMu.Unlock()
	auth.PassHash = h
	auth.SessionGen++
	saveAuthLocked()
	return nil
}

func cliResetPassword() int {
	pw1, err := readPasswordNoEcho("新密码: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取密码失败:", err)
		return 1
	}
	pw2, err := readPasswordNoEcho("再次输入: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取密码失败:", err)
		return 1
	}
	if err := cliResetPasswordCore(pw1, pw2); err != nil {
		fmt.Fprintln(os.Stderr, "重置失败:", err)
		return 1
	}
	fmt.Println("密码已重置(旧登录全部失效)")
	cliTryRestart()
	return 0
}

// cliNginxStatus: 只检测 nginx 常驻代答块（不改动、不 reload、不探活）。
func cliNginxStatus() int {
	st, err := getNginxAcmeStatus()
	if err != nil {
		fmt.Fprintln(os.Stderr, "检测失败:", err)
		return 1
	}
	fmt.Println(st.Detail)
	fmt.Println("常驻代答块:", nginxDefaultConf, "已安装:", st.DefaultInstalled, "内容最新:", st.DefaultCurrent)
	if st.ForeignDefault != "" {
		fmt.Println("已有其他 default_server:", st.ForeignDefault)
	}
	fmt.Println("80 站点数:", st.Servers80)
	if st.OK {
		return 0
	}
	return 1
}

// cliNginxEnsure: 安装 nginx 常驻代答块 + 两路自测并打印结果。
func cliNginxEnsure() int {
	changed, err := nginxInstallDefaultAndProbe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "失败:", err)
		return 1
	}
	if changed {
		fmt.Println("常驻代答块已安装，两路自测通过")
	} else {
		fmt.Println("常驻代答块已是最新，两路自测通过")
	}
	return 0
}

// cliHubCode: 被群控节点重填配对码(码错/被拒/被主服务器移除后的重配对):
// 码进 node.json(0600), 旧 token 清掉, 重启后拨号器用新码 hello。
func cliHubCode(code string) int {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 128 {
		fmt.Fprintln(os.Stderr, "配对码无效")
		return 2
	}
	if nodeIdent == nil {
		fmt.Fprintln(os.Stderr, "节点身份缺失")
		return 1
	}
	nodeMu.Lock()
	nodeIdent.PairingCode = code
	nodeIdent.Token = ""
	saveNodeIdentityLocked()
	nodeMu.Unlock()
	fmt.Println("配对码已写入(旧 token 已清除)")
	cliTryRestart()
	return 0
}

// cliLeave: 被群控节点脱离(主服务器彻底没了时的兜底): 回到首次二选一,
// 本地管理面板恢复(重启后打开面板重新选独立或群控)。
func cliLeave() int {
	if effectiveRunMode() != "managed" {
		fmt.Println("本机未被群控, 无需脱离")
		return 1
	}
	mu.Lock()
	settings.RunMode = ""
	settings.HubURL = ""
	settings.HubName = ""
	settings.HubID = ""
	saveSettings()
	mu.Unlock()
	if nodeIdent != nil {
		nodeMu.Lock()
		nodeIdent.PairingCode = ""
		nodeIdent.Token = ""
		saveNodeIdentityLocked()
		nodeMu.Unlock()
	}
	fmt.Println("已脱离群控(回到首次二选一)")
	cliTryRestart()
	return 0
}

// cliUnban: 解封 IP(面板/SSH/端口封禁通用, 只改状态, 记录保留)。
func cliUnban(ip string) int {
	if net.ParseIP(ip) == nil {
		fmt.Fprintln(os.Stderr, "IP 无效:", ip)
		return 2
	}
	if !isGloballyBanned(ip) {
		fmt.Println("该 IP 没有生效中的封禁")
		return 1
	}
	if releaseBan(ip) {
		fmt.Println("已解封:", ip)
		return 0
	}
	fmt.Println("该 IP 没有封禁记录")
	return 1
}

// readPasswordNoEcho: 无回显读一行(优先 /dev/tty, 否则 stdin; 非终端则报错)。
func readPasswordNoEcho(prompt string) (string, error) {
	fmt.Print(prompt)
	f := os.Stdin
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		f = tty
	}
	fd := int(f.Fd())
	var oldState syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&oldState)), 0, 0, 0); errno != 0 {
		return "", errors.New("无法关闭回显(请在终端交互运行)")
	}
	newState := oldState
	newState.Lflag &^= syscall.ECHO
	syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&newState)), 0, 0, 0)
	defer syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&oldState)), 0, 0, 0)
	line, err := bufio.NewReader(f).ReadString('\n')
	fmt.Println()
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
