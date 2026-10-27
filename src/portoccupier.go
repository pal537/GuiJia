package main

// 端口绑定冲突报错 enrichment: 查占用该端口 LISTEN 的进程名。
// 原理: /proc/net/tcp[/6] 里 st=0A(LISTEN) 且本地端口匹配的 socket inode,
// 再扫 /proc/[pid]/fd 的 socket:[inode] 链接反查进程名(comm)。
// 面板跑 root, 此法可行; 任何一步读不到就返回 ""(调用方回落原始错误)。

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func portOccupier(port int) string {
	inodes := listenInodesForPort(port)
	if len(inodes) == 0 {
		return ""
	}
	return procNameForInodes(inodes)
}

func listenInodesForPort(port int) map[string]bool {
	inodes := map[string]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			fl := strings.Fields(ln)
			if len(fl) < 10 {
				continue
			}
			if fl[3] != "0A" { // LISTEN
				continue
			}
			la := fl[1]
			i := strings.LastIndex(la, ":")
			if i < 0 {
				continue
			}
			p, err := strconv.ParseUint(la[i+1:], 16, 32)
			if err != nil || int(p) != port {
				continue
			}
			inodes[fl[9]] = true
		}
	}
	return inodes
}

func procNameForInodes(inodes map[string]bool) string {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			continue
		}
		hit := false
		for _, fd := range fds {
			tgt, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
			if err != nil {
				continue
			}
			if !strings.HasPrefix(tgt, "socket:[") || !strings.HasSuffix(tgt, "]") {
				continue
			}
			if inodes[tgt[len("socket:["):len(tgt)-1]] {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if b, err := os.ReadFile("/proc/" + pid + "/comm"); err == nil {
			if name := strings.TrimSpace(string(b)); name != "" {
				return name
			}
		}
		return pid // comm 读不到时回落 pid, 仍比空有用
	}
	return ""
}

// bindErrText: 绑定失败文案。address already in use 且查到占用进程时报进程名,
// 否则回落原始错误(查不到进程、非绑定错误都原样)。
func bindErrText(port int, err error) string {
	if err == nil {
		return ""
	}
	if !strings.Contains(err.Error(), "address already in use") {
		return err.Error()
	}
	if name := portOccupier(port); name != "" {
		return fmt.Sprintf("端口 %d 已被 %s 占用，面板无法同时监听同一端口", port, name)
	}
	return err.Error()
}

// portFromAddr: 从监听地址里取端口, 解析失败回落默认值。
func portFromAddr(addr string, def int) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return def
	}
	if n, err := strconv.Atoi(p); err == nil && n > 0 {
		return n
	}
	return def
}
