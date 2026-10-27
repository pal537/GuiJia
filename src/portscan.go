package main

// 监听端口扫描：从 ss 监听表里挑端口进监控清单（通用，与防火墙无关）。
// 端口类型按备注/进程名启发式猜测，仅作展示用。

import "strings"

func guessKind(port int, memo string) string {
	m := strings.ToLower(memo)
	switch {
	case strings.Contains(m, "ssh"):
		return "ssh"
	case strings.Contains(m, "webui") || strings.Contains(m, "ui"):
		return "ui"
	case port == 445 || strings.Contains(m, "smb") || strings.Contains(m, "共享"):
		return "smb"
	case port == 21 || strings.Contains(m, "ftp"):
		return "ftp"
	case port == 5005 || port == 5006 || strings.Contains(m, "webdav"):
		return "webdav"
	case port == 2049 || strings.Contains(m, "nfs"):
		return "nfs"
	case port == 8200 || strings.Contains(m, "dlna") || strings.Contains(m, "upnp"):
		return "dlna"
	case port == 3306 || port == 5432 || port == 27017 || strings.Contains(m, "mysql") || strings.Contains(m, "数据库"):
		return "db"
	case port == 8096 || port == 8920 || port == 32400 || strings.Contains(m, "plex") || strings.Contains(m, "emby") || strings.Contains(m, "jellyfin") || strings.Contains(m, "影视") || strings.Contains(m, "媒体"):
		return "media"
	case strings.Contains(m, "下载") || strings.Contains(m, "qbittorrent") || strings.Contains(m, "transmission"):
		return "download"
	}
	return "other"
}

type ScanItem struct {
	Port    int    `json:"port"`
	Proc    string `json:"proc"`
	Watched bool   `json:"watched"`
	Ignored bool   `json:"ignored"`
}

func scanListeners() []ScanItem {
	lst := ssListeners()
	mu.Lock()
	defer mu.Unlock()
	out := []ScanItem{}
	for port, proc := range lst {
		out = append(out, ScanItem{Port: port, Proc: proc, Watched: findPort(port) != nil || rangeCovered(port), Ignored: ignoredPorts[port] || rangeIgnored(port)})
	}
	// 按端口排序
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Port < out[i].Port {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
