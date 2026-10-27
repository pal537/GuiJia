package main

// 第 4 项回归测试: 默认端口检测(SSH 配置解析; WEBUI 的 ports.json 唯一 ui 端口;
// 检测不到时宁可报未知也不猜)。

import (
	"os"
	"testing"
)

func TestParseSshdConfig(t *testing.T) {
	p, ok := parseSshdConfig([]byte("# comment\nPort 16722\nPort 22\n"))
	if !ok || p != 16722 {
		t.Fatalf("首个 Port 应生效, 实际 port=%d ok=%v", p, ok)
	}
	if _, ok := parseSshdConfig([]byte("# only comment\n")); ok {
		t.Fatal("无 Port 指令应返回 ok=false(调用方再按默认 22 处理)")
	}
	if _, ok := parseSshdConfig([]byte("Port abc\n")); ok {
		t.Fatal("非法 Port 应被忽略")
	}
	if p, ok := parseSshdConfig([]byte("  Port   2222  # trailing\n")); !ok || p != 2222 {
		t.Fatalf("带行尾注释的 Port 应解析, 实际 port=%d ok=%v", p, ok)
	}
}

func TestDetectSSHPortFromConfig(t *testing.T) {
	f, err := os.CreateTemp("", "sshd_config")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("Port 16722\n")
	f.Close()
	t.Setenv("GUIJIA_SSHD_CONFIG", f.Name())
	d := detectSSHPort()
	if !d.Detected || d.Port != 16722 {
		t.Fatalf("应从测试配置文件读出 16722, 实际 %+v", d)
	}
}

func TestDetectWebUIPort(t *testing.T) {
	// 环境变量优先
	t.Setenv("GUIJIA_WEBUI_PORT", "45167")
	if d := detectWebUIPort(); !d.Detected || d.Port != 45167 {
		t.Fatalf("GUIJIA_WEBUI_PORT 应优先, 实际 %+v", d)
	}
	// 非法环境变量不致命, 回落到未检测到(本测试环境 ports 为空)
	t.Setenv("GUIJIA_WEBUI_PORT", "abc")
	if d := detectWebUIPort(); d.Detected {
		t.Fatalf("非法 GUIJIA_WEBUI_PORT 应回落, 实际 %+v", d)
	}
}
