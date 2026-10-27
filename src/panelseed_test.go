package main

import (
	"path/filepath"
	"testing"
)

// 面板端口默认种子：启动补一次、默认加星、重点端口里可见（JS 重点端口区按 p.star 过滤）。
// 手动添加的条目一律不动；种子直写清单，不走 planRangeAdd，故不受星标自身端口排除影响。
func seedSetup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldPorts, oldRanges, oldIgnored, oldPanelPort, oldPortsFile := ports, portRanges, ignoredPorts, panelPort, portsFile
	t.Cleanup(func() {
		ports, portRanges, ignoredPorts, panelPort, portsFile = oldPorts, oldRanges, oldIgnored, oldPanelPort, oldPortsFile
	})
	ports, portRanges = nil, nil
	ignoredPorts = map[int]bool{}
	portsFile = filepath.Join(dir, "ports.json")
	return dir
}

func TestEnsurePanelPortSeedFresh(t *testing.T) {
	seedSetup(t)
	panelPort = 59188
	if !ensurePanelPortSeed() {
		t.Fatal("空清单应补面板端口默认条目")
	}
	if len(ports) != 1 {
		t.Fatalf("应恰好 1 条，得到 %d 条", len(ports))
	}
	p := ports[0]
	if p.Port != 59188 || !p.Star || p.Name != "面板" || p.Kind != "ui" {
		t.Fatalf("默认条目应为 59188/加星/面板/ui，得到 %+v", p)
	}
	if ensurePanelPortSeed() || len(ports) != 1 {
		t.Fatal("重复调用不应重复补条目")
	}
}

func TestEnsurePanelPortSeedCustomPort(t *testing.T) {
	seedSetup(t)
	panelPort = 59999
	if !ensurePanelPortSeed() {
		t.Fatal("自定义面板端口也应补默认条目")
	}
	if len(ports) != 1 || ports[0].Port != 59999 || !ports[0].Star {
		t.Fatalf("应补 59999 加星条目，得到 %+v", ports)
	}
}

func TestEnsurePanelPortSeedRespectsExisting(t *testing.T) {
	seedSetup(t)
	panelPort = 59188
	// 用户手动加过（未加星）：一律不动，不改星标、不重复。
	ports = []*PortWatch{{Port: 59188, Proto: "tcp", Name: "面板", Star: false, Source: "manual", Kind: "ui"}}
	if ensurePanelPortSeed() {
		t.Fatal("已有单个条目时不应再补")
	}
	if len(ports) != 1 || ports[0].Star {
		t.Fatalf("手动条目应原样保留（未加星），得到 %+v", ports[0])
	}
}

func TestEnsurePanelPortSeedRespectsRange(t *testing.T) {
	seedSetup(t)
	panelPort = 59188
	portRanges = []*PortRange{{From: 59000, To: 60000, Name: "内网", Star: true, Kind: "other", Source: "manual"}}
	if ensurePanelPortSeed() {
		t.Fatal("已有范围覆盖面板端口时不应再补")
	}
	if len(ports) != 0 {
		t.Fatalf("不应补条目，得到 %d 条", len(ports))
	}
}

func TestEnsurePanelPortSeedRespectsIgnored(t *testing.T) {
	seedSetup(t)
	panelPort = 59188
	ignoredPorts[59188] = true // 用户删过：尊重删除，不再补回
	if ensurePanelPortSeed() {
		t.Fatal("用户删过的面板端口不应再补")
	}
	if len(ports) != 0 {
		t.Fatalf("不应补条目，得到 %d 条", len(ports))
	}
}
