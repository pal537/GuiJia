package main

import (
	"path/filepath"
	"testing"
)

func setupSeedTest(t *testing.T, panel int) func() {
	t.Helper()
	dir := t.TempDir()
	old := struct {
		dataDir       string
		portsFile     string
		panelPort     int
		ports         []*PortWatch
		portRanges    []*PortRange
		ignoredPorts  map[int]bool
		ignoredRanges []PortRange
	}{dataDir, portsFile, panelPort, ports, portRanges, ignoredPorts, ignoredRanges}
	dataDir = dir
	portsFile = filepath.Join(dir, "ports.json")
	panelPort = panel
	ports = nil
	portRanges = nil
	ignoredPorts = map[int]bool{}
	ignoredRanges = nil
	return func() {
		dataDir, portsFile, panelPort, ports, portRanges, ignoredPorts, ignoredRanges =
			old.dataDir, old.portsFile, old.panelPort, old.ports, old.portRanges, old.ignoredPorts, old.ignoredRanges
	}
}

func TestPanelPortSeedMigrate(t *testing.T) {
	t.Run("换端口迁移旧面板条目", func(t *testing.T) {
		defer setupSeedTest(t, 18080)()
		ports = []*PortWatch{{Port: 59188, Proto: "tcp", Name: "面板", Star: true, Source: "manual", Kind: "ui"}}
		if !ensurePanelPortSeed() {
			t.Fatalf("should migrate")
		}
		if len(ports) != 1 || ports[0].Port != 18080 || ports[0].Name != "面板" || !ports[0].Star || ports[0].Kind != "ui" {
			t.Fatalf("ports = %+v", ports)
		}
	})
	t.Run("无条目时种子新端口", func(t *testing.T) {
		defer setupSeedTest(t, 18080)()
		if !ensurePanelPortSeed() {
			t.Fatalf("should seed")
		}
		if len(ports) != 1 || ports[0].Port != 18080 || !ports[0].Star {
			t.Fatalf("ports = %+v", ports)
		}
	})
	t.Run("已有覆盖不补", func(t *testing.T) {
		defer setupSeedTest(t, 18080)()
		ports = []*PortWatch{{Port: 18080, Proto: "tcp", Name: "其他", Source: "manual", Kind: "other"}}
		if ensurePanelPortSeed() {
			t.Fatalf("should not seed when covered")
		}
		if len(ports) != 1 {
			t.Fatalf("ports = %+v", ports)
		}
	})
	t.Run("新端口被忽略不补不迁", func(t *testing.T) {
		defer setupSeedTest(t, 18080)()
		ports = []*PortWatch{{Port: 59188, Proto: "tcp", Name: "面板", Star: true, Source: "manual", Kind: "ui"}}
		ignoredPorts[18080] = true
		if ensurePanelPortSeed() {
			t.Fatalf("should not seed when ignored")
		}
		if ports[0].Port != 59188 {
			t.Fatalf("ignored port must not migrate, ports = %+v", ports)
		}
	})
	t.Run("非面板条目不动只追加", func(t *testing.T) {
		defer setupSeedTest(t, 18080)()
		ports = []*PortWatch{{Port: 59188, Proto: "tcp", Name: "SSH", Star: true, Source: "manual", Kind: "ssh"}}
		if !ensurePanelPortSeed() {
			t.Fatalf("should seed")
		}
		if len(ports) != 2 || ports[0].Port != 59188 || ports[1].Port != 18080 {
			t.Fatalf("ports = %+v", ports)
		}
	})
	t.Run("改过名的旧条目不动只追加", func(t *testing.T) {
		defer setupSeedTest(t, 18080)()
		ports = []*PortWatch{{Port: 59188, Proto: "tcp", Name: "我的面板", Star: true, Source: "manual", Kind: "ui"}}
		if !ensurePanelPortSeed() {
			t.Fatalf("should seed")
		}
		if len(ports) != 2 || ports[0].Port != 59188 || ports[1].Name != "面板" {
			t.Fatalf("ports = %+v", ports)
		}
	})
	t.Run("多个旧面板条目只迁第一个", func(t *testing.T) {
		defer setupSeedTest(t, 18080)()
		ports = []*PortWatch{
			{Port: 59188, Proto: "tcp", Name: "面板", Star: true, Source: "manual", Kind: "ui"},
			{Port: 18081, Proto: "tcp", Name: "面板", Star: true, Source: "manual", Kind: "ui"},
		}
		if !ensurePanelPortSeed() {
			t.Fatalf("should migrate")
		}
		if len(ports) != 2 || ports[0].Port != 18080 || ports[1].Port != 18081 {
			t.Fatalf("ports = %+v", ports)
		}
	})
}
