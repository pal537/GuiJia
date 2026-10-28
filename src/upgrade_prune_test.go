package main

// 2026-10-28 备份保留修复单测: 旧版按文件名排序留 3 份,
// v1.0.10 的名字排在 v1.0.7 前面, 刚写好的新备份当场被删、
// 真要回滚时无备份可用。改为按修改时间留最新 3 份。

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPruneUpgradeBackupsKeepsNewestByMtime: 保留按修改时间最新的 3 份,
// 名字排序靠前的最新备份不许被删; 看门狗副本不占名额、不许动。
func TestPruneUpgradeBackupsKeepsNewestByMtime(t *testing.T) {
	setupUpgradeTest(t)
	dir := upgradeBackupDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// 09:50 现场复现: 名字排序时 v1.0.10 排最前, 但它修改时间最新。
	cases := []struct {
		name string
		age  time.Duration
	}{
		{"guijia-v1.0.7-20261027233616", 4 * time.Hour},
		{"guijia-v1.0.8-20261028004935", 3 * time.Hour},
		{"guijia-v1.0.9-20261028012712", 2 * time.Hour},
		{"guijia-v1.0.10-20261028095000", 0},
		// 开发版备份名不带 v 前缀, 同样要按时间保留、不能漏删。
		{"guijia-0.9-20261027000000", 5 * time.Hour},
	}
	for _, c := range cases {
		p := filepath.Join(dir, c.name)
		if err := os.WriteFile(p, []byte("bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-c.age), now.Add(-c.age)); err != nil {
			t.Fatal(err)
		}
	}
	// 看门狗副本: 不许被保留逻辑删掉。
	watch := filepath.Join(dir, "guijia-watch-copy-123")
	if err := os.WriteFile(watch, []byte("watch"), 0755); err != nil {
		t.Fatal(err)
	}

	pruneUpgradeBackups(3)

	// 最新备份 v1.0.10 必须留下, 最旧两份(0.9 与 v1.0.7)必须被删。
	if _, err := os.Stat(filepath.Join(dir, "guijia-v1.0.10-20261028095000")); err != nil {
		t.Fatalf("最新备份 v1.0.10 不许被删: %v", err)
	}
	for _, gone := range []string{"guijia-v1.0.7-20261027233616", "guijia-0.9-20261027000000"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("最旧备份 %s 应被删, 得到 err=%v", gone, err)
		}
	}
	if _, err := os.Stat(watch); err != nil {
		t.Fatalf("看门狗副本不许被保留逻辑动: %v", err)
	}
	// 版本备份恰好剩 3 份(不含看门狗副本)。
	ents, _ := os.ReadDir(dir)
	n := 0
	for _, e := range ents {
		if e.Name() != "guijia-watch-copy-123" && len(e.Name()) > 7 && e.Name()[:7] == "guijia-" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("版本备份应剩 3 份, 得到 %d 份", n)
	}
}
