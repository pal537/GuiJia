package main

// 2026-10-28 升级假失败根治单测: 旧进程重启时被 SIGTERM 误判写 failed,
// 实际二进制已是目标版, 状态却永远挂着“重启失败, 已回滚”。

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReconcileFailedStatusByVersion: 启动按实际版本复核失败状态。
func TestReconcileFailedStatusByVersion(t *testing.T) {
	setupUpgradeTest(t)
	// 运行版等于 target → 纠正为 done, 错误清空(v 前缀归一化也算相等)。
	appVersion = "0.2"
	setUpgradeStatus("failed", "v0.2", "重启失败, 已回滚: signal: terminated", "")
	upgradeReconcileOnStart()
	st := loadUpgradeStatus()
	if st.State != "done" || st.Error != "" {
		t.Fatalf("运行版等于 target 时 failed 应纠正为 done 且清空错误, 得到 %+v", st)
	}
	// 运行版不等于 target → 原样保留(真失败不许掩盖)。
	appVersion = "0.1"
	setUpgradeStatus("failed", "v0.2", "下载失败: boom", "")
	upgradeReconcileOnStart()
	st = loadUpgradeStatus()
	if st.State != "failed" || st.Error != "下载失败: boom" {
		t.Fatalf("运行版不等于 target 时 failed 应原样保留, 得到 %+v", st)
	}
	// done/idle/applying 启动时不动。
	for _, s := range []string{"done", "idle", "applying"} {
		setUpgradeStatus(s, "v0.2", "", "")
		upgradeReconcileOnStart()
		if got := loadUpgradeStatus(); got.State != s {
			t.Fatalf("状态 %s 启动时不应被复核改动, 得到 %q", s, got.State)
		}
	}
}

// TestRestartSignalErrorNotFailure: 重启命令死于信号不是失败。
func TestRestartSignalErrorNotFailure(t *testing.T) {
	_, exe, _, _ := setupUpgradeTest(t)
	fakeUpgradeStation(t, "v0.2", []byte("NEWBIN-v0.2"), false)
	appVersion = "0.1"
	// 重启命令死于 SIGTERM (模拟 systemctl 客户端随 cgroup 被杀)。
	upgradeRestartFunc = func() error {
		return exec.Command("sh", "-c", "kill -TERM $$").Run()
	}
	setUpgradeStatus("applying", "v0.2", "", "")
	runUpgradeApply("")
	// 二进制已替换且未被还原, marker 保留(看门狗收尾), 状态保持 applying 不写 failed。
	got, _ := os.ReadFile(exe)
	if string(got) != "NEWBIN-v0.2" {
		t.Fatalf("信号致死的重启不应还原二进制, 得到 %q", got)
	}
	if _, err := os.Stat(upgradeMarkerPath()); err != nil {
		t.Fatalf("信号致死的重启不应删 marker, 看门狗还须收尾")
	}
	st := loadUpgradeStatus()
	if st.State != "applying" || st.Error != "" {
		t.Fatalf("信号致死的重启不应写 failed, 得到 %+v", st)
	}
}

// TestRestartRealErrorRollbackOnlyOnRestore: 真重启失败时, 只有还原成功才称已回滚。
func TestRestartRealErrorRollbackOnlyOnRestore(t *testing.T) {
	_, exe, _, _ := setupUpgradeTest(t)
	fakeUpgradeStation(t, "v0.2", []byte("NEWBIN-v0.2"), false)
	appVersion = "0.1"
	upgradeRestartFunc = func() error { return errors.New("restart boom") }
	setUpgradeStatus("applying", "v0.2", "", "")
	runUpgradeApply("")
	got, _ := os.ReadFile(exe)
	if string(got) != "OLDBIN" {
		t.Fatalf("真正重启失败且还原成功时二进制应回旧版, 得到 %q", got)
	}
	if _, err := os.Stat(upgradeMarkerPath()); err == nil {
		t.Fatalf("还原后 marker 应删除")
	}
	st := loadUpgradeStatus()
	if st.State != "failed" || !strings.Contains(st.Error, "已回滚") {
		t.Fatalf("还原成功时应写已回滚, 得到 %+v", st)
	}
}

// TestRestartRealErrorRollbackFailedNoClaim: 还原失败时绝不称已回滚。
func TestRestartRealErrorRollbackFailedNoClaim(t *testing.T) {
	_, exe, _, _ := setupUpgradeTest(t)
	fakeUpgradeStation(t, "v0.2", []byte("NEWBIN-v0.2"), false)
	appVersion = "0.1"
	upgradeRestartFunc = func() error {
		// 重启失败前备份已被清掉(09:50 prune 现场): 删掉备份目录全部文件。
		ents, _ := os.ReadDir(upgradeBackupDir())
		for _, e := range ents {
			os.Remove(filepath.Join(upgradeBackupDir(), e.Name()))
		}
		return errors.New("restart boom")
	}
	setUpgradeStatus("applying", "v0.2", "", "")
	runUpgradeApply("")
	got, _ := os.ReadFile(exe)
	if string(got) != "NEWBIN-v0.2" {
		t.Fatalf("还原失败时新二进制应保留, 得到 %q", got)
	}
	st := loadUpgradeStatus()
	if st.State != "failed" || !strings.Contains(st.Error, "回滚失败") || strings.Contains(st.Error, "已回滚") {
		t.Fatalf("还原失败时应写回滚失败且绝不称已回滚, 得到 %+v", st)
	}
}
