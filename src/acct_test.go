package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 流量统计开关: 应用自己打开(装上就能用)、记账、退出只恢复自己开的,
// 本来就开着的(别人的)绝不乱关。
func TestTrafficAcctLifecycle(t *testing.T) {
	dir := t.TempDir()
	acctPath = filepath.Join(dir, "acct")
	acctStatePath = filepath.Join(dir, "acct-state.json")
	defer func() { acctPath = "/proc/sys/net/netfilter/nf_conntrack_acct" }()

	os.WriteFile(acctPath, []byte("0\n"), 0644)
	settings.TrafficAcct = true
	syncTrafficAcct()
	if v, _ := acctRead(); v != "1" {
		t.Fatalf("应用应打开计数开关, 实际 %q", v)
	}
	if st := loadAcctState(); !st.WeEnabled || st.Orig != "0" {
		t.Fatalf("应记账 weEnabled=true orig=0, 实际 %+v", st)
	}
	// 重复调用幂等, 不覆盖账本
	syncTrafficAcct()
	if st := loadAcctState(); !st.WeEnabled {
		t.Fatal("重复自检不应清账")
	}
	// 退出恢复原值
	restoreTrafficAcct()
	if v, _ := acctRead(); v != "0" {
		t.Fatalf("退出应恢复为 0, 实际 %q", v)
	}
	if st := loadAcctState(); st.WeEnabled {
		t.Fatal("恢复后账本应清零")
	}
}

func TestTrafficAcctRespectsOthers(t *testing.T) {
	dir := t.TempDir()
	acctPath = filepath.Join(dir, "acct")
	acctStatePath = filepath.Join(dir, "acct-state.json")
	defer func() { acctPath = "/proc/sys/net/netfilter/nf_conntrack_acct" }()

	// 本来就是开的(别的软件开的): 应用不记账, 退出时也不许关
	os.WriteFile(acctPath, []byte("1\n"), 0644)
	settings.TrafficAcct = true
	syncTrafficAcct()
	if st := loadAcctState(); st.WeEnabled {
		t.Fatal("本来就开着的不应记成应用打开的")
	}
	restoreTrafficAcct()
	if v, _ := acctRead(); v != "1" {
		t.Fatalf("别人的开关绝不能关, 实际 %q", v)
	}
	// 设置关掉时, 应用打开的要恢复
	os.WriteFile(acctPath, []byte("0\n"), 0644)
	syncTrafficAcct() // TrafficAcct=true → 打开并记账
	settings.TrafficAcct = false
	syncTrafficAcct() // 关 → 恢复
	if v, _ := acctRead(); v != "0" {
		t.Fatalf("设置关闭应恢复 0, 实际 %q", v)
	}
	settings.TrafficAcct = true
}
