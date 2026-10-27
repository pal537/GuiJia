package main

// 每连接字节统计的数据源开关: 内核参数 nf_conntrack_acct。
// 关着时 /proc/net/nf_conntrack 里没有任何 bytes= 字段, 流量列就没有数据源。
// 本应用以 root 运行, 有权自己打开它——这样任何用户装上就能用, 不需要
// 任何人去改系统设置; 重启后应用每次启动都会重新打开, 不往系统配置目录写文件。
// 记账原则: 只恢复「本应用打开的」开关——如果它本来就是开的(别的软件开的),
// 应用绝不碰; 应用打开的, 在退出/关开关时恢复原值。

import (
	"encoding/json"
	"os"
	"strings"
)

var acctPath = "/proc/sys/net/netfilter/nf_conntrack_acct" // 测试可注入
var acctStatePath string                                   // dataDir/acct-state.json, main 里赋值

type acctState struct {
	WeEnabled bool   `json:"weEnabled"` // 是本应用打开的
	Orig      string `json:"orig"`      // 打开前的值("0")
}

func acctRead() (string, error) {
	b, err := os.ReadFile(acctPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func acctWrite(v string) error {
	return os.WriteFile(acctPath, []byte(v), 0644)
}

func loadAcctState() acctState {
	var st acctState
	if acctStatePath == "" {
		return st
	}
	if b, err := os.ReadFile(acctStatePath); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func saveAcctState(st acctState) {
	if acctStatePath == "" {
		return
	}
	b, _ := json.Marshal(st)
	os.WriteFile(acctStatePath, b, 0644)
}

// ensureTrafficAcct: 设置开关开着且当前没开时, 由应用打开并记账。
// 已开(无论谁开的)只确认不动账。
func ensureTrafficAcct() {
	cur, err := acctRead()
	if err != nil {
		return // 读不到/无权限: 流量列保持无数据, 不报错不折腾
	}
	if cur == "1" {
		return
	}
	if err := acctWrite("1"); err != nil {
		return
	}
	st := loadAcctState()
	if !st.WeEnabled {
		saveAcctState(acctState{WeEnabled: true, Orig: cur})
	}
}

// restoreTrafficAcct: 只恢复本应用打开的开关, 别人的不动。
func restoreTrafficAcct() {
	st := loadAcctState()
	if !st.WeEnabled {
		return
	}
	if cur, err := acctRead(); err == nil && cur == "1" && st.Orig == "0" {
		acctWrite("0")
	}
	saveAcctState(acctState{})
}

// syncTrafficAcct 按设置开关对齐内核开关状态(启动、每分钟自检、设置保存后调用)。
func syncTrafficAcct() {
	mu.Lock()
	on := settings.TrafficAcct
	mu.Unlock()
	if on {
		ensureTrafficAcct()
	} else {
		restoreTrafficAcct()
	}
}
