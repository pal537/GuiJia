package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 账本测试脚手架: 注入假时钟 + 临时目录, 结束恢复全局状态
func setupLedger(t *testing.T) (dir string, setNow func(time.Time)) {
	t.Helper()
	dir = t.TempDir()
	oldNow := nowFn
	oldKeep := settings.LedgerKeepDays
	cur := time.Date(2026, 10, 24, 10, 0, 0, 0, time.Local)
	nowFn = func() time.Time { return cur }
	ledgerInit(dir)
	t.Cleanup(func() {
		nowFn = oldNow
		settings.LedgerKeepDays = oldKeep
		ledgerMu.Lock()
		ledgerGen = map[string]*genState{}
		ledgerBankTotal = map[string]*ledgerTotals{}
		ledgerBankDay = map[string]*ledgerTotals{}
		ledgerMu.Unlock()
	})
	return dir, func(nt time.Time) { cur = nt }
}

func flow(tuple, key string, rx, tx uint64) ctFlow {
	return ctFlow{Tuple: tuple, Key: key, Rx: rx, Tx: tx, HasBytes: true}
}

// 逐流解析与聚合解析(ctConns)同口径对账: 同一夹具, 逐流按展示键求和必须
// 等于聚合口径的已知结果(入站聚合/外连取向/DNAT 都覆盖在聚合测试里, 这里验逐流)
func TestFlowEntriesSumsMatchAgg(t *testing.T) {
	data := "ipv4 2 udp 17 25 src=203.0.113.7 dst=127.0.0.1 sport=51234 dport=34579 packets=3 bytes=300 src=127.0.0.1 dst=203.0.113.7 sport=34579 dport=51234 packets=2 bytes=200 mark=0 use=2\n" +
		"ipv4 2 udp 17 25 src=203.0.113.7 dst=127.0.0.1 sport=51235 dport=34579 packets=1 bytes=100 src=127.0.0.1 dst=203.0.113.7 sport=34579 dport=51235 packets=1 bytes=50 mark=0 use=2\n" +
		"ipv4 2 udp 17 25 src=127.0.0.1 dst=198.51.100.9 sport=34579 dport=6881 packets=9 bytes=1000 src=198.51.100.9 dst=127.0.0.1 sport=6881 dport=34579 packets=9 bytes=4000 mark=0 use=1\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=203.0.113.8 dst=127.0.0.1 sport=1111 dport=34579 packets=9 bytes=5000 src=127.0.0.1 dst=203.0.113.8 sport=34579 dport=1111 packets=9 bytes=600 [ASSURED] mark=0 use=1\n" +
		// 非生效端口不应入选
		"ipv4 2 udp 17 25 src=203.0.113.9 dst=127.0.0.1 sport=2222 dport=9999 packets=1 bytes=10 src=127.0.0.1 dst=203.0.113.9 sport=9999 dport=2222 packets=1 bytes=10 mark=0 use=1\n"
	entries := parseCTFlowEntries(data, map[string]bool{"127.0.0.1": true}, map[int]bool{34579: true})
	if len(entries) != 4 {
		t.Fatalf("want 4 entries got %d: %+v", len(entries), entries)
	}
	sum := map[string][2]uint64{}
	tuples := map[string]bool{}
	for _, e := range entries {
		s := sum[e.Key]
		s[0] += e.Rx
		s[1] += e.Tx
		sum[e.Key] = s
		if tuples[e.Tuple] {
			t.Errorf("tuple duplicated: %s", e.Tuple)
		}
		tuples[e.Tuple] = true
		if !e.HasBytes {
			t.Errorf("entry should have bytes: %+v", e)
		}
	}
	if s := sum["203.0.113.7|34579|udp"]; s != [2]uint64{400, 250} {
		t.Errorf("inbound agg mismatch: %v", s)
	}
	if s := sum["198.51.100.9|34579|udp"]; s != [2]uint64{4000, 1000} {
		t.Errorf("outbound agg mismatch: %v", s)
	}
	if s := sum["203.0.113.8|34579|tcp"]; s != [2]uint64{5000, 600} {
		t.Errorf("tcp agg mismatch: %v", s)
	}
}

// 断续连接全生命周期: 增长入账 -> 消失不丢 -> 同四元组新流(计数回退)续记 -> 再增长
func TestLedgerAcrossReconnects(t *testing.T) {
	setupLedger(t)
	const tup = "udp|203.0.113.7:51234>192.0.2.1:34579"
	const key = "203.0.113.7|34579|udp"
	ledgerObserve([]ctFlow{flow(tup, key, 1000, 500)})
	if rx, tx := ledgerCum(key); rx != 1000 || tx != 500 {
		t.Fatalf("first sight should bank full counters, got %d/%d", rx, tx)
	}
	ledgerObserve([]ctFlow{flow(tup, key, 1600, 900)})
	if rx, tx := ledgerCum(key); rx != 1600 || tx != 900 {
		t.Fatalf("growth should add delta only, got %d/%d", rx, tx)
	}
	ledgerObserve(nil) // 流消失: 已入账的一分不少
	if rx, tx := ledgerCum(key); rx != 1600 || tx != 900 {
		t.Fatalf("disappeared flow must keep its banked total, got %d/%d", rx, tx)
	}
	// 同一四元组被新流复用, 计数从小开始 = 新一代, 当前值即新增量
	ledgerObserve([]ctFlow{flow(tup, key, 120, 60)})
	if rx, tx := ledgerCum(key); rx != 1720 || tx != 960 {
		t.Fatalf("new generation should add its own counters, got %d/%d", rx, tx)
	}
	ledgerObserve([]ctFlow{flow(tup, key, 220, 110)})
	if rx, tx := ledgerCum(key); rx != 1820 || tx != 1010 {
		t.Fatalf("new generation growth wrong, got %d/%d", rx, tx)
	}
	// 无字节数据的流不入账
	ledgerObserve([]ctFlow{{Tuple: "udp|x", Key: key, Rx: 999, Tx: 999, HasBytes: false}})
	if rx, _ := ledgerCum(key); rx != 1820 {
		t.Fatalf("no-bytes entry must not be booked, got %d", rx)
	}
}

// 应用重启: 账面与采样基线都从磁盘恢复, 老流继续增长不重复计
func TestLedgerSurvivesRestart(t *testing.T) {
	dir, _ := setupLedger(t)
	const tup = "udp|203.0.113.7:51234>192.0.2.1:34579"
	const key = "203.0.113.7|34579|udp"
	ledgerObserve([]ctFlow{flow(tup, key, 1000, 500)})
	ledgerSaveNow()
	// 模拟进程重启: 清内存状态后重新 init
	ledgerMu.Lock()
	ledgerGen = map[string]*genState{}
	ledgerBankTotal = map[string]*ledgerTotals{}
	ledgerBankDay = map[string]*ledgerTotals{}
	ledgerMu.Unlock()
	ledgerInit(dir)
	if rx, tx := ledgerCum(key); rx != 1000 || tx != 500 {
		t.Fatalf("totals should be restored, got %d/%d", rx, tx)
	}
	ledgerObserve([]ctFlow{flow(tup, key, 1250, 700)})
	if rx, tx := ledgerCum(key); rx != 1250 || tx != 700 {
		t.Fatalf("restart must not double count old flow, got %d/%d", rx, tx)
	}
}

// 手动清空: 账面归零, 但活着的流以清空时为基线, 只记之后的新增
func TestLedgerClearKeepsBaseline(t *testing.T) {
	setupLedger(t)
	const tup = "udp|203.0.113.7:51234>192.0.2.1:34579"
	const key = "203.0.113.7|34579|udp"
	ledgerObserve([]ctFlow{flow(tup, key, 1000, 500)})
	clearLedger()
	if rx, tx := ledgerCum(key); rx != 0 || tx != 0 {
		t.Fatalf("after clear totals must be zero, got %d/%d", rx, tx)
	}
	ledgerObserve([]ctFlow{flow(tup, key, 1100, 560)})
	if rx, tx := ledgerCum(key); rx != 100 || tx != 60 {
		t.Fatalf("post-clear should count only new deltas, got %d/%d", rx, tx)
	}
}

// 跨天: 增量记入新一天, 总累计不断档; 过期每日明细被清理, 近期保留
func TestLedgerDayRolloverAndPrune(t *testing.T) {
	dir, setNow := setupLedger(t)
	settings.LedgerKeepDays = 7
	const tup = "udp|203.0.113.7:51234>192.0.2.1:34579"
	const key = "203.0.113.7|34579|udp"
	ledgerObserve([]ctFlow{flow(tup, key, 100, 0)})
	ledgerSaveNow()
	day1 := filepath.Join(dir, "ledger", "2026-10-24.json")
	if _, err := os.Stat(day1); err != nil {
		t.Fatalf("day1 detail file missing: %v", err)
	}
	// 伪造一份近期明细(3 天前, 应保留)
	recent := filepath.Join(dir, "ledger", "2026-10-29.json")
	os.WriteFile(recent, []byte("{}"), 0644)
	// 8 天后同一条流继续增长 -> 触发跨天与清理
	setNow(time.Date(2026, 11, 1, 9, 0, 0, 0, time.Local))
	ledgerObserve([]ctFlow{flow(tup, key, 260, 0)})
	if rx, _ := ledgerCum(key); rx != 260 {
		t.Fatalf("total must continue across days, got %d", rx)
	}
	if _, err := os.Stat(day1); !os.IsNotExist(err) {
		t.Errorf("day1 detail (8 days old, keep=7) should be pruned")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("recent detail (3 days old) should be kept: %v", err)
	}
	ledgerSaveNow()
	if _, err := os.Stat(filepath.Join(dir, "ledger", "2026-11-01.json")); err != nil {
		t.Errorf("new day detail file missing: %v", err)
	}
}
