package main

// 流量账本: conntrack 的每流字节计数随流消亡而清零, 断续连接(如 QB 对端反复
// 连上/断开)的历史总量会丢。本账本每 2 秒采样每条流的计数, 把两次采样之间
// 新增的字节持续累加进账本; 同一条流计数回退, 说明旧流已死、新流复用了同一
// 四元组, 按新流从零开始的数值继续累加。增量在采样当下就入账, 不等流结束,
// 所以流消失时已记部分不会丢。
// 账本分两层: 永久累计(只增不减, 不自动清理) + 每日明细(按设置保留天数清理)。
// 列表默认仍显示本次连接流量; 本账本的累计供悬停显示。
// 采样口径限制: 活不过一个采样间隔的微连接可能漏记, 属预期内近似(九成五以上覆盖)。

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ctFlow 是 conntrack 里的一条流(不聚合), Tuple 标识这一条流的这一代。
type ctFlow struct {
	Tuple    string
	Key      string // 展示键 peer|port|proto, 与连接列表同键
	Rx, Tx   uint64
	HasBytes bool
}

// parseCTFlowEntries 与 ctConns 完全同口径(入站/外连/容器外连的分类与字节取向),
// 区别只是逐流返回不聚合。parse_test 里有双口径对账测试防漂移。
func parseCTFlowEntries(content string, locals map[string]bool, eff map[int]bool) []ctFlow {
	out := []ctFlow{}
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := f[2]
		if proto != "udp" && proto != "tcp" {
			continue
		}
		if proto == "tcp" {
			stOK := false
			for _, tok := range f[3:] {
				if tok == "ESTABLISHED" || tok == "SYN_RECV" {
					stOK = true
					break
				}
				if strings.Contains(tok, "=") {
					break
				}
			}
			if !stOK {
				continue
			}
		}
		var tupBytes [2]uint64
		tupIdx := -1
		sawBytes := false
		for _, tok := range f[4:] {
			if tok == "packets" || strings.HasPrefix(tok, "packets=") {
				if tupIdx < 1 {
					tupIdx++
				}
				continue
			}
			if strings.HasPrefix(tok, "bytes=") && tupIdx >= 0 {
				sawBytes = true
				if bv, err := strconv.ParseUint(tok[len("bytes="):], 10, 64); err == nil {
					tupBytes[tupIdx] = bv
				}
			}
		}
		tuples := []map[string]string{{}}
		cur := tuples[0]
		for _, tok := range f[4:] {
			eq := strings.Index(tok, "=")
			if eq < 0 {
				continue
			}
			k, v := tok[:eq], tok[eq+1:]
			if k == "src" && len(cur) > 0 {
				cur = map[string]string{}
				tuples = append(tuples, cur)
			}
			cur[k] = v
		}
		orig := tuples[0]
		srcIP, dstIP := normalizeIP(orig["src"]), normalizeIP(orig["dst"])
		sport, _ := strconv.Atoi(orig["sport"])
		dport, _ := strconv.Atoi(orig["dport"])
		var peer string
		var wport int
		inbound := false
		switch {
		case locals[dstIP] && eff[dport]:
			peer, wport = srcIP, dport
			inbound = true
		case locals[srcIP] && eff[sport]:
			peer, wport = dstIP, sport
		case eff[sport]:
			if pip := net.ParseIP(srcIP); pip != nil && isPrivateIP(pip) {
				peer, wport = dstIP, sport
			} else {
				continue
			}
		default:
			continue
		}
		if peer == "" || locals[peer] {
			continue
		}
		if pip := net.ParseIP(peer); pip == nil || pip.IsLoopback() {
			continue
		}
		origB, replyB := tupBytes[0], tupBytes[1]
		rx, tx := origB, replyB
		if !inbound {
			rx, tx = replyB, origB
		}
		out = append(out, ctFlow{
			Tuple:    proto + "|" + srcIP + ":" + itoa(sport) + ">" + dstIP + ":" + itoa(dport),
			Key:      peer + "|" + itoa(wport) + "|" + proto,
			Rx:       rx,
			Tx:       tx,
			HasBytes: sawBytes,
		})
	}
	return out
}

// ---------- 账本状态 ----------

type ledgerTotals struct {
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

type genState struct {
	Key      string `json:"key"`
	Rx       uint64 `json:"rx"` // 上次采样见到的原始计数
	Tx       uint64 `json:"tx"`
	LastSeen int64  `json:"lastSeen"` // unix 秒; 流消失后保留一小段时间, 防采样抖动误判新流
}

var (
	ledgerMu        sync.Mutex
	ledgerGen       = map[string]*genState{}     // tuple -> 上次采样计数
	ledgerBankTotal = map[string]*ledgerTotals{} // key -> 永久累计
	ledgerBankDay   = map[string]*ledgerTotals{} // key -> 今日累计增量
	ledgerDayStr    string
	ledgerDirty     bool
	ledgerTotalFile string
	ledgerGenFile   string
	ledgerDayDir    string
	nowFn           = time.Now // 测试可注入
)

const ledgerGenKeepSec = 900 // 流消失后其采样状态保留 15 分钟再清

func ledgerInit(dir string) {
	ledgerTotalFile = filepath.Join(dir, "ledger-total.json")
	ledgerGenFile = filepath.Join(dir, "ledger-gen.json")
	ledgerDayDir = filepath.Join(dir, "ledger")
	os.MkdirAll(ledgerDayDir, 0755)
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	if b, err := os.ReadFile(ledgerTotalFile); err == nil {
		json.Unmarshal(b, &ledgerBankTotal)
		if ledgerBankTotal == nil {
			ledgerBankTotal = map[string]*ledgerTotals{}
		}
	}
	if b, err := os.ReadFile(ledgerGenFile); err == nil {
		json.Unmarshal(b, &ledgerGen)
		if ledgerGen == nil {
			ledgerGen = map[string]*genState{}
		}
	}
	ledgerDayStr = nowFn().Format("2006-01-02")
	ledgerBankDay = loadLedgerDayLocked(ledgerDayStr)
}

func loadLedgerDayLocked(day string) map[string]*ledgerTotals {
	m := map[string]*ledgerTotals{}
	if b, err := os.ReadFile(filepath.Join(ledgerDayDir, day+".json")); err == nil {
		json.Unmarshal(b, &m)
		if m == nil {
			m = map[string]*ledgerTotals{}
		}
	}
	return m
}

func ledgerAddLocked(key string, rx, tx uint64) {
	if rx == 0 && tx == 0 {
		return
	}
	t := ledgerBankTotal[key]
	if t == nil {
		t = &ledgerTotals{}
		ledgerBankTotal[key] = t
	}
	t.Rx += rx
	t.Tx += tx
	d := ledgerBankDay[key]
	if d == nil {
		d = &ledgerTotals{}
		ledgerBankDay[key] = d
	}
	d.Rx += rx
	d.Tx += tx
	ledgerDirty = true
}

// ledgerObserve 吃一拍逐流采样: 把每条流相对上次采样的新增字节累加进账本。
// 计数回退 = 旧流已死、新流复用同一四元组, 新流当前的数值就是它的新增量。
func ledgerObserve(entries []ctFlow) {
	now := nowFn()
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	day := now.Format("2006-01-02")
	if day != ledgerDayStr {
		// 跨天: 先把旧日明细落盘, 再切到新一天(新一天已有文件则续记)
		saveLedgerLocked()
		ledgerDayStr = day
		ledgerBankDay = loadLedgerDayLocked(day)
		pruneLedgerLocked()
	}
	nowSec := now.Unix()
	for _, e := range entries {
		if !e.HasBytes {
			continue
		}
		g := ledgerGen[e.Tuple]
		if g == nil {
			// 第一次见到这条流: 它当前的计数就是已产生的量, 整体入账
			ledgerAddLocked(e.Key, e.Rx, e.Tx)
			ledgerGen[e.Tuple] = &genState{Key: e.Key, Rx: e.Rx, Tx: e.Tx, LastSeen: nowSec}
			continue
		}
		var dRx, dTx uint64
		if e.Rx >= g.Rx {
			dRx = e.Rx - g.Rx
		} else {
			dRx = e.Rx // 计数回退: 新一代流, 当前值即新增量
		}
		if e.Tx >= g.Tx {
			dTx = e.Tx - g.Tx
		} else {
			dTx = e.Tx
		}
		if g.Key == e.Key {
			ledgerAddLocked(e.Key, dRx, dTx)
		} else {
			// 同一四元组极少会改归属键; 万一发生, 按方向无法拆分, 记到新键
			ledgerAddLocked(e.Key, dRx, dTx)
		}
		g.Rx, g.Tx, g.Key, g.LastSeen = e.Rx, e.Tx, e.Key, nowSec
	}
	// 消失的流不做任何结转(增量早已逐拍入账); 其采样状态保留一小段时间,
	// 防同一条流因采样抖动短暂缺席被误判成新流而重复计数
	for tup, g := range ledgerGen {
		if nowSec-g.LastSeen > ledgerGenKeepSec {
			delete(ledgerGen, tup)
		}
	}
}

// ledgerCum 返回某展示键的累计总量(增量逐拍入账, 这里就是账面值)。
func ledgerCum(key string) (uint64, uint64) {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	if t := ledgerBankTotal[key]; t != nil {
		return t.Rx, t.Tx
	}
	return 0, 0
}

func saveLedgerLocked() {
	if ledgerTotalFile == "" {
		return
	}
	if b, err := json.Marshal(ledgerBankTotal); err == nil {
		tmp := ledgerTotalFile + ".tmp"
		if os.WriteFile(tmp, b, 0644) == nil {
			os.Rename(tmp, ledgerTotalFile)
		}
	}
	if b, err := json.Marshal(ledgerBankDay); err == nil {
		p := filepath.Join(ledgerDayDir, ledgerDayStr+".json")
		tmp := p + ".tmp"
		if os.WriteFile(tmp, b, 0644) == nil {
			os.Rename(tmp, p)
		}
	}
	// 采样状态一并落盘: 应用重启后接着上次的计数算增量, 不重复计旧流量
	if b, err := json.Marshal(ledgerGen); err == nil && ledgerGenFile != "" {
		tmp := ledgerGenFile + ".tmp"
		if os.WriteFile(tmp, b, 0644) == nil {
			os.Rename(tmp, ledgerGenFile)
		}
	}
	ledgerDirty = false
}

// clearLedger 手动清空账本: 累计与每日明细归零, 每日文件删除。
// 各流的采样基线保留(基线之后的增量继续记), 避免活着的流把清空前的量再算进来。
func clearLedger() {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	ledgerBankTotal = map[string]*ledgerTotals{}
	ledgerBankDay = map[string]*ledgerTotals{}
	saveLedgerLocked()
	if files, err := filepath.Glob(filepath.Join(ledgerDayDir, "????-??-??.json")); err == nil {
		for _, f := range files {
			if filepath.Base(f)[:10] != ledgerDayStr {
				os.Remove(f)
			}
		}
	}
}

// ledgerReload 数据恢复后重读账本文件(恢复流程专用): 文件已替换,
// 内存旧账本必须丢弃, 否则下次落盘会把恢复前的数据写回去。
func ledgerReload() {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	if b, err := os.ReadFile(ledgerTotalFile); err == nil {
		json.Unmarshal(b, &ledgerBankTotal)
		if ledgerBankTotal == nil {
			ledgerBankTotal = map[string]*ledgerTotals{}
		}
	} else {
		ledgerBankTotal = map[string]*ledgerTotals{}
	}
	if b, err := os.ReadFile(ledgerGenFile); err == nil {
		json.Unmarshal(b, &ledgerGen)
		if ledgerGen == nil {
			ledgerGen = map[string]*genState{}
		}
	} else {
		ledgerGen = map[string]*genState{}
	}
	ledgerDayStr = nowFn().Format("2006-01-02")
	ledgerBankDay = loadLedgerDayLocked(ledgerDayStr)
	ledgerDirty = false
}

// ledgerFlush 脏了才落盘(housekeep 每分钟调)。
func ledgerFlush() {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	if ledgerDirty {
		saveLedgerLocked()
	}
}

// ledgerSaveNow 无条件落盘(退出时调)。
func ledgerSaveNow() {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	saveLedgerLocked()
}

// ledgerPrune 清理过期每日明细(housekeep 每分钟调; 跨天时也会调)。
func ledgerPrune() {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	pruneLedgerLocked()
}

// pruneLedgerLocked 按设置清理过期每日明细; 永久累计永不清理。
func pruneLedgerLocked() {
	mu.Lock()
	keep := settings.LedgerKeepDays
	mu.Unlock()
	if keep <= 0 || ledgerDayDir == "" {
		return
	}
	files, err := filepath.Glob(filepath.Join(ledgerDayDir, "????-??-??.json"))
	if err != nil {
		return
	}
	sort.Strings(files)
	cutoff := nowFn().AddDate(0, 0, -keep).Format("2006-01-02")
	for _, f := range files {
		if filepath.Base(f)[:10] < cutoff {
			os.Remove(f)
		}
	}
}

func ledgerTick() {
	mu.Lock()
	acctOn := settings.TrafficAcct
	mu.Unlock()
	if !acctOn {
		return // 流量统计关着时 conntrack 也没有字节计数, 账本暂停(已有账面保留)
	}
	b, err := os.ReadFile(ctPath)
	if err != nil {
		return
	}
	eff, _ := effPorts()
	effSet := map[int]bool{}
	for p := range eff {
		effSet[p] = true
	}
	ledgerObserve(parseCTFlowEntries(string(b), localIPSet(), effSet))
}

func ledgerLoop() {
	ledgerTick()
	t := time.NewTicker(2 * time.Second)
	for range t.C {
		ledgerTick()
	}
}
