package main

// 端口范围(第 7 项): 按范围存储(起止两个数), 绝不展开成 50000 条;
// 匹配用一张 65536 位图, 查哪个端口都是 O(1)。
// 核心不变量: 星标与普通互斥, 一个端口同一时间只属于一边; 星标永远赢:
//  - 加普通撞上星标 -> 新段绕开星标切开, 星标保持不变;
//  - 加星标撞上普通 -> 普通被切开让路(单个移除、范围切成两段);
//  - 同类重叠 -> 修剪/已包含, 不重复存。

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

type PortRange struct {
	From   int    `json:"from"`
	To     int    `json:"to"`
	Name   string `json:"name"`
	Star   bool   `json:"star"`
	Kind   string `json:"kind"`
	Source string `json:"source"` // manual(范围只由用户添加, 防火墙同步不产生范围)
}

// portIndex 是位图快照: 发布后不再修改, 读方无锁(原子指针交换)。
type portIndex struct {
	cover    [65536]uint8 // 0 无, 1 普通, 2 星标(单个优先于范围)
	rangeIdx [65536]int32 // 0 无, 否则范围下标+1
	ignored  [65536]bool  // 删除/忽略的端口(单个 + 范围), 防火墙同步不再导回
}

var portIndexPtr atomic.Pointer[portIndex]

// rebuildPortIndex 从当前清单重建位图。调用方须持有 mu(或在启动单线程期)。
func rebuildPortIndex() {
	idx := &portIndex{}
	for _, p := range ports {
		if p == nil || p.Port < 1 || p.Port > 65535 {
			continue
		}
		if p.Star {
			idx.cover[p.Port] = 2
		} else {
			idx.cover[p.Port] = 1
		}
	}
	for i, r := range portRanges {
		if r == nil {
			continue
		}
		class := uint8(1)
		if r.Star {
			class = 2
		}
		for p := r.From; p <= r.To && p <= 65535; p++ {
			if p < 1 {
				continue
			}
			if idx.cover[p] == 0 {
				idx.cover[p] = class
			}
			if idx.rangeIdx[p] == 0 {
				idx.rangeIdx[p] = int32(i) + 1
			}
		}
	}
	for p := range ignoredPorts {
		if p >= 1 && p <= 65535 {
			idx.ignored[p] = true
		}
	}
	for _, r := range ignoredRanges {
		for p := r.From; p <= r.To && p <= 65535; p++ {
			if p >= 1 {
				idx.ignored[p] = true
			}
		}
	}
	portIndexPtr.Store(idx)
}

// rangeCovered 查某端口是否被任一范围覆盖(O(1), 无锁)。
func rangeCovered(port int) bool {
	idx := portIndexPtr.Load()
	if idx == nil || port < 1 || port > 65535 {
		return false
	}
	return idx.rangeIdx[port] > 0
}

// rangeIgnored 查某端口是否在忽略集合里(O(1), 无锁)。
func rangeIgnored(port int) bool {
	idx := portIndexPtr.Load()
	if idx == nil || port < 1 || port > 65535 {
		return false
	}
	return idx.ignored[port]
}

// portCoverClass 查某端口的覆盖类别: 0 无, 1 普通, 2 星标。
func portCoverClass(port int) uint8 {
	idx := portIndexPtr.Load()
	if idx == nil || port < 1 || port > 65535 {
		return 0
	}
	return idx.cover[port]
}

// coverCounts 返回(被覆盖端口总数, 其中星标数)。
func coverCounts() (covered, starred int) {
	idx := portIndexPtr.Load()
	if idx == nil {
		return 0, 0
	}
	for p := 1; p <= 65535; p++ {
		if idx.cover[p] != 0 {
			covered++
			if idx.cover[p] == 2 {
				starred++
			}
		}
	}
	return covered, starred
}

// lookupPort 单个优先、再范围: 返回该端口的监控条目(范围合成一条)。
// 调用方可不持 mu(内部短暂加锁读切片)。
func lookupPort(port int) *PortWatch {
	mu.Lock()
	p := findPort(port)
	var rng *PortRange
	if p == nil {
		if idx := portIndexPtr.Load(); idx != nil && port >= 1 && port <= 65535 {
			if ri := idx.rangeIdx[port]; ri > 0 && int(ri)-1 < len(portRanges) {
				rng = portRanges[ri-1]
			}
		}
	}
	mu.Unlock()
	if p != nil {
		return p
	}
	if rng != nil {
		return &PortWatch{Port: port, Proto: "tcp", Name: rng.Name, Star: rng.Star, Source: rng.Source, Kind: rng.Kind}
	}
	return nil
}

// ---------- 输入解析 ----------

type rangeSeg struct{ from, to int }

// parsePortSpec 解析"单个/范围/逗号组合", 错了明确报哪一段有问题。
func parsePortSpec(spec string) ([]rangeSeg, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("端口不能为空")
	}
	var segs []rangeSeg
	for i, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		segNo := i + 1
		if part == "" {
			return nil, fmt.Errorf("第 %d 段为空", segNo)
		}
		if strings.Contains(part, "-") {
			f := strings.SplitN(part, "-", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(f[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(f[1]))
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("第 %d 段 %q 无效: 范围须为 1-65535 且起始不大于结束", segNo, part)
			}
			segs = append(segs, rangeSeg{a, b})
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("第 %d 段 %q 无效: 端口须为 1-65535 的整数", segNo, part)
		}
		segs = append(segs, rangeSeg{n, n})
	}
	return segs, nil
}

// ---------- 区间运算(纯函数, 不碰全局状态) ----------

// subtractSeg 从 [a,b] 里减掉一批已覆盖区间, 返回剩余段(升序)。
func subtractSeg(a, b int, covered []rangeSeg) []rangeSeg {
	segs := []rangeSeg{{a, b}}
	for _, c := range covered {
		var next []rangeSeg
		for _, s := range segs {
			if c.to < s.from || c.from > s.to {
				next = append(next, s)
				continue
			}
			if s.from < c.from {
				next = append(next, rangeSeg{s.from, c.from - 1})
			}
			if s.to > c.to {
				next = append(next, rangeSeg{c.to + 1, s.to})
			}
		}
		segs = next
		if len(segs) == 0 {
			break
		}
	}
	return segs
}

// intersectSeg [a,b] 与一批区间的交集(升序)。
func intersectSeg(a, b int, covered []rangeSeg) []rangeSeg {
	var out []rangeSeg
	for _, c := range covered {
		lo := max(a, c.from)
		hi := min(b, c.to)
		if lo <= hi {
			out = append(out, rangeSeg{lo, hi})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].from < out[j].from })
	return out
}

// ---------- 添加规划 ----------

type rangeAddPiece struct {
	From    int    `json:"from"`
	To      int    `json:"to"`
	Star    bool   `json:"star"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	AsRange bool   `json:"asRange"` // true=存成范围条目, false=存成单个条目
}

type rangeCut struct {
	From   int             `json:"from"`
	To     int             `json:"to"`
	Single bool            `json:"single"`
	Remain []rangeAddPiece `json:"remain"` // 切开后剩下的段(空=整条移除)
}

type rangeSkip struct {
	From   int    `json:"from"`
	To     int    `json:"to"`
	Reason string `json:"reason"`
}

type rangeAddPlan struct {
	ToAdd        []rangeAddPiece `json:"toAdd"`
	Cut          []rangeCut      `json:"cut,omitempty"`
	Skipped      []rangeSkip     `json:"skipped,omitempty"`
	ExcludedSelf []int           `json:"excludedSelf,omitempty"`
	// 内部用: 是否有任何"需要用户先看一眼"的变化(切开/跳过/排除自身)
	NeedsPreview bool `json:"-"`
}

// planRangeAdd 规划一次添加(纯读全局, 调用方须持有 mu)。
// 星标赢——普通覆盖被切开让路, 星标覆盖只跳过;
// 普通——新段绕开一切已有覆盖, 已有条目一律不动。
// 多段输入按顺序规划, 每段的结果滚动进工作覆盖集, 故段与段重叠也不会
// 在存储里留下重叠条目。
func planRangeAdd(segs []rangeSeg, star bool, name, kind string) *rangeAddPlan {
	plan := &rangeAddPlan{}
	wStar, wPlain, wPlainSingles, wPlainRanges := workingCoverage()
	selfPorts := map[int]bool{}
	for _, sp := range []int{18793, appPort()} {
		selfPorts[sp] = true
	}
	planOne := func(seg rangeSeg, asRange bool) {
		partial := planRangeAddOne(seg, star, name, kind, asRange, wStar, wPlain, wPlainSingles, wPlainRanges)
		plan.ToAdd = append(plan.ToAdd, partial.ToAdd...)
		plan.Cut = append(plan.Cut, partial.Cut...)
		plan.Skipped = append(plan.Skipped, partial.Skipped...)
		// 滚动工作覆盖集
		if star {
			for _, t := range partial.ToAdd {
				wStar = append(wStar, rangeSeg{t.From, t.To})
			}
			for _, c := range partial.Cut {
				if c.Single {
					wPlainSingles = subtractSegs(wPlainSingles, c.From, c.To)
					wPlain = subtractSegs(wPlain, c.From, c.To)
				} else {
					wPlainRanges = replaceSeg(wPlainRanges, c.From, c.To, c.Remain)
					wPlain = subtractSegs(wPlain, c.From, c.To)
					for _, m := range c.Remain {
						wPlain = append(wPlain, rangeSeg{m.From, m.To})
					}
				}
			}
		} else {
			for _, t := range partial.ToAdd {
				wPlain = append(wPlain, rangeSeg{t.From, t.To})
				if t.AsRange {
					wPlainRanges = append(wPlainRanges, rangeSeg{t.From, t.To})
				} else {
					wPlainSingles = append(wPlainSingles, rangeSeg{t.From, t.To})
				}
			}
		}
	}
	for _, seg := range segs {
		asRange := seg.from != seg.to
		if star {
			// 星标范围自动排除自身端口(只监控不排除)
			var selfSegs []rangeSeg
			for sp := range selfPorts {
				if sp >= seg.from && sp <= seg.to {
					plan.ExcludedSelf = append(plan.ExcludedSelf, sp)
					selfSegs = append(selfSegs, rangeSeg{sp, sp})
				}
			}
			if len(selfSegs) > 0 {
				for _, rs := range subtractSeg(seg.from, seg.to, selfSegs) {
					planOne(rs, asRange)
				}
				continue
			}
		}
		planOne(seg, asRange)
	}
	sort.Ints(plan.ExcludedSelf)
	{
		// 同一自身端口出现在多段里时去重
		dedup := plan.ExcludedSelf[:0]
		for i, p := range plan.ExcludedSelf {
			if i == 0 || p != plan.ExcludedSelf[i-1] {
				dedup = append(dedup, p)
			}
		}
		plan.ExcludedSelf = dedup
	}
	plan.NeedsPreview = len(plan.Cut) > 0 || len(plan.Skipped) > 0 || len(plan.ExcludedSelf) > 0
	return plan
}

// workingCoverage 取当前覆盖集的副本(单个 + 范围, 按类别分)。
func workingCoverage() (star, plain, plainSingles, plainRanges []rangeSeg) {
	for _, p := range ports {
		if p == nil {
			continue
		}
		if p.Star {
			star = append(star, rangeSeg{p.Port, p.Port})
		} else {
			plain = append(plain, rangeSeg{p.Port, p.Port})
			plainSingles = append(plainSingles, rangeSeg{p.Port, p.Port})
		}
	}
	for _, r := range portRanges {
		if r == nil {
			continue
		}
		if r.Star {
			star = append(star, rangeSeg{r.From, r.To})
		} else {
			plain = append(plain, rangeSeg{r.From, r.To})
			plainRanges = append(plainRanges, rangeSeg{r.From, r.To})
		}
	}
	return star, plain, plainSingles, plainRanges
}

// subtractSegs 从区间集里减掉 [a,b](用于工作集滚动)。
func subtractSegs(segs []rangeSeg, a, b int) []rangeSeg {
	var out []rangeSeg
	for _, s := range segs {
		out = append(out, subtractSeg(s.from, s.to, []rangeSeg{{a, b}})...)
	}
	return out
}

// replaceSeg 把区间集里与 [a,b] 相交的段替换为 remain 段(用于工作集滚动)。
func replaceSeg(segs []rangeSeg, a, b int, remain []rangeAddPiece) []rangeSeg {
	var out []rangeSeg
	for _, s := range segs {
		if s.to < a || s.from > b {
			out = append(out, s)
			continue
		}
		for _, m := range remain {
			out = append(out, rangeSeg{m.From, m.To})
		}
	}
	return out
}

func planRangeAddOne(seg rangeSeg, star bool, name, kind string, asRange bool, starCovered, plainCovered, plainSingles, plainRanges []rangeSeg) *rangeAddPlan {
	plan := &rangeAddPlan{}
	a, b := seg.from, seg.to
	if star {
		// 星标: 只绕开星标覆盖; 普通覆盖切开让路
		for _, s := range intersectSeg(a, b, starCovered) {
			plan.Skipped = append(plan.Skipped, rangeSkip{s.from, s.to, "已星标, 保持不变"})
		}
		for _, s := range intersectSeg(a, b, plainSingles) {
			plan.Cut = append(plan.Cut, rangeCut{From: s.from, To: s.to, Single: true})
		}
		for _, r := range plainRanges {
			if r.to < a || r.from > b {
				continue
			}
			remain := subtractSeg(r.from, r.to, []rangeSeg{{a, b}})
			var rp []rangeAddPiece
			for _, m := range remain {
				rp = append(rp, rangeAddPiece{From: m.from, To: m.to, AsRange: true})
			}
			plan.Cut = append(plan.Cut, rangeCut{From: r.from, To: r.to, Remain: rp})
		}
		for _, s := range subtractSeg(a, b, starCovered) {
			plan.ToAdd = append(plan.ToAdd, rangeAddPiece{From: s.from, To: s.to, Star: true, Name: name, Kind: kind, AsRange: asRange})
		}
		return plan
	}
	// 普通: 绕开一切已有覆盖, 已有条目不动
	allCovered := append(append([]rangeSeg{}, starCovered...), plainCovered...)
	for _, s := range intersectSeg(a, b, starCovered) {
		plan.Skipped = append(plan.Skipped, rangeSkip{s.from, s.to, "已星标, 保持不变"})
	}
	for _, s := range intersectSeg(a, b, plainCovered) {
		plan.Skipped = append(plan.Skipped, rangeSkip{s.from, s.to, "已在监控中"})
	}
	for _, s := range subtractSeg(a, b, allCovered) {
		plan.ToAdd = append(plan.ToAdd, rangeAddPiece{From: s.from, To: s.to, Star: false, Name: name, Kind: kind, AsRange: asRange})
	}
	return plan
}

// applyRangeAddPlan 执行规划(调用方须持有 mu): 切开普通条目, 追加新条目。
func applyRangeAddPlan(plan *rangeAddPlan) {
	// 切普通单个
	cutSingles := map[int]bool{}
	for _, c := range plan.Cut {
		if c.Single {
			cutSingles[c.From] = true
		}
	}
	if len(cutSingles) > 0 {
		kept := []*PortWatch{}
		for _, p := range ports {
			if p != nil && !cutSingles[p.Port] {
				kept = append(kept, p)
			}
		}
		ports = kept
	}
	// 顺序切普通范围: 每个切口在当前清单里按起止精确匹配一条, 替换为剩余段。
	// 后一个切口可能引用前一个切口切出的剩余段, 故必须顺序匹配、不能一次性
	// 按原始起止匹配。
	for _, c := range plan.Cut {
		if c.Single {
			continue
		}
		for i, r := range portRanges {
			if r == nil || r.Star || r.From != c.From || r.To != c.To {
				continue
			}
			var repl []*PortRange
			for _, m := range c.Remain {
				repl = append(repl, &PortRange{From: m.From, To: m.To, Name: r.Name, Star: false, Kind: r.Kind, Source: r.Source})
			}
			portRanges = append(portRanges[:i], append(repl, portRanges[i+1:]...)...)
			break
		}
	}
	for _, t := range plan.ToAdd {
		if t.AsRange {
			portRanges = append(portRanges, &PortRange{From: t.From, To: t.To, Name: t.Name, Star: t.Star, Kind: t.Kind, Source: "manual"})
		} else {
			ports = append(ports, &PortWatch{Port: t.From, Proto: "tcp", Name: t.Name, Star: t.Star, Source: "manual", Kind: t.Kind})
		}
	}
	rebuildPortIndex()
}
