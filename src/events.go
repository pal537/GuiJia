package main

// 事件存储: 按天一个 JSONL 文件(data/events/YYYY-MM-DD.jsonl),保留 N 天自动删除
// 统计: stats.json 保存每日计数与当日见过的来源 IP 集合

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID     string `json:"id"`
	Ts     int64  `json:"ts"`
	Type   string `json:"type"` // ssh_login|ssh_fail|ssh_brute|ui_login|new_conn|new_listener|ban|autoban
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Detail string `json:"detail"`
	Geo    string `json:"geo,omitempty"`
}

var (
	evMu     sync.Mutex
	eventSeq int64
)

func pushEvent(ev Event) {
	evMu.Lock()
	defer evMu.Unlock()
	if ev.Ts == 0 {
		ev.Ts = nowMs()
	}
	eventSeq++
	ev.ID = time.Now().Format("20060102150405") + "-" + itoa(int(eventSeq))
	if ev.IP != "" {
		ev.Geo = geoLookup(ev.IP).Text
	}
	day := time.UnixMilli(ev.Ts).Format("2006-01-02")
	dir := eventsDir
	if ev.Type == "new_src" {
		dir = eventsSrcDir // 新来源事件量大价值低: 独立目录、独立保留期
	}
	f, err := os.OpenFile(filepath.Join(dir, day+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	b, _ := json.Marshal(ev)
	f.Write(append(b, '\n'))
	f.Close()
	statsOnEvent(ev)
}

// listEvents 收集全部匹配事件(新→旧)并分页返回, 附带匹配总数——
// 事件页「加载更多」靠 total/hasMore 工作, 所有事件类型同一套逻辑。
// 事件分布在两个目录: eventsDir(常规) 与 eventsSrcDir(新来源), 合并后按时间倒序。
func listEvents(typ, q string, limit, offset int) (page []Event, total int) {
	evMu.Lock()
	files, _ := filepath.Glob(filepath.Join(eventsDir, "*.jsonl"))
	srcFiles, _ := filepath.Glob(filepath.Join(eventsSrcDir, "*.jsonl"))
	evMu.Unlock()
	files = append(files, srcFiles...)
	all := []Event{}
	for _, fp := range files {
		f, err := os.Open(fp)
		if err != nil {
			continue
		}
		var dayEvs []Event
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			var ev Event
			if json.Unmarshal(sc.Bytes(), &ev) == nil {
				dayEvs = append(dayEvs, ev)
			}
		}
		f.Close()
		for i := len(dayEvs) - 1; i >= 0; i-- {
			ev := dayEvs[i]
			if typ != "" && ev.Type != typ {
				continue
			}
			if q != "" && !strings.Contains(ev.IP, q) && !strings.Contains(ev.Detail, q) {
				continue
			}
			all = append(all, ev)
		}
	}
	// 两个目录合并后按时间倒序(同日文件跨目录时文件序不等于时间序)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Ts > all[j].Ts })
	total = len(all)
	if offset > total {
		offset = total
	}
	if limit < 1 {
		limit = 100
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}

func pruneDir(dir string, keepDays int) {
	cut := time.Now().AddDate(0, 0, -keepDays).Format("2006-01-02")
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	for _, fp := range files {
		day := strings.TrimSuffix(filepath.Base(fp), ".jsonl")
		if day < cut {
			os.Remove(fp)
		}
	}
}

func pruneEvents() {
	keep := settings.LogKeepDays
	if keep < 1 {
		keep = 30
	}
	pruneDir(eventsDir, keep)
	// 新来源事件按自己的保留期清理(0 = 不记录, pushEvent 已拦截, 这里清干净)
	pruneDir(eventsSrcDir, settings.NewSrcKeepDays)
}

func clearEvents() {
	for _, dir := range []string{eventsDir, eventsSrcDir} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		for _, fp := range files {
			os.Remove(fp)
		}
	}
}

// ---------- 每日统计 ----------

type DayStats struct {
	Date         string         `json:"date"`
	SSHLogins    int            `json:"sshLogins"`
	SSHFails     int            `json:"sshFails"`
	UILogins     int            `json:"uiLogins"`
	Bans         int            `json:"bans"`         // 今日拉黑次数 = 今日封禁动作数：手动、TG、面板爆破、SSH 爆破、扫描、蜜罐、端口防护的成功封禁各计 1 次
	HoneypotBans int            `json:"honeypotBans"` // 今日蜜罐封禁：今日拉黑里的蜜罐明细（已含在 Bans 总数里，明细 ≤ 总数）
	Sources      map[string]int `json:"sources"`      // 来源IP -> 当日新连接对数
}

var (
	statsMu  sync.Mutex
	statsMap = map[string]*DayStats{}
)

func todayStats() *DayStats {
	day := time.Now().Format("2006-01-02")
	statsMu.Lock()
	defer statsMu.Unlock()
	ds := statsMap[day]
	if ds == nil {
		ds = &DayStats{Date: day, Sources: map[string]int{}}
		statsMap[day] = ds
	}
	return ds
}

func loadStats() {
	if b, err := os.ReadFile(statsFile); err == nil {
		json.Unmarshal(b, &statsMap)
	}
	for _, ds := range statsMap {
		if ds.Sources == nil {
			ds.Sources = map[string]int{}
		}
	}
}

func saveStats() {
	statsMu.Lock()
	defer statsMu.Unlock()
	// 只保留最近 40 天
	cut := time.Now().AddDate(0, 0, -40).Format("2006-01-02")
	for d := range statsMap {
		if d < cut {
			delete(statsMap, d)
		}
	}
	saveJSON(statsFile, statsMap)
}

func statsOnEvent(ev Event) {
	ds := todayStats()
	statsMu.Lock()
	defer statsMu.Unlock()
	switch ev.Type {
	case "ssh_login":
		ds.SSHLogins++
	case "ssh_fail":
		ds.SSHFails++
	case "ui_login":
		ds.UILogins++
	case "ban", "autoban", "portguard_ban":
		// 今日拉黑 = 今日全部封禁动作数：手动、TG、面板爆破、SSH 爆破、
		// 扫描、端口防护的成功封禁各计 1 次；解封（unban）不计。
		ds.Bans++
	case "honeypot_ban":
		// 蜜罐封禁同时计入总数与明细（明细 ≤ 总数）；蜜罐 handler 不再
		// 直接改 HoneypotBans，单一事件源头，避免两者对不上。
		ds.Bans++
		ds.HoneypotBans++
	}
}

// recalibrateTodayStats 启动时用当日事件文件重算今日封禁数与蜜罐分端口命中。
// 只读 eventsDir/<今日>.jsonl 一遍：ban/autoban/honeypot_ban/portguard_ban 计入
// Bans，honeypot_ban 计入 HoneypotBans，honeypot_hit 按端口分组计入命中。
// 只覆盖当日条目的 Bans/HoneypotBans（覆盖不是累加，绝不双计），其他字段、
// 其他日期一律不动；坏行跳过不中断；当日文件不存在时不动（无证据不改数）。
// 幂等：事件落盘在统计之前，崩溃重算结果不变；运行中增量从校准值起算。
func recalibrateTodayStats() {
	day := time.Now().Format("2006-01-02")
	f, err := os.Open(filepath.Join(eventsDir, day+".jsonl"))
	if err != nil {
		return
	}
	defer f.Close()
	var bans, hpBans int
	hits := map[int]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var ev Event
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "ban", "autoban", "honeypot_ban", "portguard_ban":
			bans++
		}
		if ev.Type == "honeypot_ban" {
			hpBans++
		}
		if ev.Type == "honeypot_hit" && ev.Port > 0 {
			hits[ev.Port]++
		}
	}
	statsMu.Lock()
	ds := statsMap[day]
	if ds == nil {
		ds = &DayStats{Date: day, Sources: map[string]int{}}
		statsMap[day] = ds
	}
	ds.Bans = bans
	ds.HoneypotBans = hpBans
	statsMu.Unlock()
	honeypotMu.Lock()
	honeypotPortDay = day
	honeypotPortHits = hits
	honeypotMu.Unlock()
}

// 记录一个新连接对(srcIP -> 本地端口), 返回该 IP 是否是今日首次出现
func statsNewConn(ip string, port int) bool {
	ds := todayStats()
	statsMu.Lock()
	defer statsMu.Unlock()
	_, seen := ds.Sources[ip]
	ds.Sources[ip]++
	return !seen
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
