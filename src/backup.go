package main

// 备份与恢复(第 9 项): 设置备份与数据备份分开。
// 设置备份 = 一个 JSON 下载: settings.json + ports.json + 蜜罐配置 + 反代配置
// (proxy.json, 全部配置, 不含数据) + 反代上传证书的 PEM 对(仅上传来源,
// 扫描来源是只读系统文件, 不打包); 黑名单归数据备份, 只恢复设置不会带回黑名单。
// 数据备份 = 一个 zip 下载(Windows 可直接打开): bans.json + stats.json +
// events/*.jsonl + events-src/*.jsonl + 流量账本。
// 恢复前自动拍当前快照(data/snapshots/, 每种最新 5 份, 与备份同格式,
// 可用同样入口导回); 恢复数据后立即重做 nft 对账; 恢复设置里的反代后
// 立即重载反代配置并重起监听。
// 备份文件含版本号, 版本不匹配警告(新键补默认、未知键忽略)。
// 注意: 设置备份含 TG 机器人 token 与反代上传证书的私钥, 下载时前端先弹"妥善保管、勿外传"确认。

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const backupFormat = 1

const backupSnapshotKeep = 5

func backupSnapshotDir() string {
	d := filepath.Join(dataDir, "snapshots")
	os.MkdirAll(d, 0755)
	return d
}

// nextSnapshotPath 快照文件名(秒级时间戳, 同秒冲突加序号)。
func nextSnapshotPath(kind, ext string) string {
	dir := backupSnapshotDir()
	base := time.Now().Format("20060102-150405")
	p := filepath.Join(dir, kind+"-"+base+ext)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	for i := 2; i < 100; i++ {
		p = filepath.Join(dir, fmt.Sprintf("%s-%s-%d%s", kind, base, i, ext))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
	}
	return p
}

func pruneSnapshots(kind, ext string) {
	dir := backupSnapshotDir()
	files, _ := filepath.Glob(filepath.Join(dir, kind+"-*"+ext))
	sort.Strings(files) // 文件名含时间戳, 字典序 = 时间序
	for len(files) > backupSnapshotKeep {
		os.Remove(files[0])
		files = files[1:]
	}
}

// ---------- 设置备份 ----------

type settingsBackup struct {
	Format     int                        `json:"format"`
	App        string                     `json:"app"`
	CreatedAt  int64                      `json:"createdAt"`
	Kind       string                     `json:"kind"` // "settings"
	Settings   json.RawMessage            `json:"settings"`
	Ports      json.RawMessage            `json:"ports"`
	Honeypot   json.RawMessage            `json:"honeypot,omitempty"`
	Proxy      json.RawMessage            `json:"proxy,omitempty"`
	ProxyCerts map[string]proxyCertBackup `json:"proxyCerts,omitempty"`
}

// proxyCertBackup 反代上传证书的一对 PEM(仅上传来源)。
type proxyCertBackup struct {
	Crt string `json:"crt"`
	Key string `json:"key"`
}

// buildSettingsBackup 从磁盘文件原样打包(保真: 含 RescuePassHash 等全部键;
// 磁盘文件缺失时回落到内存值)。
func buildSettingsBackup() ([]byte, error) {
	readOrMarshal := func(path string, fallback any) json.RawMessage {
		if b, err := os.ReadFile(path); err == nil && json.Valid(b) {
			return json.RawMessage(b)
		}
		b, _ := json.Marshal(fallback)
		return json.RawMessage(b)
	}
	env := settingsBackup{
		Format: backupFormat, App: appVersion, CreatedAt: time.Now().Unix(), Kind: "settings",
		Settings: readOrMarshal(settingFile, settingsSnapshot()),
		Ports:    readOrMarshal(portsFile, portsSnapshot()),
	}
	if proxyFile != "" {
		env.Proxy = readOrMarshal(proxyFile, proxyConfigSnapshot())
	}
	if b, err := os.ReadFile(honeypotFile); err == nil && json.Valid(b) {
		env.Honeypot = json.RawMessage(b)
	}
	env.ProxyCerts = collectProxyCertBackup()
	return json.MarshalIndent(env, "", "  ")
}

// proxyConfigSnapshot 内存反代配置回落值(文件缺失时用)。
func proxyConfigSnapshot() ProxyConfig {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	cfg := proxyCfg
	rules := []*ProxyRule{}
	for _, rr := range proxyCfg.Rules {
		cp := *rr
		rules = append(rules, &cp)
	}
	cfg.Rules = rules
	return cfg
}

// collectProxyCertBackup 打包上传证书的 PEM 对(扫描来源不打包)。
func collectProxyCertBackup() map[string]proxyCertBackup {
	dir := filepath.Join(dataDir, "certs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := map[string]proxyCertBackup{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".crt")
		if !proxyCertNameRe.MatchString(name) || strings.Contains(name, "..") {
			continue
		}
		crt, err1 := os.ReadFile(filepath.Join(dir, name+".crt"))
		key, err2 := os.ReadFile(filepath.Join(dir, name+".key"))
		if err1 != nil || err2 != nil || len(crt) == 0 || len(crt) > 1<<20 || len(key) == 0 || len(key) > 1<<20 {
			continue
		}
		out[name] = proxyCertBackup{Crt: string(crt), Key: string(key)}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// settingsSnapshot/portsSnapshot 内存回落值(文件缺失时用)。
func settingsSnapshot() Settings {
	mu.Lock()
	defer mu.Unlock()
	return settings
}

func portsSnapshot() map[string]any {
	mu.Lock()
	defer mu.Unlock()
	ign := []int{}
	for p := range ignoredPorts {
		ign = append(ign, p)
	}
	sort.Ints(ign)
	return map[string]any{"ports": ports, "ignored": ign, "ranges": portRanges, "ignoredRanges": ignoredRanges}
}

// ---------- 数据备份 ----------

type dataManifest struct {
	Format    int    `json:"format"`
	App       string `json:"app"`
	CreatedAt int64  `json:"createdAt"`
	Kind      string `json:"kind"` // "data"
}

// buildDataBackup 打包 zip: 清单文件 + 事件 + 账本(缺失的文件跳过, 不中断)。
func buildDataBackup() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	addFile := func(name string, data []byte) {
		w, err := zw.Create(name)
		if err != nil {
			return
		}
		w.Write(data)
	}
	man, _ := json.Marshal(dataManifest{Format: backupFormat, App: appVersion, CreatedAt: time.Now().Unix(), Kind: "data"})
	addFile("backup.json", man)
	for _, f := range []struct{ disk, zip string }{
		{bansFile, "bans.json"}, {statsFile, "stats.json"},
		{ledgerTotalFile, "ledger-total.json"}, {ledgerGenFile, "ledger-gen.json"},
	} {
		if f.disk == "" {
			continue
		}
		if b, err := os.ReadFile(f.disk); err == nil {
			addFile(f.zip, b)
		}
	}
	for _, dir := range []struct {
		disk, prefix string
	}{{eventsDir, "events/"}, {eventsSrcDir, "events-src/"}, {ledgerDayDir, "ledger/"}} {
		if dir.disk == "" {
			continue
		}
		entries, err := os.ReadDir(dir.disk)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if dir.prefix == "ledger/" {
				if !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
			} else if !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(dir.disk, e.Name())); err == nil {
				addFile(dir.prefix+e.Name(), b)
			}
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------- 恢复 ----------

// checkBackupVersion 比对备份版本, 返回警告(空 = 无警告)。
func checkBackupVersion(format int, app string) []string {
	var warns []string
	if format != backupFormat {
		warns = append(warns, fmt.Sprintf("备份格式版本为 %d, 当前为 %d, 可能不完全兼容", format, backupFormat))
	}
	if app != appVersion {
		warns = append(warns, fmt.Sprintf("备份来自版本 %s, 当前版本为 %s", app, appVersion))
	}
	return warns
}

func restoreSettings(data []byte, confirm bool) (needConfirm bool, warns []string, err error) {
	var env settingsBackup
	if err := json.Unmarshal(data, &env); err != nil {
		return false, nil, fmt.Errorf("设置备份文件无法解析")
	}
	if env.Kind != "" && env.Kind != "settings" {
		return false, nil, fmt.Errorf("这不是设置备份文件")
	}
	if len(env.Settings) == 0 {
		// 裸 settings.json(非信封)误传进来时绝不能当成"空配置"恢复(会清空),
		// 直接拒绝, 让用户传真正的设置备份文件。
		return false, nil, fmt.Errorf("不是设置备份文件(缺少 settings 内容)")
	}
	warns = checkBackupVersion(env.Format, env.App)
	if len(warns) > 0 && !confirm {
		return true, warns, nil
	}
	// 快照先行
	if snap, err := buildSettingsBackup(); err == nil {
		os.WriteFile(nextSnapshotPath("settings", ".json"), snap, 0644)
		pruneSnapshots("settings", ".json")
	}
	// 设置: 在默认值上解码(新键补默认、未知键忽略)
	ns := defaultSettings()
	if len(env.Settings) > 0 {
		if err := json.Unmarshal(env.Settings, &ns); err != nil {
			return false, nil, fmt.Errorf("设置内容无法解析: %v", err)
		}
	}
	if ns.TrustedIPs == nil {
		ns.TrustedIPs = []string{}
	}
	var wrap struct {
		Ports         []*PortWatch `json:"ports"`
		Ignored       []int        `json:"ignored"`
		Ranges        []*PortRange `json:"ranges"`
		IgnoredRanges []PortRange  `json:"ignoredRanges"`
	}
	if len(env.Ports) > 0 {
		if err := json.Unmarshal(env.Ports, &wrap); err != nil {
			return false, nil, fmt.Errorf("端口内容无法解析: %v", err)
		}
	}
	mu.Lock()
	settings = ns
	ports = wrap.Ports
	if ports == nil {
		ports = []*PortWatch{}
	}
	ignoredPorts = map[int]bool{}
	for _, p := range wrap.Ignored {
		ignoredPorts[p] = true
	}
	portRanges = wrap.Ranges
	if portRanges == nil {
		portRanges = []*PortRange{}
	}
	ignoredRanges = wrap.IgnoredRanges
	if ignoredRanges == nil {
		ignoredRanges = []PortRange{}
	}
	saveSettings()
	savePorts()
	mu.Unlock()
	// 蜜罐配置: 备份里有才恢复(没有则不动), 恢复后按启动语义重起监听
	if len(env.Honeypot) > 0 {
		var hp HoneypotConfig
		if json.Unmarshal(env.Honeypot, &hp) == nil {
			if hp.HitThreshold < 1 {
				hp.HitThreshold = 1
			}
			if hp.BanHours < 1 {
				hp.BanHours = 24
			}
			honeypotStopAll()
			honeypotMu.Lock()
			honeypotCfg = hp
			saveHoneypot()
			honeypotMu.Unlock()
			honeypotStartAll()
		}
	}
	// 反代配置: 备份里有才恢复(没有则不动); 先写回上传证书, 再写 proxy.json,
	// 最后重载并重起监听(监听端口被占只记错误, 不中断恢复)。
	if len(env.Proxy) > 0 && proxyFile != "" {
		var pc ProxyConfig
		if err := json.Unmarshal(env.Proxy, &pc); err != nil {
			return false, nil, fmt.Errorf("反代内容无法解析: %v", err)
		}
		if pc.Rules == nil {
			pc.Rules = []*ProxyRule{}
		}
		certDir := filepath.Join(dataDir, "certs")
		for name, pair := range env.ProxyCerts {
			if !proxyCertNameRe.MatchString(name) || strings.Contains(name, "..") {
				continue
			}
			if pair.Crt == "" || pair.Key == "" || len(pair.Crt) > 1<<20 || len(pair.Key) > 1<<20 {
				continue
			}
			os.MkdirAll(certDir, 0755)
			os.WriteFile(filepath.Join(certDir, name+".crt"), []byte(pair.Crt), 0644)
			os.WriteFile(filepath.Join(certDir, name+".key"), []byte(pair.Key), 0600)
		}
		norm, err := json.Marshal(pc)
		if err != nil {
			return false, nil, fmt.Errorf("反代内容无法保存: %v", err)
		}
		if err := os.WriteFile(proxyFile, norm, 0644); err != nil {
			return false, nil, fmt.Errorf("反代内容无法保存: %v", err)
		}
		loadProxy()
		proxyApply()
		proxyProbeAll()
	}
	return false, warns, nil
}

// restoreData 解压并替换数据文件, 随后重读内存并重做 nft 对账。
// 只替换 zip 里出现的文件(缺失的条目不动当前文件, 不删数据)。
// zip 条目严格白名单(防 zip-slip: 拒绝 .. 与绝对路径)。
func restoreData(data []byte, confirm bool) (needConfirm bool, warns []string, err error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false, nil, fmt.Errorf("数据备份文件无法解压")
	}
	files := map[string][]byte{}
	var man dataManifest
	for _, f := range zr.File {
		name := f.Name
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
			return false, nil, fmt.Errorf("备份中含非法路径条目 %q, 已拒绝", name)
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		files[name] = b
		if name == "backup.json" {
			json.Unmarshal(b, &man)
		}
	}
	if man.Kind != "" && man.Kind != "data" {
		return false, nil, fmt.Errorf("这不是数据备份文件")
	}
	warns = checkBackupVersion(man.Format, man.App)
	if len(warns) > 0 && !confirm {
		return true, warns, nil
	}
	// 快照先行
	if snap, err := buildDataBackup(); err == nil {
		os.WriteFile(nextSnapshotPath("data", ".zip"), snap, 0644)
		pruneSnapshots("data", ".zip")
	}
	writeIfPresent := func(disk, zipName string) {
		if disk == "" {
			return
		}
		if b, ok := files[zipName]; ok {
			os.WriteFile(disk, b, 0644)
		}
	}
	writeIfPresent(bansFile, "bans.json")
	writeIfPresent(statsFile, "stats.json")
	writeIfPresent(ledgerTotalFile, "ledger-total.json")
	writeIfPresent(ledgerGenFile, "ledger-gen.json")
	// 事件目录: 先清空再写回(恢复 = 该目录以备份为准)
	for _, dir := range []struct {
		disk, prefix string
	}{{eventsDir, "events/"}, {eventsSrcDir, "events-src/"}} {
		if dir.disk == "" {
			continue
		}
		hasAny := false
		for name := range files {
			if strings.HasPrefix(name, dir.prefix) {
				hasAny = true
				break
			}
		}
		if !hasAny {
			continue // 备份里没这个目录的条目: 不动当前目录
		}
		os.MkdirAll(dir.disk, 0755)
		if entries, err := os.ReadDir(dir.disk); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					os.Remove(filepath.Join(dir.disk, e.Name()))
				}
			}
		}
		for name, b := range files {
			if !strings.HasPrefix(name, dir.prefix) {
				continue
			}
			base := strings.TrimPrefix(name, dir.prefix)
			if base == "" || strings.Contains(base, "/") || strings.Contains(base, "\\") {
				continue
			}
			os.WriteFile(filepath.Join(dir.disk, base), b, 0644)
		}
	}
	// 账本每日明细: 同样先清后写(只处理 ledger/ 前缀的 .json)
	hasLedgerDay := false
	for name := range files {
		if strings.HasPrefix(name, "ledger/") {
			hasLedgerDay = true
			break
		}
	}
	if hasLedgerDay && ledgerDayDir != "" {
		os.MkdirAll(ledgerDayDir, 0755)
		if entries, err := os.ReadDir(ledgerDayDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
					os.Remove(filepath.Join(ledgerDayDir, e.Name()))
				}
			}
		}
		for name, b := range files {
			if !strings.HasPrefix(name, "ledger/") || !strings.HasSuffix(name, ".json") {
				continue
			}
			base := strings.TrimPrefix(name, "ledger/")
			if base == "" || strings.Contains(base, "/") || strings.Contains(base, "\\") {
				continue
			}
			os.WriteFile(filepath.Join(ledgerDayDir, base), b, 0644)
		}
	}
	// 重读内存
	banMu.Lock()
	loadBans()
	banMu.Unlock()
	statsMu.Lock()
	loadStats()
	statsMu.Unlock()
	ledgerReload()
	// 立即重做 nft 对账: 记录和内核封禁一致
	if !dryBan {
		ensureSetAndRule()
		reconcileBans()
	}
	return false, warns, nil
}

// ---------- HTTP ----------

func backupDownloadName(kind string) string {
	return "guijia-" + kind + "-" + time.Now().Format("20060102-150405") +
		map[string]string{"settings": ".json", "data": ".zip"}[kind]
}

func handleBackupSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", 405)
		return
	}
	b, err := buildSettingsBackup()
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="+backupDownloadName("settings"))
	w.Write(b)
}

func handleBackupData(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", 405)
		return
	}
	b, err := buildDataBackup()
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+backupDownloadName("data"))
	w.Write(b)
}

func readRestoreFile(r *http.Request) ([]byte, bool, error) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return nil, false, fmt.Errorf("上传解析失败")
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		return nil, false, fmt.Errorf("未收到文件")
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, false, fmt.Errorf("文件读取失败")
	}
	confirm := r.FormValue("confirm") == "1" || r.URL.Query().Get("confirm") == "1"
	return b, confirm, nil
}

func handleBackupRestoreSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	b, confirm, err := readRestoreFile(r)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	needConfirm, warns, err := restoreSettings(b, confirm)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	if needConfirm {
		writeJSON(w, 200, map[string]any{"needConfirm": true, "warnings": warns})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "warnings": warns})
}

func handleBackupRestoreData(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	b, confirm, err := readRestoreFile(r)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	needConfirm, warns, err := restoreData(b, confirm)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	if needConfirm {
		writeJSON(w, 200, map[string]any{"needConfirm": true, "warnings": warns})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "warnings": warns})
}
