package main

// 面板升级: GitHub releases 检测 → 面板提示 → 点一下升级 → 失败自动回滚;
// 多机时主服务器可把升级推给节点(走已有命令通道, 节点侧同样验签+备份+健康检查+失败回滚)。
// - 只升二进制, 不动 guijia.service(单元变更走一键安装脚本重跑)。
// - 升级只在用户点确认后执行, 不做深夜全自动重启。
// - 安全门: 资产逐一验 SHA256SUMS(不过不装); 目标版必须高于当前版(防回滚攻击);
//   升级前备份当前二进制, 替换前先起看门狗(旧版代码), 看门狗验健康, 不过自动还原并重启。
// - 真实 GitHub releases 尚不存在时, 检测与下载走 GUIJIA_UPGRADE_API_BASE 覆盖的地址
//   (仅测试/排障用); 默认就是 api.github.com, 不拼假地址。
// - 资产命名与一键安装脚本同一套: guijia-linux-arm64 / guijia-linux-amd64 / SHA256SUMS。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const upgradeRepo = "pal537/GuiJia"

// ---------- 版本比较 ----------

type parsedVersion struct {
	nums []int
	pre  string
}

func parseVersion(v string) (parsedVersion, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return parsedVersion{}, errors.New("版本号为空")
	}
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i] // 构建元数据不参与比较
	}
	pre := ""
	if i := strings.Index(v, "-"); i >= 0 {
		pre, v = v[i+1:], v[:i]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		if p == "" {
			return parsedVersion{}, errors.New("版本号段为空")
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return parsedVersion{}, fmt.Errorf("版本号段无效: %q", p)
		}
		nums[i] = n
	}
	return parsedVersion{nums: nums, pre: pre}, nil
}

// compareVersions: -1/0/1; 数字段缺位按 0 计(1.0 == 1.0.0); 预发布版低于正式版。
func compareVersions(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	n := len(pa.nums)
	if len(pb.nums) > n {
		n = len(pb.nums)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa.nums) {
			x = pa.nums[i]
		}
		if i < len(pb.nums) {
			y = pb.nums[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	if pa.pre == pb.pre {
		return 0, nil
	}
	if pa.pre == "" {
		return 1, nil
	}
	if pb.pre == "" {
		return -1, nil
	}
	if pa.pre < pb.pre {
		return -1, nil
	}
	return 1, nil
}

func isNewerVersion(cur, latest string) bool {
	c, err := compareVersions(cur, latest)
	return err == nil && c < 0
}

// normalizeUpgradeTag: 钉版本归一化("1.0"→"v1.0", "v1.0"→"v1.0"), 空=latest。
func normalizeUpgradeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" || tag == "latest" {
		return ""
	}
	return "v" + strings.TrimPrefix(tag, "v")
}

// ---------- release 查询与下载 ----------

func upgradeAPIBase() string {
	if v := os.Getenv("GUIJIA_UPGRADE_API_BASE"); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	return "https://api.github.com/repos/" + upgradeRepo + "/releases"
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	HTMLURL string    `json:"html_url"`
	Assets  []ghAsset `json:"assets"`
}

var upgradeHTTPClient = &http.Client{Timeout: 60 * time.Second}

// fetchRelease: tag 为空取 latest, 否则取指定 tag 的 release。
func fetchRelease(tag string) (*ghRelease, error) {
	url := upgradeAPIBase() + "/latest"
	if t := normalizeUpgradeTag(tag); t != "" {
		url = upgradeAPIBase() + "/tags/" + t
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "guijia-upgrade")
	resp, err := upgradeHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("查询 release 失败: HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("release 未带 tag")
	}
	return &rel, nil
}

func upgradeAssetName() string { return "guijia-linux-" + runtime.GOARCH }

func (rel *ghRelease) assetURL(name string) string {
	for _, a := range rel.Assets {
		if a.Name == name {
			return a.URL
		}
	}
	return ""
}

func downloadUpgradeFile(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "guijia-upgrade")
	resp, err := upgradeHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// verifyUpgradeSHA: 按 SHA256SUMS 内容比对 name 对应行的期望值(不过不装)。
func verifyUpgradeSHA(data []byte, sums []byte, name string) error {
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if strings.TrimPrefix(f[1], "*") == name {
			want = f[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("SHA256SUMS 里没有 %s", name)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(want) {
		return fmt.Errorf("%s 校验失败", name)
	}
	return nil
}

// ---------- 状态与标记 ----------

type upgradeStatus struct {
	State      string `json:"state"` // idle|applying|done|failed
	Current    string `json:"current"`
	Target     string `json:"target"`
	Error      string `json:"error,omitempty"`
	ReleaseURL string `json:"releaseUrl,omitempty"`
	CheckedAt  int64  `json:"checkedAt"`
	UpdatedAt  int64  `json:"updatedAt"`
}

var upgradeMu sync.Mutex

func upgradeStatusPath() string { return filepath.Join(dataDir, "upgrade-status.json") }
func upgradeMarkerPath() string { return filepath.Join(dataDir, "upgrade-marker.json") }
func upgradeBackupDir() string  { return filepath.Join(dataDir, "upgrade-backup") }

func loadUpgradeStatusFrom(path string) upgradeStatus {
	st := upgradeStatus{State: "idle", Current: appVersion}
	if b, err := os.ReadFile(path); err == nil {
		var s upgradeStatus
		if json.Unmarshal(b, &s) == nil && s.State != "" {
			st = s
		}
	}
	st.Current = appVersion // 当前版永远以运行中二进制为准, 不信旧文件
	return st
}

func loadUpgradeStatus() upgradeStatus {
	return loadUpgradeStatusFrom(upgradeStatusPath())
}

func saveUpgradeStatusTo(path string, st upgradeStatus) {
	st.UpdatedAt = time.Now().Unix()
	b, _ := json.Marshal(st)
	os.WriteFile(path, b, 0644)
}

func saveUpgradeStatus(st upgradeStatus) {
	saveUpgradeStatusTo(upgradeStatusPath(), st)
}

func setUpgradeStatus(state, target, errMsg, releaseURL string) {
	upgradeMu.Lock()
	defer upgradeMu.Unlock()
	st := loadUpgradeStatus()
	st.State = state
	if target != "" {
		st.Target = target
	}
	st.Error = errMsg
	if releaseURL != "" {
		st.ReleaseURL = releaseURL
	}
	saveUpgradeStatus(st)
}

// setUpgradeStatusAt: 看门狗专用, 状态写到指定路径(不依赖全局 dataDir)。
// 原因: 看门狗由 systemd 瞬时 service 启动时环境是干净的, GUIJIA_DATA_DIR 会丢,
// 若按 dataDir 写, 状态会落到默认目录、面板永远读不到(实测抓到的真 bug)。
// marker 本身就在面板数据目录里, 故状态写 marker 同目录最可靠。
func setUpgradeStatusAt(path, state, target, errMsg, releaseURL string) {
	upgradeMu.Lock()
	defer upgradeMu.Unlock()
	st := loadUpgradeStatusFrom(path)
	st.State = state
	if target != "" {
		st.Target = target
	}
	st.Error = errMsg
	if releaseURL != "" {
		st.ReleaseURL = releaseURL
	}
	saveUpgradeStatusTo(path, st)
}

type upgradeMarker struct {
	Target     string `json:"target"`
	From       string `json:"from"`
	Backup     string `json:"backup"`
	Port       int    `json:"port"`
	TimeoutSec int    `json:"timeoutSec"`
	StartedAt  int64  `json:"startedAt"`
	// Exe: 升级时面板的真实可执行文件路径。看门狗跑在副本里, 其 os.Executable()
	// 是副本路径, 回滚重启必须起这条真实路径(且补齐数据目录与端口环境),
	// 否则面板会跑在随后自删的副本上, 下次升级读不到二进制。
	Exe string `json:"exe"`
}

// upgradeWatchTimeoutSec: 看门狗等待新版健康的上限(默认 60 秒;
// GUIJIA_UPGRADE_WATCH_TIMEOUT 仅测试/排障覆盖)。
func upgradeWatchTimeoutSec() int {
	if v := os.Getenv("GUIJIA_UPGRADE_WATCH_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 && n <= 600 {
			return n
		}
	}
	return 60
}

// ---------- 可执行文件、重启、看门狗起停 ----------

var upgradeExePathOverride = "" // 测试覆盖可执行文件路径

func upgradeExePath() string {
	if upgradeExePathOverride != "" {
		return upgradeExePathOverride
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

// upgradeHasServiceUnit: 本机是否有 guijia systemd 单元(有才走 systemctl,
// 否则走自身重执行; 容器/手动运行/实测环境都没有单元, 不能硬走 systemctl)。
func upgradeHasServiceUnit() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "cat", "guijia").Run() == nil
}

// upgradeRestartFunc: 触发重启(默认有单元走 systemctl, 否则自身重执行; 测试可拦截)。
// systemd 模式下命令返回即由服务管理器接管; 重执行模式下成功不再返回。
var upgradeRestartFunc = func() error {
	if upgradeHasServiceUnit() {
		return exec.Command("systemctl", "restart", "guijia").Run()
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}

// upgradeSpawnWatcherFunc: 在替换二进制之前起看门狗(默认 systemd-run 瞬时 service,
// 无 systemd 时 setsid 脱离; 测试可拦截)。看门狗必须从数据目录里的稳定副本启动,
// 绝不能直接用运行中的二进制路径: systemd-run service 的启动是异步的,
// systemd-run 返回时 service 还没 exec, 而 apply 紧接着就会把新文件 rename 到原路径,
// service 实际 exec 到的是新文件——回滚场景下那是秒退的坏包脚本, 看门狗根本没跑起来
// (实测: service 启动与停用在同一秒, 面板死后无人回滚、状态永远 applying)。
// setsid 路径同样有 fork/exec 与 rename 的竞态, 故两路都起副本。
// 副本由看门狗退出时自删(见 cliUpgradeWatch); 起失败则当场删副本不留垃圾;
// 面板启动时顺带清理 24 小时以上的残留副本(被杀掉的看门狗留下的)。
var upgradeSpawnWatcherFunc = func(markerPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(upgradeBackupDir(), 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	copyPath := filepath.Join(upgradeBackupDir(), fmt.Sprintf("guijia-watch-copy-%d", time.Now().UnixNano()))
	if err := os.WriteFile(copyPath, data, 0755); err != nil {
		return err
	}
	spawnOK := false
	defer func() {
		if !spawnOK {
			os.Remove(copyPath)
		}
	}()
	if _, err := exec.LookPath("systemd-run"); err == nil {
		unit := fmt.Sprintf("guijia-watch-%d", time.Now().UnixNano())
		// 必须用 systemd-run 瞬时 service(独立单元, 主服务重启/重执行都牵连不到),
		// 绝不能用 --scope: 实测 systemd 255 上 --scope 即使加 --no-block 也会等
		// 命令结束才返回, 导致 apply 卡在 spawn 里、看门狗等不到重启先超时,
		// 写下假的"已回滚"状态, 而 apply 随后又真的升级成功(状态与事实相反)。
		// 瞬时 service 实测立即返回(0.05 秒), 服务独立运行, 退出后单元自动清理。
		cmd := exec.Command("systemd-run", "--unit="+unit, copyPath, "upgrade-watch", markerPath)
		if out, err := cmd.CombinedOutput(); err == nil {
			spawnOK = true
			return nil
		} else {
			fmt.Fprintln(os.Stderr, "systemd-run watch failed, fallback setsid:", strings.TrimSpace(string(out)))
		}
	}
	cmd := exec.Command(copyPath, "upgrade-watch", markerPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return err
	}
	spawnOK = true
	return nil
}

var upgradeProbeInterval = 2 * time.Second

// upgradeProbeVersionFunc: 探面板版本(默认调本机 node/status, 公开接口, 双模式通用)。
var upgradeProbeVersionFunc = func(port int) (string, error) {
	cli := &http.Client{Timeout: 5 * time.Second}
	for _, p := range []string{"/api/node/status", "/api/version"} {
		resp, err := cli.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, p))
		if err != nil {
			continue
		}
		var d struct {
			Version string `json:"version"`
		}
		derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d)
		resp.Body.Close()
		if derr == nil && d.Version != "" {
			return d.Version, nil
		}
	}
	return "", errors.New("面板版本探针失败")
}

// restoreUpgradeBackup: 把备份拷回可执行文件路径(同目录临时文件 + 改名)。
func restoreUpgradeBackup(backup, exe string) error {
	if exe == "" {
		return errors.New("可执行文件路径未知")
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	tmp := exe + ".rollback-tmp"
	if err := os.WriteFile(tmp, data, 0755); err != nil {
		return err
	}
	return os.Rename(tmp, exe)
}

func pruneUpgradeBackups(keep int) {
	ents, err := os.ReadDir(upgradeBackupDir())
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "guijia-") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		os.Remove(filepath.Join(upgradeBackupDir(), names[0]))
		names = names[1:]
	}
}

// watcherRestoreTarget: 回滚还原的目标路径。看门狗跑在副本里, 其自身的
// os.Executable() 是副本路径, 绝不能往副本上还原——必须还原到 marker 里记的
// 真实面板路径(现行 apply 必写 Exe; 旧 marker 无 Exe 时回落自身路径兼容)。
func watcherRestoreTarget(mk upgradeMarker) string {
	if mk.Exe != "" {
		return mk.Exe
	}
	return upgradeExePath()
}

// runUpgradeWatcher: 看门狗主逻辑(探针与重启均可注入, 便于单测)。
// marker 消失 = 另有人已处理, 静默退出; 探到目标版 = 成功; 超时 = 还原备份+重启+记失败。
// 状态一律写 marker 同目录(不走全局 dataDir): systemd 瞬时 service 环境干净,
// GUIJIA_DATA_DIR 会丢, 按 dataDir 写会落到默认目录、面板永远读不到。
func runUpgradeWatcher(markerPath string, probe func(int) (string, error), restart func(upgradeMarker) error) int {
	b, err := os.ReadFile(markerPath)
	if err != nil {
		return 2
	}
	var mk upgradeMarker
	if json.Unmarshal(b, &mk) != nil || mk.Target == "" || mk.Backup == "" || mk.Port <= 0 {
		return 2
	}
	statusPath := filepath.Join(filepath.Dir(markerPath), "upgrade-status.json")
	timeout := mk.TimeoutSec
	if timeout <= 0 {
		timeout = 60
	}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(markerPath); err != nil {
			return 0 // marker 已被他人处理(成功/回滚), 静默退出
		}
		// 版本比较必须归一化: 探到的是二进制里的 "0.2", 标记里是 release 的 "v0.2",
		// 直接 == 永远对不上, 成功升级也会被误判回滚(实测证实)。
		if v, err := probe(mk.Port); err == nil {
			if c, cerr := compareVersions(v, mk.Target); cerr == nil && c == 0 {
				setUpgradeStatusAt(statusPath, "done", mk.Target, "", "")
				os.Remove(markerPath)
				return 0
			}
		}
		time.Sleep(upgradeProbeInterval)
	}
	if err := restoreUpgradeBackup(mk.Backup, watcherRestoreTarget(mk)); err != nil {
		setUpgradeStatusAt(statusPath, "failed", mk.Target, "回滚失败: "+err.Error(), "")
		os.Remove(markerPath)
		return 1
	}
	if restart != nil {
		_ = restart(mk) // 重启失败也继续: 状态已记失败, 面板靠手动重启恢复
	}
	setUpgradeStatusAt(statusPath, "failed", mk.Target, "升级后 "+strconv.Itoa(timeout)+" 秒内未检测到新版本, 已回滚到 "+mk.From, "")
	os.Remove(markerPath)
	return 1
}

func cliUpgradeWatch(markerPath string) int {
	if markerPath == "" {
		markerPath = upgradeMarkerPath()
	}
	code := runUpgradeWatcher(markerPath, upgradeProbeVersionFunc, func(mk upgradeMarker) error {
		if upgradeHasServiceUnit() {
			return exec.Command("systemctl", "restart", "guijia").Run()
		}
		exe := mk.Exe
		if exe == "" {
			// 旧 marker 无 Exe 字段时回落自身路径(仅兼容, 现行 apply 必写 Exe)。
			var err error
			exe, err = os.Executable()
			if err != nil {
				return err
			}
		}
		// 看门狗不能 syscall.Exec(会带上 upgrade-watch 参数跑偏),
		// 必须起一个干净 argv 的新进程。systemd 瞬时 service 环境干净,
		// 必须显式补齐数据目录与端口, 否则面板会起在默认目录/默认端口上。
		dataDir := filepath.Dir(markerPath)
		if _, err := exec.LookPath("systemd-run"); err == nil {
			// 有 systemd 时必须再经 systemd-run 起独立 service: 看门狗 service
			// 退出时会清掉整个 cgroup, 直接 setsid 起的面板在同一 cgroup 里会被
			// 连坐杀掉(实测: 回滚后看门狗正常收尾, 但重启的面板始终没起来)。
			args := []string{"--unit=" + fmt.Sprintf("guijia-panel-%d", time.Now().UnixNano())}
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "GUIJIA_") {
					continue
				}
				if strings.HasPrefix(kv, "GUIJIA_DATA_DIR=") || strings.HasPrefix(kv, "GUIJIA_PORT=") {
					continue // 下面显式补, 避免重复
				}
				args = append(args, "--setenv="+kv)
			}
			args = append(args,
				"--setenv=GUIJIA_DATA_DIR="+dataDir,
				"--setenv=GUIJIA_PORT="+strconv.Itoa(mk.Port),
				exe)
			return exec.Command("systemd-run", args...).Run()
		}
		// 无 systemd: setsid 直起, 看门狗退出后孤儿进程继续跑, 不会被连坐。
		cmd := exec.Command(exe)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
		env := os.Environ()
		filtered := env[:0]
		for _, kv := range env {
			if strings.HasPrefix(kv, "GUIJIA_DATA_DIR=") || strings.HasPrefix(kv, "GUIJIA_PORT=") {
				continue
			}
			filtered = append(filtered, kv)
		}
		cmd.Env = append(filtered,
			"GUIJIA_DATA_DIR="+dataDir,
			"GUIJIA_PORT="+strconv.Itoa(mk.Port))
		return cmd.Start()
	})
	// 退出时自删看门狗副本(仅当自身就是副本时; 手动跑 guijia upgrade-watch 时
	// 自身是真二进制, 绝不能删)。
	if exe, err := os.Executable(); err == nil && strings.Contains(exe, "guijia-watch-copy-") {
		os.Remove(exe)
	}
	return code
}

// upgradeReconcileOnStart: 启动时收尾上次升级留下的 marker。
// marker 新鲜(看门狗可能还活着)不动; 陈旧(看门狗已死)则按当前版定 done/failed 并删 marker。
// 顺带清理 24 小时以上的看门狗残留副本(被杀掉的看门狗留下的); 现行看门狗最长存活
// 约超时+重启余量(默认 60 秒级), 24 小时阈值绝不会误删活着的看门狗副本。
func upgradeReconcileOnStart() {
	if names, err := os.ReadDir(upgradeBackupDir()); err == nil {
		for _, n := range names {
			if !strings.HasPrefix(n.Name(), "guijia-watch-copy-") {
				continue
			}
			if fi, err := n.Info(); err == nil && time.Since(fi.ModTime()) > 24*time.Hour {
				os.Remove(filepath.Join(upgradeBackupDir(), n.Name()))
			}
		}
	}
	b, err := os.ReadFile(upgradeMarkerPath())
	if err != nil {
		return
	}
	var mk upgradeMarker
	if json.Unmarshal(b, &mk) != nil || mk.Target == "" {
		os.Remove(upgradeMarkerPath())
		return
	}
	timeout := mk.TimeoutSec
	if timeout <= 0 {
		timeout = 60
	}
	if time.Now().Unix()-mk.StartedAt < int64(timeout)+30 {
		return
	}
	if appVersion == mk.Target {
		setUpgradeStatus("done", mk.Target, "", "")
	} else {
		setUpgradeStatus("failed", mk.Target, "升级后未检测到新版本(看门狗未收尾)", "")
	}
	os.Remove(upgradeMarkerPath())
}

// ---------- 升级主流程 ----------

// runUpgradeApply: 后台升级全流程(下载→验签→备份→起看门狗→替换→重启)。
// 替换前任何一步失败都不改系统; 替换后失败靠看门狗回滚(重执行失败时当场还原)。
func runUpgradeApply(target string) {
	cur := appVersion
	rel, err := fetchRelease(target)
	if err != nil {
		setUpgradeStatus("failed", target, "查询新版失败: "+err.Error(), "")
		return
	}
	latest := rel.TagName
	if !isNewerVersion(cur, latest) {
		setUpgradeStatus("failed", latest, "当前版本已是最新", rel.HTMLURL)
		return
	}
	asset := upgradeAssetName()
	assetURL := rel.assetURL(asset)
	sumsURL := rel.assetURL("SHA256SUMS")
	if assetURL == "" || sumsURL == "" {
		setUpgradeStatus("failed", latest, "新版缺少对应架构的安装包或校验文件", rel.HTMLURL)
		return
	}
	binData, err := downloadUpgradeFile(assetURL)
	if err != nil {
		setUpgradeStatus("failed", latest, "下载失败: "+err.Error(), rel.HTMLURL)
		return
	}
	sumsData, err := downloadUpgradeFile(sumsURL)
	if err != nil {
		setUpgradeStatus("failed", latest, "下载校验文件失败: "+err.Error(), rel.HTMLURL)
		return
	}
	if err := verifyUpgradeSHA(binData, sumsData, asset); err != nil {
		setUpgradeStatus("failed", latest, "校验失败, 未改动系统: "+err.Error(), rel.HTMLURL)
		return
	}
	exe := upgradeExePath()
	if exe == "" {
		setUpgradeStatus("failed", latest, "可执行文件路径未知", rel.HTMLURL)
		return
	}
	if err := os.MkdirAll(upgradeBackupDir(), 0755); err != nil {
		setUpgradeStatus("failed", latest, "备份目录创建失败: "+err.Error(), rel.HTMLURL)
		return
	}
	ts := time.Now().Format("20060102150405")
	backup := filepath.Join(upgradeBackupDir(), "guijia-"+cur+"-"+ts)
	oldData, err := os.ReadFile(exe)
	if err != nil {
		setUpgradeStatus("failed", latest, "读取当前二进制失败: "+err.Error(), rel.HTMLURL)
		return
	}
	if err := os.WriteFile(backup, oldData, 0755); err != nil {
		setUpgradeStatus("failed", latest, "备份失败: "+err.Error(), rel.HTMLURL)
		return
	}
	pruneUpgradeBackups(3)
	mk := upgradeMarker{Target: latest, From: cur, Backup: backup, Port: appPort(), TimeoutSec: upgradeWatchTimeoutSec(), StartedAt: time.Now().Unix(), Exe: upgradeExePath()}
	mb, _ := json.Marshal(mk)
	if err := os.WriteFile(upgradeMarkerPath(), mb, 0644); err != nil {
		setUpgradeStatus("failed", latest, "写升级标记失败: "+err.Error(), rel.HTMLURL)
		return
	}
	if err := upgradeSpawnWatcherFunc(upgradeMarkerPath()); err != nil {
		os.Remove(upgradeMarkerPath())
		setUpgradeStatus("failed", latest, "启动升级看门狗失败: "+err.Error(), rel.HTMLURL)
		return
	}
	tmp := exe + ".upgrade-tmp"
	if err := os.WriteFile(tmp, binData, 0755); err != nil {
		os.Remove(upgradeMarkerPath())
		setUpgradeStatus("failed", latest, "写新二进制失败: "+err.Error(), rel.HTMLURL)
		return
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		os.Remove(upgradeMarkerPath())
		setUpgradeStatus("failed", latest, "替换二进制失败: "+err.Error(), rel.HTMLURL)
		return
	}
	if err := upgradeRestartFunc(); err != nil {
		// 重执行失败 = 旧进程还在, 当场还原, 看门狗见 marker 消失会静默退出。
		_ = restoreUpgradeBackup(backup, exe)
		os.Remove(upgradeMarkerPath())
		setUpgradeStatus("failed", latest, "重启失败, 已回滚: "+err.Error(), rel.HTMLURL)
		return
	}
	// systemctl 模式: 进程即将被 SIGTERM, 状态保持 applying, 看门狗/启动自愈收尾。
}

// ---------- 接口 ----------

func handleUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	rel, err := fetchRelease("")
	if err != nil {
		errJSON(w, 502, "查询新版失败: "+err.Error())
		return
	}
	upgradeMu.Lock()
	st := loadUpgradeStatus()
	st.CheckedAt = time.Now().Unix()
	st.Target = rel.TagName
	st.ReleaseURL = rel.HTMLURL
	saveUpgradeStatus(st)
	upgradeMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"current":    appVersion,
		"latest":     rel.TagName,
		"hasUpdate":  isNewerVersion(appVersion, rel.TagName),
		"releaseUrl": rel.HTMLURL,
	})
}

func handleUpgradeApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	upgradeMu.Lock()
	st := loadUpgradeStatus()
	if st.State == "applying" {
		upgradeMu.Unlock()
		errJSON(w, 409, "正在升级中, 请稍候")
		return
	}
	if in.Version != "" {
		if _, err := parseVersion(in.Version); err != nil {
			upgradeMu.Unlock()
			errJSON(w, 400, "版本号无效")
			return
		}
	}
	st.State = "applying"
	st.Target = in.Version
	st.Error = ""
	saveUpgradeStatus(st)
	upgradeMu.Unlock()
	go runUpgradeApply(in.Version)
	writeJSON(w, 200, map[string]any{"ok": true, "state": "applying", "target": in.Version})
}

func handleUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	writeJSON(w, 200, loadUpgradeStatus())
}

// ---------- 推送升级状态跟踪(第 1 项) ----------
// handleNodeUpgradeAll 只回“已开始升级”就结束, 面板此前再无下文。
// 这里记下每台被推节点的推送任务, 后台每 10 秒刷新一次(与节点升级状态
// 对照), 前端轮询 GET /api/nodes/upgrade-push-status 逐节点推进状态线:
// 升级中 -> 升级成功(版本已到目标)/已是最新/升级失败: 原因。
// 任务只存内存: 主服务器重启即清空, 前端轮询到空即停, 不编造旧状态。

type pushJob struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	FromVersion string `json:"fromVersion"`
	Target      string `json:"target"`
	StartedAt   int64  `json:"startedAt"`
	State       string `json:"state"` // upgrading | done | failed
	Detail      string `json:"detail"`
	Version     string `json:"version"` // 完成时节点版本
	evaluating  bool
}

var (
	pushMu   sync.Mutex
	pushJobs = map[string]*pushJob{}
	pushLoop bool
)

// pushGraceSec 节点重启宽限: 推送后 2 分钟内离线只算“重启中”, 不算失败。
const pushGraceSec = 120

// pushTimeoutSec 推送超时: 5 分钟未到目标版即判失败。
const pushTimeoutSec = 300

// nodePushUpgrading 该节点是否有进行中的推送升级任务(重启窗口内,
// 供代理报错文案区分“可能正在重启”, 第 4 项)。
func nodePushUpgrading(fp string) bool {
	pushMu.Lock()
	defer pushMu.Unlock()
	j := pushJobs[fp]
	return j != nil && j.State == "upgrading"
}

func pushJobPublic(j *pushJob) map[string]any {
	return map[string]any{
		"fingerprint": j.Fingerprint, "name": j.Name, "state": j.State,
		"detail": j.Detail, "version": j.Version, "target": j.Target,
	}
}

func handleNodeUpgradePushStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errJSON(w, 405, "method")
		return
	}
	pushMu.Lock()
	defer pushMu.Unlock()
	out := []map[string]any{}
	for _, j := range pushJobs {
		out = append(out, pushJobPublic(j))
	}
	writeJSON(w, 200, map[string]any{"jobs": out})
}

// seedPushJob 推送成功发出后记任务(调用方须已确认节点在线)。
func seedPushJob(fp, name, fromVersion, target string) {
	pushMu.Lock()
	pushJobs[fp] = &pushJob{
		Fingerprint: fp, Name: name, FromVersion: fromVersion, Target: target,
		StartedAt: time.Now().Unix(), State: "upgrading", Detail: "升级中…",
	}
	needLoop := !pushLoop
	if needLoop {
		pushLoop = true
	}
	pushMu.Unlock()
	if needLoop {
		go pushRefreshLoop()
	}
}

// evalPushJob 纯判定(供测试): 按注册表版本、节点升级状态文件、在线与耗时
// 判定任务状态。proxyState: 节点 api/upgrade/status 的 state(""=没拿到);
// proxyUpdatedAt: 该状态文件的 UpdatedAt; online: 注册表是否在线。
func evalPushJob(j *pushJob, nodeVersion string, nodeGone bool, online bool, proxyState string, proxyUpdatedAt int64, proxyErr string, now int64) (state, detail string) {
	elapsed := now - j.StartedAt
	if nodeGone {
		return "failed", "节点已移除"
	}
	if nodeVersion != "" && nodeVersion != j.FromVersion {
		return "done", "升级成功：" + nodeVersion
	}
	if proxyState == "done" && proxyUpdatedAt >= j.StartedAt {
		return "done", "升级成功"
	}
	if proxyState == "failed" && proxyUpdatedAt >= j.StartedAt {
		if strings.Contains(proxyErr, "已是最新") {
			return "done", "已是最新"
		}
		if proxyErr != "" {
			return "failed", "升级失败：" + proxyErr
		}
		return "failed", "升级失败"
	}
	if proxyState == "applying" {
		return "upgrading", "升级中…"
	}
	if !online {
		if elapsed < pushGraceSec {
			return "upgrading", "升级中（节点重启中…）"
		}
		if elapsed >= pushTimeoutSec {
			return "failed", "升级失败：超时未完成"
		}
		return "upgrading", "升级中…"
	}
	if elapsed >= pushTimeoutSec {
		return "failed", "升级失败：超时未完成"
	}
	return "upgrading", "升级中…"
}

// refreshPushJobOnce 刷新单个任务(可能调节点代理, 慢; 调用方须是后台 goroutine)。
func refreshPushJobOnce(fp string) {
	pushMu.Lock()
	j := pushJobs[fp]
	if j == nil || j.State != "upgrading" || j.evaluating {
		pushMu.Unlock()
		return
	}
	j.evaluating = true
	pushMu.Unlock()
	defer func() {
		pushMu.Lock()
		if jj := pushJobs[fp]; jj != nil {
			jj.evaluating = false
		}
		pushMu.Unlock()
	}()
	hubMu.Lock()
	s := findHubServer(fp)
	var nodeVersion string
	var online bool
	nodeGone := s == nil
	if s != nil {
		nodeVersion = s.Version
		online = hubNodeOnline(s)
	}
	hubMu.Unlock()
	// 节点升级状态文件(经命令通道, 节点重启中拿不到属正常, 不算失败)。
	var proxyState, proxyErr string
	var proxyUpdatedAt int64
	if !nodeGone {
		if st, body, kind := hubCallNode(fp, "GET", "api/upgrade/status", nil); kind == "" && st >= 200 && st < 300 {
			var v struct {
				State     string `json:"state"`
				Error     string `json:"error"`
				UpdatedAt int64  `json:"updatedAt"`
			}
			if json.Unmarshal(body, &v) == nil {
				proxyState, proxyErr, proxyUpdatedAt = v.State, v.Error, v.UpdatedAt
			}
		}
	}
	pushMu.Lock()
	jj := pushJobs[fp]
	if jj == nil || jj.State != "upgrading" {
		pushMu.Unlock()
		return
	}
	state, detail := evalPushJob(jj, nodeVersion, nodeGone, online, proxyState, proxyUpdatedAt, proxyErr, time.Now().Unix())
	jj.State, jj.Detail = state, detail
	if state == "done" && nodeVersion != "" {
		jj.Version = nodeVersion
	}
	pushMu.Unlock()
}

// pushRefreshLoop 后台刷新: 只要还有 upgrading 任务就每 10 秒刷一轮,
// 全部终态后退出(下次推送再起)。
func pushRefreshLoop() {
	for {
		time.Sleep(10 * time.Second)
		pushMu.Lock()
		fps := []string{}
		anyUpgrading := false
		for fp, j := range pushJobs {
			if j.State == "upgrading" {
				fps = append(fps, fp)
				anyUpgrading = true
			}
		}
		if !anyUpgrading {
			pushLoop = false
			pushMu.Unlock()
			return
		}
		pushMu.Unlock()
		var wg sync.WaitGroup
		for _, fp := range fps {
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()
				refreshPushJobOnce(fp)
			}(fp)
		}
		wg.Wait()
	}
}

// handleNodeUpgradeAll: 主服务器点一下, 把升级推给全部在线节点(各自下载+验签+回滚)。
// 单节点失败只报该节点, 不影响其他节点与主服务器; 离线节点跳过。
func handleNodeUpgradeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errJSON(w, 405, "method")
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	body, _ := json.Marshal(map[string]string{"version": in.Version})
	hubMu.Lock()
	servers := append([]*hubServer{}, hubServers...)
	hubMu.Unlock()
	type res struct {
		Fingerprint string `json:"fingerprint"`
		Name        string `json:"name"`
		OK          bool   `json:"ok"`
		Detail      string `json:"detail"`
	}
	out := []res{}
	for _, s := range servers {
		if !hubNodeOnline(s) {
			out = append(out, res{s.Fingerprint, s.Name, false, "节点离线, 已跳过"})
			continue
		}
		status, respBody, errKind := hubCallNode(s.Fingerprint, "POST", "api/upgrade/apply", body)
		switch errKind {
		case "":
			var d struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(respBody, &d)
			if status >= 200 && status < 300 {
				out = append(out, res{s.Fingerprint, s.Name, true, "已开始升级"})
				// 记推送任务, 后台刷新状态线(第 1 项): 成功与否不再只凭这一句。
				seedPushJob(s.Fingerprint, s.Name, s.Version, in.Version)
			} else if d.Error != "" {
				out = append(out, res{s.Fingerprint, s.Name, false, d.Error})
			} else {
				out = append(out, res{s.Fingerprint, s.Name, false, fmt.Sprintf("节点返回 %d", status)})
			}
		case "notfound":
			out = append(out, res{s.Fingerprint, s.Name, false, "节点已不存在"})
		case "offline":
			out = append(out, res{s.Fingerprint, s.Name, false, "节点离线"})
		case "nochan":
			out = append(out, res{s.Fingerprint, s.Name, false, "节点未建立命令通道"})
		case "timeout":
			out = append(out, res{s.Fingerprint, s.Name, false, "节点响应超时"})
		default:
			out = append(out, res{s.Fingerprint, s.Name, false, errKind})
		}
	}
	writeJSON(w, 200, map[string]any{"results": out})
}
