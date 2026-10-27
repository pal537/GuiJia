package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupUpgradeTest: 升级测试基座(临时数据目录 + 假可执行文件 + 假看门狗/重启)。
func setupUpgradeTest(t *testing.T) (dir, exe string, spawned, restarted *bool) {
	t.Helper()
	dir = t.TempDir()
	oldDataDir, oldExeOverride := dataDir, upgradeExePathOverride
	oldSpawn, oldRestart := upgradeSpawnWatcherFunc, upgradeRestartFunc
	oldInterval := upgradeProbeInterval
	oldVersion := appVersion
	dataDir = dir
	exe = filepath.Join(dir, "guijia")
	os.WriteFile(exe, []byte("OLDBIN"), 0755)
	upgradeExePathOverride = exe
	spawned, restarted = new(bool), new(bool)
	upgradeSpawnWatcherFunc = func(string) error { *spawned = true; return nil }
	upgradeRestartFunc = func() error { *restarted = true; return nil }
	upgradeProbeInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		dataDir, upgradeExePathOverride = oldDataDir, oldExeOverride
		upgradeSpawnWatcherFunc, upgradeRestartFunc = oldSpawn, oldRestart
		upgradeProbeInterval = oldInterval
		appVersion = oldVersion
	})
	return dir, exe, spawned, restarted
}

// fakeUpgradeStation: 假 release 站(latest JSON + 资产 + SHA256SUMS)。
func fakeUpgradeStation(t *testing.T, tag string, bin []byte, tamper bool) *httptest.Server {
	t.Helper()
	asset := upgradeAssetName()
	sum := sha256.Sum256(bin)
	sums := hex.EncodeToString(sum[:]) + "  " + asset + "\n"
	if tamper {
		sums = strings.Repeat("0", 64) + "  " + asset + "\n"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		// browser_download_url 指向本站, 与真实 GitHub JSON 结构一致。
		base := "http://" + r.Host
		json.NewEncoder(w).Encode(map[string]any{
			"tag_name": tag,
			"html_url": base + "/releases/tag/" + tag,
			"assets": []map[string]string{
				{"name": asset, "browser_download_url": base + "/" + asset},
				{"name": "SHA256SUMS", "browser_download_url": base + "/SHA256SUMS"},
			},
		})
	})
	mux.HandleFunc("/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sums)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("GUIJIA_UPGRADE_API_BASE", srv.URL)
	return srv
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1", "0.2", -1},
		{"0.2", "0.1", 1},
		{"1.0", "1.0.0", 0},
		{"v1.10", "v1.9", 1},
		{"1.0-alpha", "1.0", -1},
		{"1.0", "1.0-alpha", 1},
		{"0.1", "0.1", 0},
		{"v0.1", "0.1", 0},
	}
	for _, c := range cases {
		got, err := compareVersions(c.a, c.b)
		if err != nil || got != c.want {
			t.Fatalf("compareVersions(%q,%q)=%d,%v, want %d", c.a, c.b, got, err, c.want)
		}
	}
	if _, err := compareVersions("0.1", "abc"); err == nil {
		t.Fatalf("非法版本号应报错")
	}
	if _, err := compareVersions("", "0.1"); err == nil {
		t.Fatalf("空版本号应报错")
	}
	if isNewerVersion("0.2", "0.1") {
		t.Fatalf("旧版不应判为更新")
	}
	if !isNewerVersion("0.1", "v0.2") {
		t.Fatalf("新版应判为更新")
	}
}

func TestVerifyUpgradeSHA(t *testing.T) {
	data := []byte("hello-upgrade")
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	asset := "guijia-linux-amd64"
	if err := verifyUpgradeSHA(data, []byte(hexSum+"  "+asset+"\n"), asset); err != nil {
		t.Fatalf("正常校验应过: %v", err)
	}
	if err := verifyUpgradeSHA(data, []byte(hexSum+" *"+asset+"\n"), asset); err != nil {
		t.Fatalf("* 形式校验应过: %v", err)
	}
	if err := verifyUpgradeSHA(data, []byte(strings.Repeat("0", 64)+"  "+asset+"\n"), asset); err == nil {
		t.Fatalf("篡改后校验应失败")
	}
	if err := verifyUpgradeSHA(data, []byte(hexSum+"  other\n"), asset); err == nil {
		t.Fatalf("缺条目应失败")
	}
}

func TestUpgradeCheckFakeStation(t *testing.T) {
	dir, _, _, _ := setupUpgradeTest(t)
	_ = dir
	fakeUpgradeStation(t, "v0.2", []byte("NEWBIN"), false)
	rel, err := fetchRelease("")
	if err != nil {
		t.Fatalf("fetchRelease 失败: %v", err)
	}
	if rel.TagName != "v0.2" {
		t.Fatalf("tag 应为 v0.2, 得到 %q", rel.TagName)
	}
	if rel.assetURL(upgradeAssetName()) == "" {
		t.Fatalf("应找到对应架构资产")
	}
	if !isNewerVersion(appVersion, rel.TagName) {
		t.Fatalf("0.1 → v0.2 应判为更新")
	}
	// handler 层: 检查接口返回 hasUpdate, 并记录检查时间。
	req := httptest.NewRequest("GET", "/api/upgrade/check", nil)
	rec := httptest.NewRecorder()
	handleUpgradeCheck(rec, req)
	if rec.Code != 200 {
		t.Fatalf("检查接口应 200, 得到 %d: %s", rec.Code, rec.Body.String())
	}
	var d struct {
		HasUpdate bool   `json:"hasUpdate"`
		Latest    string `json:"latest"`
	}
	if json.NewDecoder(rec.Body).Decode(&d) != nil || !d.HasUpdate || d.Latest != "v0.2" {
		t.Fatalf("检查结果不对: %+v", d)
	}
}

func TestUpgradeApplySuccess(t *testing.T) {
	_, exe, spawned, restarted := setupUpgradeTest(t)
	fakeUpgradeStation(t, "v0.2", []byte("NEWBIN-v0.2"), false)
	appVersion = "0.1"
	setUpgradeStatus("applying", "v0.2", "", "") // handler 侧先置 applying, 再起后台流程
	runUpgradeApply("")
	got, _ := os.ReadFile(exe)
	if string(got) != "NEWBIN-v0.2" {
		t.Fatalf("可执行文件应被替换为新版, 得到 %q", got)
	}
	if !*spawned {
		t.Fatalf("替换前应起看门狗")
	}
	if !*restarted {
		t.Fatalf("替换后应触发重启")
	}
	if _, err := os.Stat(upgradeMarkerPath()); err != nil {
		t.Fatalf("替换后 marker 应存在(看门狗收尾): %v", err)
	}
	ents, _ := os.ReadDir(upgradeBackupDir())
	if len(ents) != 1 {
		t.Fatalf("应恰好 1 份备份, 得到 %d", len(ents))
	}
	bb, _ := os.ReadFile(filepath.Join(upgradeBackupDir(), ents[0].Name()))
	if string(bb) != "OLDBIN" {
		t.Fatalf("备份内容应为旧二进制, 得到 %q", bb)
	}
	st := loadUpgradeStatus()
	if st.State != "applying" {
		t.Fatalf("未真实重启前状态应保持 applying, 得到 %q", st.State)
	}
}

func TestUpgradeApplyTampered(t *testing.T) {
	_, exe, spawned, _ := setupUpgradeTest(t)
	fakeUpgradeStation(t, "v0.2", []byte("EVILBIN"), true) // 校验和不符
	appVersion = "0.1"
	runUpgradeApply("")
	got, _ := os.ReadFile(exe)
	if string(got) != "OLDBIN" {
		t.Fatalf("校验失败时绝不能替换, 得到 %q", got)
	}
	if *spawned {
		t.Fatalf("校验失败时不应起看门狗")
	}
	if _, err := os.Stat(upgradeMarkerPath()); err == nil {
		t.Fatalf("校验失败时不应留 marker")
	}
	st := loadUpgradeStatus()
	if st.State != "failed" || !strings.Contains(st.Error, "校验失败") {
		t.Fatalf("状态应为 failed 且含校验失败, 得到 %+v", st)
	}
}

func TestUpgradeApplyNotNewer(t *testing.T) {
	_, exe, _, _ := setupUpgradeTest(t)
	fakeUpgradeStation(t, "v0.2", []byte("NEWBIN"), false)
	appVersion = "0.2" // 已是新版
	runUpgradeApply("")
	got, _ := os.ReadFile(exe)
	if string(got) != "OLDBIN" {
		t.Fatalf("已是最新时不应替换, 得到 %q", got)
	}
	st := loadUpgradeStatus()
	if st.State != "failed" {
		t.Fatalf("已是最新时状态应为 failed(拒绝), 得到 %+v", st)
	}
}

func TestUpgradeApplyConflictAndBadVersion(t *testing.T) {
	setupUpgradeTest(t)
	setUpgradeStatus("applying", "v0.2", "", "")
	req := httptest.NewRequest("POST", "/api/upgrade/apply", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handleUpgradeApply(rec, req)
	if rec.Code != 409 {
		t.Fatalf("升级中再次申请应 409, 得到 %d", rec.Code)
	}
	setUpgradeStatus("idle", "", "", "")
	req = httptest.NewRequest("POST", "/api/upgrade/apply", strings.NewReader(`{"version":"abc"}`))
	rec = httptest.NewRecorder()
	handleUpgradeApply(rec, req)
	if rec.Code != 400 {
		t.Fatalf("非法版本号应 400, 得到 %d", rec.Code)
	}
}

func TestUpgradeWatcherSuccess(t *testing.T) {
	setupUpgradeTest(t)
	mk := upgradeMarker{Target: "0.2", From: "0.1", Backup: "/nonexistent", Port: 59188, TimeoutSec: 5, StartedAt: time.Now().Unix()}
	mb, _ := json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	code := runUpgradeWatcher(upgradeMarkerPath(), func(int) (string, error) { return "0.2", nil }, func(upgradeMarker) error { return nil })
	if code != 0 {
		t.Fatalf("探到目标版应返回 0, 得到 %d", code)
	}
	if _, err := os.Stat(upgradeMarkerPath()); err == nil {
		t.Fatalf("成功后 marker 应删除")
	}
	if st := loadUpgradeStatus(); st.State != "done" || st.Target != "0.2" {
		t.Fatalf("成功后状态应为 done/0.2, 得到 %+v", st)
	}
}

// TestUpgradeWatcherWritesStatusBesideMarker: 看门狗状态必须写 marker 同目录,
// 而不是全局 dataDir——systemd 瞬时 service 环境干净、GUIJIA_DATA_DIR 会丢,
// 按 dataDir 写会落到默认目录、面板永远读不到(实测抓到的真 bug)。
func TestUpgradeWatcherWritesStatusBesideMarker(t *testing.T) {
	setupUpgradeTest(t)
	markerDir := t.TempDir()
	mk := upgradeMarker{Target: "v0.2", From: "0.1", Backup: "/nonexistent", Port: 59188, TimeoutSec: 5, StartedAt: time.Now().Unix()}
	mb, _ := json.Marshal(mk)
	mp := filepath.Join(markerDir, "upgrade-marker.json")
	os.WriteFile(mp, mb, 0644)
	code := runUpgradeWatcher(mp, func(int) (string, error) { return "0.2", nil }, func(upgradeMarker) error { return nil })
	if code != 0 {
		t.Fatalf("探到目标版应返回 0, 得到 %d", code)
	}
	b, err := os.ReadFile(filepath.Join(markerDir, "upgrade-status.json"))
	if err != nil {
		t.Fatalf("marker 同目录应有 upgrade-status.json: %v", err)
	}
	var st upgradeStatus
	json.Unmarshal(b, &st)
	if st.State != "done" || st.Target != "v0.2" {
		t.Fatalf("marker 同目录状态应为 done/v0.2, 得到 %+v", st)
	}
	if _, err := os.Stat(upgradeStatusPath()); err == nil {
		t.Fatalf("全局 dataDir 下不应出现状态文件(看门狗写错了地方)")
	}
}

// 归一化后相等才算成功(直接 == 会误判回滚, 实测抓到的真 bug)。
func TestUpgradeWatcherSuccessVPrefix(t *testing.T) {
	setupUpgradeTest(t)
	mk := upgradeMarker{Target: "v0.2", From: "0.1", Backup: "/nonexistent", Port: 59188, TimeoutSec: 5, StartedAt: time.Now().Unix()}
	mb, _ := json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	code := runUpgradeWatcher(upgradeMarkerPath(), func(int) (string, error) { return "0.2", nil }, func(upgradeMarker) error { return nil })
	if code != 0 {
		t.Fatalf("v 前缀归一化后应返回 0, 得到 %d", code)
	}
	if st := loadUpgradeStatus(); st.State != "done" {
		t.Fatalf("v 前缀归一化后状态应为 done, 得到 %+v", st)
	}
}

func TestUpgradeWatcherRollback(t *testing.T) {
	_, exe, _, _ := setupUpgradeTest(t)
	// 备份里放旧二进制, 看门狗超时后应把它拷回 marker 里记的真实面板路径(Exe),
	// 而不是看门狗自身的路径(看门狗跑在副本里, 往自身上还原就还错了地方)。
	backup := filepath.Join(upgradeBackupDir(), "guijia-0.1-x")
	os.MkdirAll(upgradeBackupDir(), 0755)
	os.WriteFile(backup, []byte("OLDBIN"), 0755)
	os.WriteFile(exe, []byte("BROKEN"), 0755)
	mk := upgradeMarker{Target: "0.2", From: "0.1", Backup: backup, Port: 59188, TimeoutSec: 5, StartedAt: time.Now().Unix(), Exe: exe}
	mb, _ := json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	// 探针永远返回旧版, 但把超时压到 1 秒内跑完: 改 marker 超时为 0 不行(默认 60),
	// 故直接用短超时 marker + 快探针间隔(setup 已把间隔压到 10ms)。
	mk.TimeoutSec = 1
	mb, _ = json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	restarted := false
	code := runUpgradeWatcher(upgradeMarkerPath(), func(int) (string, error) { return "0.1", nil }, func(upgradeMarker) error { restarted = true; return nil })
	if code != 1 {
		t.Fatalf("超时回滚应返回 1, 得到 %d", code)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "OLDBIN" {
		t.Fatalf("回滚后可执行文件应恢复旧版, 得到 %q", got)
	}
	if !restarted {
		t.Fatalf("回滚后应触发重启")
	}
	st := loadUpgradeStatus()
	if st.State != "failed" || !strings.Contains(st.Error, "回滚") {
		t.Fatalf("回滚后状态应为 failed 且含回滚, 得到 %+v", st)
	}
}

func TestUpgradeWatcherMarkerGone(t *testing.T) {
	setupUpgradeTest(t)
	mk := upgradeMarker{Target: "0.2", From: "0.1", Backup: "/nonexistent", Port: 59188, TimeoutSec: 5, StartedAt: time.Now().Unix()}
	mb, _ := json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	code := runUpgradeWatcher(upgradeMarkerPath(), func(int) (string, error) {
		os.Remove(upgradeMarkerPath()) // 另有人处理了, 看门狗静默退出
		return "0.1", nil
	}, func(upgradeMarker) error { return nil })
	if code != 0 {
		t.Fatalf("marker 消失时应静默退出 0, 得到 %d", code)
	}
}

func TestUpgradeReconcileOnStart(t *testing.T) {
	setupUpgradeTest(t)
	// 陈旧 marker + 当前版就是目标 → done。
	appVersion = "0.2"
	mk := upgradeMarker{Target: "0.2", From: "0.1", Backup: "/nonexistent", Port: 59188, TimeoutSec: 60, StartedAt: time.Now().Unix() - 1000}
	mb, _ := json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	upgradeReconcileOnStart()
	if st := loadUpgradeStatus(); st.State != "done" {
		t.Fatalf("陈旧 marker 且版本已是目标时应 done, 得到 %+v", st)
	}
	if _, err := os.Stat(upgradeMarkerPath()); err == nil {
		t.Fatalf("收尾后 marker 应删除")
	}
	// 陈旧 marker + 当前版不是目标 → failed。
	appVersion = "0.1"
	mk.Target = "0.2"
	mb, _ = json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	upgradeReconcileOnStart()
	if st := loadUpgradeStatus(); st.State != "failed" {
		t.Fatalf("陈旧 marker 且版本未变时应 failed, 得到 %+v", st)
	}
	// 新鲜 marker → 不动(看门狗可能还活着)。
	mk.StartedAt = time.Now().Unix()
	mb, _ = json.Marshal(mk)
	os.WriteFile(upgradeMarkerPath(), mb, 0644)
	setUpgradeStatus("applying", "0.2", "", "")
	upgradeReconcileOnStart()
	if _, err := os.Stat(upgradeMarkerPath()); err != nil {
		t.Fatalf("新鲜 marker 不应被启动收尾动")
	}
}

func TestUpgradePushAllOfflineAndProxyable(t *testing.T) {
	if !isProxyablePath("api/upgrade/apply") {
		t.Fatalf("升级接口应允许跨节点调用(主服务器推节点靠它)")
	}
	if isProxyablePath("api/nodes/upgrade-all") {
		t.Fatalf("upgrade-all 是主服务器本地接口, 绝不能被代理到节点")
	}
	hubMu.Lock()
	oldServers := hubServers
	hubServers = []*hubServer{{Fingerprint: strings.Repeat("a", 64), Name: "离线节点", Status: "offline", LastSeen: time.Now().Unix() - 1000}}
	hubMu.Unlock()
	defer func() {
		hubMu.Lock()
		hubServers = oldServers
		hubMu.Unlock()
	}()
	req := httptest.NewRequest("POST", "/api/nodes/upgrade-all", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handleNodeUpgradeAll(rec, req)
	if rec.Code != 200 {
		t.Fatalf("推送接口应 200, 得到 %d: %s", rec.Code, rec.Body.String())
	}
	var d struct {
		Results []struct {
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"results"`
	}
	if json.NewDecoder(rec.Body).Decode(&d) != nil || len(d.Results) != 1 || d.Results[0].OK || !strings.Contains(d.Results[0].Detail, "离线") {
		t.Fatalf("离线节点应跳过并注明, 得到 %+v", d)
	}
}
