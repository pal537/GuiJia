package main

// 归属地库下载与手动检查更新（与防火墙无关，通用 Linux 通用）：
// IPv6 库 37MB 不进安装包，首次运行后台下载；v4 库内嵌兜底。

import (
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var geoDLRun int32

// ---------- IPv6 归属地库下载(37MB, 不进安装包) ----------

func downloadGeoV6(force bool) {
	if !atomic.CompareAndSwapInt32(&geoDLRun, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&geoDLRun, 0)
	if geoV6Loaded() && !force {
		return
	}
	// 注意: jsdelivr 对 GitHub 文件有 20MB 上限, 37MB 的 v6 库只能走 raw 源
	urls := []string{geoV6URL, geoV6URL}
	for _, u := range urls {
		if fetchFile(u, geoV6Path+".tmp") {
			if fi, err := os.Stat(geoV6Path + ".tmp"); err == nil && fi.Size() > 30000000 {
				// 先在临时文件上探针+加载, 成功才转正(更新失败不伤现有库)
				if geoLoadV6(geoV6Path + ".tmp") {
					os.Rename(geoV6Path+".tmp", geoV6Path)
					return
				}
			}
			os.Remove(geoV6Path + ".tmp")
		}
	}
}

func fetchFile(url, dst string) bool {
	cli := &http.Client{Timeout: 10 * time.Minute}
	resp, err := cli.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return false
	}
	defer resp.Body.Close()
	f, err := os.Create(dst)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err == nil
}

// ---------- 归属地库手动检查更新: v4/v6 都支持 ----------

const geoV4URL = "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb"

// 检查更新流程: 后台下载上游最新库 -> 与现有库比对 sha256 -> 一致报
// "当前版本已是最新", 不一致则探针校验后转正并热加载, 报"已经更新到最新版本"。
type geoCheckResult struct {
	Done    bool   `json:"done"`
	Updated bool   `json:"updated"`
	Message string `json:"message"`
	Size    int64  `json:"size"`
	Date    int64  `json:"date"`
	Err     string `json:"error,omitempty"`
}

var (
	geoCheckMu  sync.Mutex
	geoCheckRun = map[string]bool{}
	geoCheckRes = map[string]*geoCheckResult{}
)

func geoCheckUpdate(v string) {
	geoCheckMu.Lock()
	if geoCheckRun[v] {
		geoCheckMu.Unlock()
		return
	}
	geoCheckRun[v] = true
	geoCheckMu.Unlock()
	res := &geoCheckResult{}
	defer func() {
		geoCheckMu.Lock()
		res.Done = true
		geoCheckRes[v] = res
		geoCheckRun[v] = false
		geoCheckMu.Unlock()
	}()
	isV4 := v == "4"
	url, path := geoV6URL, geoV6Path
	var minSize int64 = 30000000
	if isV4 {
		url, path, minSize = geoV4URL, geoV4Path, 5000000
	} else if atomic.LoadInt32(&geoDLRun) == 1 {
		res.Err = "正在下载 IPv6 库，稍后再检查"
		return
	}
	tmp := path + ".chk"
	if !fetchFile(url, tmp) {
		res.Err = "下载上游库失败"
		return
	}
	defer os.Remove(tmp)
	fi, err := os.Stat(tmp)
	if err != nil || fi.Size() < minSize {
		res.Err = "下载的库文件异常"
		return
	}
	var cur []byte
	if b, err := os.ReadFile(path); err == nil {
		cur = b
	} else if isV4 {
		cur = embeddedXDBv4
	}
	nb, _ := os.ReadFile(tmp)
	if cur != nil && sha256.Sum256(cur) == sha256.Sum256(nb) {
		res.Message = "当前版本已是最新"
		if fi, err := os.Stat(path); err == nil {
			res.Size, res.Date = fi.Size(), fi.ModTime().Unix()
		} else {
			res.Size = int64(len(embeddedXDBv4))
		}
		return
	}
	ok := false
	if isV4 {
		ok = geoLoadV4File(tmp)
	} else {
		ok = geoLoadV6(tmp)
	}
	if !ok {
		res.Err = "下载的库校验失败，已保留旧库"
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		res.Err = "更新文件失败: " + err.Error()
		return
	}
	if isV4 {
		geoLoadV4File(path)
	} else {
		geoLoadV6(path)
	}
	res.Updated = true
	res.Message = "已经更新到最新版本"
	if fi, err := os.Stat(path); err == nil {
		res.Size, res.Date = fi.Size(), fi.ModTime().Unix()
	}
}
