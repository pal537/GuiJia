package main

import (
	"os"
	"strings"
	"testing"
)

// 回归: 上游曾把 v4 库改名为 ip2region_v4.xdb, 旧地址 data/ip2region.xdb
// 已 404, 导致 v4 检查更新永远报"下载上游库失败"。两个地址必须指向
// 上游 data/ 目录下真实存在的文件名, 且与内嵌库版本对应。
func TestGeoUpdateURLs(t *testing.T) {
	if geoV4URL != "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb" {
		t.Fatalf("geoV4URL = %q, want ip2region_v4.xdb", geoV4URL)
	}
	if geoV6URL != "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb" {
		t.Fatalf("geoV6URL = %q, want ip2region_v6.xdb", geoV6URL)
	}
	for _, u := range []string{geoV4URL, geoV6URL} {
		if !strings.HasPrefix(u, "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/") {
			t.Fatalf("bad geo url prefix: %q", u)
		}
	}
}

// 回归: IPv6 库默认不下载、只由设置页手动下载。启动流程(main.go)不得再调用
// downloadGeoV6(仅手动下载接口 api/geo/download 可调); 设置页须保留手动下载入口。
func TestGeoV6NoAutoDownload(t *testing.T) {
	mainSrc, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mainSrc), "downloadGeoV6") {
		t.Errorf("main.go 不应再调用 downloadGeoV6(IPv6 库默认不自动下载)")
	}
	html := string(indexHTML)
	for _, s := range []string{`id="btnGeoDl"`, "立即下载", "尚未下载"} {
		if !strings.Contains(html, s) {
			t.Errorf("设置页归属地卡应保留 IPv6 手动下载入口, 缺 %q", s)
		}
	}
}
