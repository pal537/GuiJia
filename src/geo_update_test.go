package main

import (
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
