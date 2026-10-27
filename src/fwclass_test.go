package main

// 防火墙来源分类矩阵: v4/v6、境内/境外/港澳台/外国、自定义国家、自定义省份、
// CIDR、全部 IP、未知、私网保留段。分类逻辑按 2026-10-27 内嵌库实测字段写:
// 港澳台的国家字段仍是"中国", 必须看省份(香港特别行政区/澳门特别行政区/台湾省)。

import (
	"net"
	"strings"
	"testing"
)

func TestFWSourceMatchMatrix(t *testing.T) {
	geoMainland := GeoInfo{Country: "中国", Province: "江苏省", City: "南京市"}
	geoHK := GeoInfo{Country: "中国", Province: "香港特别行政区", City: ""}
	geoMO := GeoInfo{Country: "中国", Province: "澳门特别行政区", City: ""}
	geoTW := GeoInfo{Country: "中国", Province: "台湾省", City: ""}
	geoUS := GeoInfo{Country: "United States", Province: "California", City: "San Francisco"}
	geoJP := GeoInfo{Country: "Japan", Province: "Tokyo", City: ""}
	geoCF := GeoInfo{Country: "Bangladesh", Province: "Dhaka Division", City: "Dhaka", ISP: "Cloudflare"}
	geoUnknown := GeoInfo{}
	geoPrivate := GeoInfo{Country: "内网", Text: "内网", Private: true}

	ip4 := net.ParseIP("8.8.8.8")
	ip6 := net.ParseIP("2606:4700:4700::1111")
	cases := []struct {
		name string
		src  FWSource
		ip   net.IP
		geo  GeoInfo
		want bool
	}{
		{"全部IP命中一切", FWSource{Kind: "all"}, ip4, geoUnknown, true},
		{"全部IP命中未知", FWSource{Kind: "all"}, ip4, geoUnknown, true},
		{"全部IPv4命中v4", FWSource{Kind: "all_v4"}, ip4, geoUnknown, true},
		{"全部IPv4不命中v6", FWSource{Kind: "all_v4"}, ip6, geoUnknown, false},
		{"全部IPv6命中v6", FWSource{Kind: "all_v6"}, ip6, geoUnknown, true},
		{"全部IPv6不命中v4", FWSource{Kind: "all_v6"}, ip4, geoUnknown, false},
		{"境内命中大陆", FWSource{Kind: "cn_in"}, ip4, geoMainland, true},
		{"境内不命中香港", FWSource{Kind: "cn_in"}, ip4, geoHK, false},
		{"境内不命中澳门", FWSource{Kind: "cn_in"}, ip4, geoMO, false},
		{"境内不命中台湾", FWSource{Kind: "cn_in"}, ip4, geoTW, false},
		{"境内不命中外国", FWSource{Kind: "cn_in"}, ip4, geoUS, false},
		{"境内不命中未知", FWSource{Kind: "cn_in"}, ip4, geoUnknown, false},
		{"境外不命中大陆", FWSource{Kind: "cn_out"}, ip4, geoMainland, false},
		{"境外命中香港", FWSource{Kind: "cn_out"}, ip4, geoHK, true},
		{"境外命中澳门", FWSource{Kind: "cn_out"}, ip4, geoMO, true},
		{"境外命中台湾", FWSource{Kind: "cn_out"}, ip4, geoTW, true},
		{"境外命中外国", FWSource{Kind: "cn_out"}, ip4, geoUS, true},
		{"境外命中Cloudflare段", FWSource{Kind: "cn_out"}, ip4, geoCF, true},
		{"境外不命中未知", FWSource{Kind: "cn_out"}, ip4, geoUnknown, false},
		{"境外不命中私网", FWSource{Kind: "cn_out"}, ip4, geoPrivate, false},
		{"自定义国家中国命中大陆", FWSource{Kind: "custom_loc", Countries: []string{"中国"}}, ip4, geoMainland, true},
		{"自定义国家中国不命中香港", FWSource{Kind: "custom_loc", Countries: []string{"中国"}}, ip4, geoHK, false},
		{"自定义国家香港命中香港", FWSource{Kind: "custom_loc", Countries: []string{"香港"}}, ip4, geoHK, true},
		{"自定义国家香港不命中大陆", FWSource{Kind: "custom_loc", Countries: []string{"香港"}}, ip4, geoMainland, false},
		{"自定义国家澳门命中澳门", FWSource{Kind: "custom_loc", Countries: []string{"澳门"}}, ip4, geoMO, true},
		{"自定义国家台湾命中台湾", FWSource{Kind: "custom_loc", Countries: []string{"台湾"}}, ip4, geoTW, true},
		{"自定义国家美国命中美国", FWSource{Kind: "custom_loc", Countries: []string{"United States"}}, ip4, geoUS, true},
		{"自定义国家美国不命中日本", FWSource{Kind: "custom_loc", Countries: []string{"United States"}}, ip4, geoJP, false},
		{"自定义国家多选任一命中", FWSource{Kind: "custom_loc", Countries: []string{"Japan", "United States"}}, ip4, geoUS, true},
		{"自定义国家不命中未知", FWSource{Kind: "custom_loc", Countries: []string{"中国", "United States"}}, ip4, geoUnknown, false},
		{"自定义省份江苏命中南京", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}, ip4, geoMainland, true},
		{"自定义省份江苏不命中香港", FWSource{Kind: "custom_loc", Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}, ip4, geoHK, false},
		{"自定义位置国家或省份任一命中", FWSource{Kind: "custom_loc", Countries: []string{"Japan"}, Locations: []GuardLocation{{Kind: "province", Name: "江苏"}}}, ip4, geoMainland, true},
		{"自定义位置都不命中", FWSource{Kind: "custom_loc", Countries: []string{"Japan"}, Locations: []GuardLocation{{Kind: "province", Name: "浙江"}}}, ip4, geoMainland, false},
	}
	for _, c := range cases {
		// custom_ip 的 cidrNet 需预解析(其余 kind 不用)
		if c.src.Kind == "custom_ip" {
			c.src.cidrNet = parseCIDRNet(c.src.CIDR)
		}
		if got := fwSourceMatch(c.src, c.ip, c.geo); got != c.want {
			t.Errorf("%s: fwSourceMatch = %v, want %v (geo=%+v)", c.name, got, c.want, c.geo)
		}
	}
	// CIDR 单测(单独列出, 因需预解析)
	cidrCases := []struct {
		cidr string
		ip   string
		want bool
	}{
		{"8.8.8.0/24", "8.8.8.8", true},
		{"8.8.8.0/24", "8.8.4.4", false},
		{"8.8.8.8", "8.8.8.8", true},  // 裸 IP 按单地址
		{"8.8.8.8", "8.8.8.9", false}, // 裸 IP 不含邻居
		{"2606:4700::/32", "2606:4700:4700::1111", true},
		{"2606:4700::/32", "2001:4860:4860::8888", false},
		{"0.0.0.0/0", "8.8.8.8", true}, // 全网段等价于全部 IPv4
	}
	for _, c := range cidrCases {
		src := FWSource{Kind: "custom_ip", CIDR: c.cidr, cidrNet: parseCIDRNet(c.cidr)}
		if got := fwSourceMatch(src, net.ParseIP(c.ip), GeoInfo{}); got != c.want {
			t.Errorf("CIDR %s 对 %s = %v, want %v", c.cidr, c.ip, got, c.want)
		}
	}
}

// TestFWGeoRealDB: 真实内嵌库抽查(大陆、港澳台、美、日、Cloudflare 段、私网)。
func TestFWGeoRealDB(t *testing.T) {
	geoLoadV4Embedded()
	cases := []struct {
		ip      string
		country string
		sar     string
		in      bool
		out     bool
		ispFrag string
	}{
		{"114.114.114.114", "中国", "", true, false, ""},                // 江苏南京
		{"223.5.5.5", "中国", "", true, false, ""},                      // 浙江杭州
		{"116.48.125.74", "中国", "香港", false, true, ""},                // 香港(库里国家仍是中国)
		{"180.217.44.104", "中国", "台湾", false, true, ""},               // 台湾
		{"8.8.8.8", "United States", "", false, true, ""},             // 美国
		{"133.167.1.1", "Japan", "", false, true, ""},                 // 日本
		{"172.68.4.188", "Bangladesh", "", false, true, "Cloudflare"}, // Cloudflare 段(截图同款)
	}
	for _, c := range cases {
		g := geoLookup(c.ip)
		if g.Country != c.country {
			t.Errorf("%s 国家 = %q, want %q (全文 %+v)", c.ip, g.Country, c.country, g)
		}
		if got := geoSAR(g); got != c.sar {
			t.Errorf("%s SAR = %q, want %q", c.ip, got, c.sar)
		}
		if got := geoIsMainland(g); got != c.in {
			t.Errorf("%s 境内 = %v, want %v", c.ip, got, c.in)
		}
		if got := fwSourceMatch(FWSource{Kind: "cn_out"}, net.ParseIP(c.ip), g); got != c.out {
			t.Errorf("%s 境外 = %v, want %v", c.ip, got, c.out)
		}
		if c.ispFrag != "" && !strings.Contains(g.Text, c.ispFrag) {
			t.Errorf("%s 展示应带运营商名 %q, 得到 %q", c.ip, c.ispFrag, g.Text)
		}
	}
	// 私网: 库不查, 直接标内网
	if g := geoLookup("192.168.1.1"); !g.Private || g.Country != "内网" {
		t.Errorf("私网应标内网, 得到 %+v", g)
	}
	// 澳门: 内嵌 v4 库无澳门段(枚举证实), 字段形态与港台同源(省份=澳门特别行政区),
	// 分类逻辑只认归一化省份, 故用港台同形态的合成值验证澳门分支。
	if got := geoSAR(GeoInfo{Country: "中国", Province: "澳门特别行政区"}); got != "澳门" {
		t.Errorf("澳门省份形态 SAR = %q, want 澳门", got)
	}
	if geoIsMainland(GeoInfo{Country: "中国", Province: "澳门特别行政区"}) {
		t.Error("澳门不应算大陆")
	}
}

// TestBannableReserved: 保留段永远不封禁(文档段除外, 全库测试固件用它)。
func TestBannableReserved(t *testing.T) {
	oldTrusted := settings.TrustedIPs
	settings.TrustedIPs = nil
	defer func() { settings.TrustedIPs = oldTrusted }()
	blocked := []string{
		"10.0.0.5", "172.16.0.5", "192.168.1.1", "127.0.0.1", "::1", "fe80::1",
		"100.64.0.1", "198.18.0.1", "240.0.0.1", "224.0.0.1", "169.254.1.1",
		"ff00::1", "2001::1", "2001:2::1", "2001:10::1",
	}
	for _, ip := range blocked {
		if ok, _ := bannable(ip); ok {
			t.Errorf("保留段 %s 应不可拉黑", ip)
		}
	}
	allowed := []string{
		"203.0.113.55", "192.0.2.1", "198.51.100.1", "2001:db8::1", // 文档段例外
		"8.8.8.8", "114.114.114.114", "172.68.4.188",
	}
	for _, ip := range allowed {
		if ok, why := bannable(ip); !ok {
			t.Errorf("公网/文档段 %s 应可拉黑, 被拒: %s", ip, why)
		}
	}
	if ok, _ := bannable("not-an-ip"); ok {
		t.Error("非法 IP 应不可拉黑")
	}
}
