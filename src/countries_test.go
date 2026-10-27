package main

// 国家三方对照表: 覆盖库枚举、代码归一化、旧字符串归一化。

import (
	"strings"
	"testing"
)

// TestCountryTableCoversDB: 库枚举的每个国家字符串都能在三方表里找到
// (中文串与英文串同属一代码, 如 India/印度同为 IN); 表里代码不重复冲突。
func TestCountryTableCoversDB(t *testing.T) {
	seenCode := map[string]string{}
	for _, e := range countryTable {
		if prev, ok := seenCode[e.Code]; ok && prev != e.En && prev != e.Zh {
			// 同一代码多行只允许中英双拼(India/印度、United States/美国)。
			if !(e.Code == "IN" || e.Code == "US") {
				t.Errorf("代码 %s 对应多条: %q 与 %q", e.Code, prev, e.En)
			}
		}
		seenCode[e.Code] = e.En
	}
	for _, s := range geoCountries() {
		if _, ok := countryEntryForName(s); !ok {
			t.Errorf("库国家 %q 在三方表里没有条目", s)
		}
	}
	// SAR 三条齐全
	for _, want := range []string{"HK", "MO", "TW"} {
		if _, ok := countryEntryForCode(want); !ok {
			t.Errorf("SAR 代码 %s 缺失", want)
		}
	}
}

// TestCountryCodeForGeo: 归属地 -> 代码归一化(含港澳台省份判定与中英双拼)。
func TestCountryCodeForGeo(t *testing.T) {
	cases := []struct {
		geo  GeoInfo
		want string
	}{
		{GeoInfo{Country: "中国", Province: "江苏省", City: "南京市"}, "CN"},
		{GeoInfo{Country: "中国", Province: "香港特别行政区"}, "HK"},
		{GeoInfo{Country: "中国", Province: "澳门特别行政区"}, "MO"},
		{GeoInfo{Country: "中国", Province: "台湾省"}, "TW"},
		{GeoInfo{Country: "United States", Province: "California"}, "US"},
		{GeoInfo{Country: "美国"}, "US"},
		{GeoInfo{Country: "India"}, "IN"},
		{GeoInfo{Country: "印度"}, "IN"},
		{GeoInfo{Country: "Japan"}, "JP"},
		{GeoInfo{Country: "日本"}, "JP"},
		{GeoInfo{}, ""},
	}
	for _, c := range cases {
		if got := countryCodeForGeo(c.geo); got != c.want {
			t.Errorf("geo %+v -> %q, want %q", c.geo, got, c.want)
		}
	}
	if got := countryZhForCode("US"); got != "美国" {
		t.Errorf("US 中文名 = %q, want 美国", got)
	}
	if got := countryZhForCode("HK"); got != "香港" {
		t.Errorf("HK 中文名 = %q, want 香港", got)
	}
}

// TestNormalizeCountrySelections: 旧字符串归一化入库(中英同码去重)。
func TestNormalizeCountrySelections(t *testing.T) {
	got := normalizeCountrySelections([]string{"美国", "United States", "HK", "香港", " Japan ", ""})
	want := []string{"US", "HK", "JP"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("归一化 = %v, want %v", got, want)
	}
}
