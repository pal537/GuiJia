package main

// 归属地国旗: 归属地名(中文/英文/ISO 代码) -> 国旗 emoji。
// ip2region 返回的国家名是中文(如中国、美国); 手动归属地是用户自由文本,
// 同一张表覆盖中文名、英文名与 ISO 代码; 命中不了的一律不显示旗(不猜)。

import (
	"strings"
)

// countryCodeForName 归属地名 -> ISO 3166-1 alpha-2 大写代码, 命中不了返回 ""。
func countryCodeForName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	if len(n) == 2 {
		up := strings.ToUpper(n)
		if up[0] >= 'A' && up[0] <= 'Z' && up[1] >= 'A' && up[1] <= 'Z' {
			return up
		}
	}
	if code, ok := countryNameMap[n]; ok {
		return code
	}
	if code, ok := countryNameMap[strings.ToLower(n)]; ok {
		return code
	}
	return ""
}

// flagEmojiForCountry 归属地名 -> 国旗 emoji, 命中不了返回 ""。
func flagEmojiForCountry(name string) string {
	code := countryCodeForName(name)
	if code == "" {
		return ""
	}
	r1 := rune(0x1F1E6 + rune(code[0]-'A'))
	r2 := rune(0x1F1E6 + rune(code[1]-'A'))
	return string([]rune{r1, r2})
}

var countryNameMap = map[string]string{
	"中国": "CN", "china": "CN",
	"中国香港": "HK", "香港": "HK", "hong kong": "HK", "hongkong": "HK",
	"中国澳门": "MO", "澳门": "MO", "macau": "MO", "macao": "MO",
	"中国台湾": "TW", "台湾": "TW", "taiwan": "TW",
	"美国": "US", "united states": "US", "usa": "US", "america": "US",
	"日本": "JP", "japan": "JP",
	"韩国": "KR", "korea": "KR", "south korea": "KR",
	"新加坡": "SG", "singapore": "SG",
	"英国": "GB", "united kingdom": "GB", "uk": "GB", "england": "GB",
	"德国": "DE", "germany": "DE",
	"法国": "FR", "france": "FR",
	"荷兰": "NL", "netherlands": "NL", "holland": "NL",
	"加拿大": "CA", "canada": "CA",
	"澳大利亚": "AU", "australia": "AU",
	"俄罗斯": "RU", "russia": "RU",
	"印度": "IN", "india": "IN",
	"巴西": "BR", "brazil": "BR",
	"意大利": "IT", "italy": "IT",
	"西班牙": "ES", "spain": "ES",
	"瑞典": "SE", "sweden": "SE",
	"挪威": "NO", "norway": "NO",
	"芬兰": "FI", "finland": "FI",
	"丹麦": "DK", "denmark": "DK",
	"波兰": "PL", "poland": "PL",
	"土耳其": "TR", "turkey": "TR", "turkiye": "TR",
	"泰国": "TH", "thailand": "TH",
	"越南": "VN", "vietnam": "VN",
	"马来西亚": "MY", "malaysia": "MY",
	"印尼": "ID", "indonesia": "ID",
	"菲律宾": "PH", "philippines": "PH",
	"阿联酋": "AE", "united arab emirates": "AE", "uae": "AE",
	"沙特": "SA", "saudi arabia": "SA",
	"以色列": "IL", "israel": "IL",
	"乌克兰": "UA", "ukraine": "UA",
	"爱尔兰": "IE", "ireland": "IE",
	"瑞士": "CH", "switzerland": "CH",
	"奥地利": "AT", "austria": "AT",
	"比利时": "BE", "belgium": "BE",
	"捷克": "CZ", "czech": "CZ", "czechia": "CZ",
	"葡萄牙": "PT", "portugal": "PT",
	"希腊": "GR", "greece": "GR",
	"墨西哥": "MX", "mexico": "MX",
	"阿根廷": "AR", "argentina": "AR",
	"智利": "CL", "chile": "CL",
	"埃及": "EG", "egypt": "EG",
	"南非": "ZA", "south africa": "ZA",
	"新西兰": "NZ", "new zealand": "NZ",
	"罗马尼亚": "RO", "romania": "RO",
	"匈牙利": "HU", "hungary": "HU",
	"冰岛": "IS", "iceland": "IS",
	"卢森堡": "LU", "luxembourg": "LU",
	"保加利亚": "BG", "bulgaria": "BG",
	"克罗地亚": "HR", "croatia": "HR",
	"立陶宛": "LT", "lithuania": "LT",
	"拉脱维亚": "LV", "latvia": "LV",
	"爱沙尼亚": "EE", "estonia": "EE",
	"斯洛文尼亚": "SI", "slovenia": "SI",
	"斯洛伐克": "SK", "slovakia": "SK",
}
