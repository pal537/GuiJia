package main

// 国家三方对照: ISO 代码 ↔ 中文名 ↔ 英文名, 逐条对应归属地库实际枚举的
// 国家集合。代码取自库记录自身的国家代码字段(实测逐条导出, 非手写),
// 中文名为标准译名。分类一律按代码归一化匹配: 库里 "India" 与 "印度"
// 是两条记录但同属 IN, 选了任何一种写法都生效, 杜绝中英文混写导致选了
// 不生效。港澳台不进国家枚举, 单列为地区级选项(HK/MO/TW)。

import (
	"strings"
	"sync"
)

type CountryEntry struct {
	Code string `json:"code"`
	Zh   string `json:"zh"`
	En   string `json:"en"`
}

var countryTable = []CountryEntry{
	{Code: "AF", Zh: "阿富汗", En: "Afghanistan"},
	{Code: "AL", Zh: "阿尔巴尼亚", En: "Albania"},
	{Code: "DZ", Zh: "阿尔及利亚", En: "Algeria"},
	{Code: "AS", Zh: "美属萨摩亚", En: "American Samoa"},
	{Code: "AD", Zh: "安道尔", En: "Andorra"},
	{Code: "AO", Zh: "安哥拉", En: "Angola"},
	{Code: "AI", Zh: "安圭拉", En: "Anguilla"},
	{Code: "AQ", Zh: "南极洲", En: "Antarctica"},
	{Code: "AG", Zh: "安提瓜和巴布达", En: "Antigua and Barbuda"},
	{Code: "AR", Zh: "阿根廷", En: "Argentina"},
	{Code: "AM", Zh: "亚美尼亚", En: "Armenia"},
	{Code: "AW", Zh: "阿鲁巴", En: "Aruba"},
	{Code: "AU", Zh: "澳大利亚", En: "Australia"},
	{Code: "AT", Zh: "奥地利", En: "Austria"},
	{Code: "AZ", Zh: "阿塞拜疆", En: "Azerbaijan"},
	{Code: "BS", Zh: "巴哈马", En: "Bahamas"},
	{Code: "BH", Zh: "巴林", En: "Bahrain"},
	{Code: "BD", Zh: "孟加拉国", En: "Bangladesh"},
	{Code: "BB", Zh: "巴巴多斯", En: "Barbados"},
	{Code: "BY", Zh: "白俄罗斯", En: "Belarus"},
	{Code: "BE", Zh: "比利时", En: "Belgium"},
	{Code: "BZ", Zh: "伯利兹", En: "Belize"},
	{Code: "BJ", Zh: "贝宁", En: "Benin"},
	{Code: "BM", Zh: "百慕大", En: "Bermuda"},
	{Code: "BT", Zh: "不丹", En: "Bhutan"},
	{Code: "BO", Zh: "玻利维亚", En: "Bolivia"},
	{Code: "BA", Zh: "波斯尼亚和黑塞哥维那", En: "Bosnia and Herzegovina"},
	{Code: "BW", Zh: "博茨瓦纳", En: "Botswana"},
	{Code: "BR", Zh: "巴西", En: "Brazil"},
	{Code: "IO", Zh: "英属印度洋领地", En: "British Indian Ocean Territory"},
	{Code: "VG", Zh: "英属维尔京群岛", En: "British Virgin Islands"},
	{Code: "BN", Zh: "文莱", En: "Brunei Darussalam"},
	{Code: "BG", Zh: "保加利亚", En: "Bulgaria"},
	{Code: "BF", Zh: "布基纳法索", En: "Burkina Faso"},
	{Code: "BI", Zh: "布隆迪", En: "Burundi"},
	{Code: "CV", Zh: "佛得角", En: "Cabo Verde"},
	{Code: "KH", Zh: "柬埔寨", En: "Cambodia"},
	{Code: "CM", Zh: "喀麦隆", En: "Cameroon"},
	{Code: "CA", Zh: "加拿大", En: "Canada"},
	{Code: "BQ", Zh: "荷属加勒比区", En: "Caribbean Netherlands"},
	{Code: "KY", Zh: "开曼群岛", En: "Cayman Islands"},
	{Code: "CF", Zh: "中非共和国", En: "Central African Republic"},
	{Code: "TD", Zh: "乍得", En: "Chad"},
	{Code: "CL", Zh: "智利", En: "Chile"},
	{Code: "CO", Zh: "哥伦比亚", En: "Colombia"},
	{Code: "KM", Zh: "科摩罗", En: "Comoros"},
	{Code: "CG", Zh: "刚果共和国", En: "Congo"},
	{Code: "CK", Zh: "库克群岛", En: "Cook Islands"},
	{Code: "CR", Zh: "哥斯达黎加", En: "Costa Rica"},
	{Code: "HR", Zh: "克罗地亚", En: "Croatia"},
	{Code: "CU", Zh: "古巴", En: "Cuba"},
	{Code: "CW", Zh: "库拉索", En: "Curaçao"},
	{Code: "CY", Zh: "塞浦路斯", En: "Cyprus"},
	{Code: "CZ", Zh: "捷克", En: "Czechia"},
	{Code: "CI", Zh: "科特迪瓦", En: "Côte d'Ivoire"},
	{Code: "CD", Zh: "刚果民主共和国", En: "DR Congo"},
	{Code: "DK", Zh: "丹麦", En: "Denmark"},
	{Code: "DJ", Zh: "吉布提", En: "Djibouti"},
	{Code: "DM", Zh: "多米尼克", En: "Dominica"},
	{Code: "DO", Zh: "多米尼加共和国", En: "Dominican Republic"},
	{Code: "EC", Zh: "厄瓜多尔", En: "Ecuador"},
	{Code: "EG", Zh: "埃及", En: "Egypt"},
	{Code: "SV", Zh: "萨尔瓦多", En: "El Salvador"},
	{Code: "GQ", Zh: "赤道几内亚", En: "Equatorial Guinea"},
	{Code: "ER", Zh: "厄立特里亚", En: "Eritrea"},
	{Code: "EE", Zh: "爱沙尼亚", En: "Estonia"},
	{Code: "SZ", Zh: "斯威士兰", En: "Eswatini"},
	{Code: "ET", Zh: "埃塞俄比亚", En: "Ethiopia"},
	{Code: "FK", Zh: "福克兰群岛", En: "Falkland Islands"},
	{Code: "FO", Zh: "法罗群岛", En: "Faroe Islands"},
	{Code: "FJ", Zh: "斐济", En: "Fiji"},
	{Code: "FI", Zh: "芬兰", En: "Finland"},
	{Code: "FR", Zh: "法国", En: "France"},
	{Code: "GF", Zh: "法属圭亚那", En: "French Guiana"},
	{Code: "PF", Zh: "法属波利尼西亚", En: "French Polynesia"},
	{Code: "GA", Zh: "加蓬", En: "Gabon"},
	{Code: "GM", Zh: "冈比亚", En: "Gambia"},
	{Code: "GE", Zh: "格鲁吉亚", En: "Georgia"},
	{Code: "DE", Zh: "德国", En: "Germany"},
	{Code: "GH", Zh: "加纳", En: "Ghana"},
	{Code: "GI", Zh: "直布罗陀", En: "Gibraltar"},
	{Code: "GR", Zh: "希腊", En: "Greece"},
	{Code: "GL", Zh: "格陵兰", En: "Greenland"},
	{Code: "GD", Zh: "格林纳达", En: "Grenada"},
	{Code: "GP", Zh: "瓜德罗普", En: "Guadeloupe"},
	{Code: "GU", Zh: "关岛", En: "Guam"},
	{Code: "GT", Zh: "危地马拉", En: "Guatemala"},
	{Code: "GG", Zh: "根西", En: "Guernsey"},
	{Code: "GN", Zh: "几内亚", En: "Guinea"},
	{Code: "GW", Zh: "几内亚比绍", En: "Guinea-Bissau"},
	{Code: "GY", Zh: "圭亚那", En: "Guyana"},
	{Code: "HT", Zh: "海地", En: "Haiti"},
	{Code: "VA", Zh: "梵蒂冈", En: "Holy See"},
	{Code: "HN", Zh: "洪都拉斯", En: "Honduras"},
	{Code: "HU", Zh: "匈牙利", En: "Hungary"},
	{Code: "IS", Zh: "冰岛", En: "Iceland"},
	{Code: "IN", Zh: "印度", En: "India"},
	{Code: "ID", Zh: "印度尼西亚", En: "Indonesia"},
	{Code: "IR", Zh: "伊朗", En: "Iran"},
	{Code: "IQ", Zh: "伊拉克", En: "Iraq"},
	{Code: "IE", Zh: "爱尔兰", En: "Ireland"},
	{Code: "IM", Zh: "马恩岛", En: "Isle of Man"},
	{Code: "IL", Zh: "以色列", En: "Israel"},
	{Code: "IT", Zh: "意大利", En: "Italy"},
	{Code: "JM", Zh: "牙买加", En: "Jamaica"},
	{Code: "JP", Zh: "日本", En: "Japan"},
	{Code: "JE", Zh: "泽西", En: "Jersey"},
	{Code: "JO", Zh: "约旦", En: "Jordan"},
	{Code: "KZ", Zh: "哈萨克斯坦", En: "Kazakhstan"},
	{Code: "KE", Zh: "肯尼亚", En: "Kenya"},
	{Code: "KI", Zh: "基里巴斯", En: "Kiribati"},
	{Code: "XK", Zh: "科索沃", En: "Kosovo"},
	{Code: "KW", Zh: "科威特", En: "Kuwait"},
	{Code: "KG", Zh: "吉尔吉斯斯坦", En: "Kyrgyzstan"},
	{Code: "LA", Zh: "老挝", En: "Laos"},
	{Code: "LV", Zh: "拉脱维亚", En: "Latvia"},
	{Code: "LB", Zh: "黎巴嫩", En: "Lebanon"},
	{Code: "LS", Zh: "莱索托", En: "Lesotho"},
	{Code: "LR", Zh: "利比里亚", En: "Liberia"},
	{Code: "LY", Zh: "利比亚", En: "Libya"},
	{Code: "LI", Zh: "列支敦士登", En: "Liechtenstein"},
	{Code: "LT", Zh: "立陶宛", En: "Lithuania"},
	{Code: "LU", Zh: "卢森堡", En: "Luxembourg"},
	{Code: "MG", Zh: "马达加斯加", En: "Madagascar"},
	{Code: "MW", Zh: "马拉维", En: "Malawi"},
	{Code: "MY", Zh: "马来西亚", En: "Malaysia"},
	{Code: "MV", Zh: "马尔代夫", En: "Maldives"},
	{Code: "ML", Zh: "马里", En: "Mali"},
	{Code: "MT", Zh: "马耳他", En: "Malta"},
	{Code: "MH", Zh: "马绍尔群岛", En: "Marshall Islands"},
	{Code: "MQ", Zh: "马提尼克", En: "Martinique"},
	{Code: "MR", Zh: "毛里塔尼亚", En: "Mauritania"},
	{Code: "MU", Zh: "毛里求斯", En: "Mauritius"},
	{Code: "YT", Zh: "马约特", En: "Mayotte"},
	{Code: "MX", Zh: "墨西哥", En: "Mexico"},
	{Code: "FM", Zh: "密克罗尼西亚", En: "Micronesia"},
	{Code: "MD", Zh: "摩尔多瓦", En: "Moldova"},
	{Code: "MC", Zh: "摩纳哥", En: "Monaco"},
	{Code: "MN", Zh: "蒙古", En: "Mongolia"},
	{Code: "ME", Zh: "黑山", En: "Montenegro"},
	{Code: "MS", Zh: "蒙特塞拉特", En: "Montserrat"},
	{Code: "MA", Zh: "摩洛哥", En: "Morocco"},
	{Code: "MZ", Zh: "莫桑比克", En: "Mozambique"},
	{Code: "MM", Zh: "缅甸", En: "Myanmar"},
	{Code: "NA", Zh: "纳米比亚", En: "Namibia"},
	{Code: "NR", Zh: "瑙鲁", En: "Nauru"},
	{Code: "NP", Zh: "尼泊尔", En: "Nepal"},
	{Code: "NL", Zh: "荷兰", En: "Netherlands"},
	{Code: "NC", Zh: "新喀里多尼亚", En: "New Caledonia"},
	{Code: "NZ", Zh: "新西兰", En: "New Zealand"},
	{Code: "NI", Zh: "尼加拉瓜", En: "Nicaragua"},
	{Code: "NE", Zh: "尼日尔", En: "Niger"},
	{Code: "NG", Zh: "尼日利亚", En: "Nigeria"},
	{Code: "NU", Zh: "纽埃", En: "Niue"},
	{Code: "NF", Zh: "诺福克岛", En: "Norfolk Island"},
	{Code: "KP", Zh: "朝鲜", En: "North Korea"},
	{Code: "MK", Zh: "北马其顿", En: "North Macedonia"},
	{Code: "MP", Zh: "北马里亚纳群岛", En: "Northern Mariana Islands"},
	{Code: "NO", Zh: "挪威", En: "Norway"},
	{Code: "OM", Zh: "阿曼", En: "Oman"},
	{Code: "PK", Zh: "巴基斯坦", En: "Pakistan"},
	{Code: "PW", Zh: "帕劳", En: "Palau"},
	{Code: "PS", Zh: "巴勒斯坦", En: "Palestine"},
	{Code: "PA", Zh: "巴拿马", En: "Panama"},
	{Code: "PG", Zh: "巴布亚新几内亚", En: "Papua New Guinea"},
	{Code: "PY", Zh: "巴拉圭", En: "Paraguay"},
	{Code: "PE", Zh: "秘鲁", En: "Peru"},
	{Code: "PH", Zh: "菲律宾", En: "Philippines"},
	{Code: "PN", Zh: "皮特凯恩群岛", En: "Pitcairn"},
	{Code: "PL", Zh: "波兰", En: "Poland"},
	{Code: "PT", Zh: "葡萄牙", En: "Portugal"},
	{Code: "PR", Zh: "波多黎各", En: "Puerto Rico"},
	{Code: "QA", Zh: "卡塔尔", En: "Qatar"},
	{Code: "RO", Zh: "罗马尼亚", En: "Romania"},
	{Code: "RU", Zh: "俄罗斯", En: "Russia"},
	{Code: "RW", Zh: "卢旺达", En: "Rwanda"},
	{Code: "RE", Zh: "留尼汪", En: "Réunion"},
	{Code: "BL", Zh: "圣巴泰勒米", En: "Saint Barthélemy"},
	{Code: "SH", Zh: "圣赫勒拿", En: "Saint Helena"},
	{Code: "KN", Zh: "圣基茨和尼维斯", En: "Saint Kitts and Nevis"},
	{Code: "LC", Zh: "圣卢西亚", En: "Saint Lucia"},
	{Code: "MF", Zh: "圣马丁", En: "Saint Martin"},
	{Code: "PM", Zh: "圣皮埃尔和密克隆", En: "Saint Pierre and Miquelon"},
	{Code: "VC", Zh: "圣文森特和格林纳丁斯", En: "Saint Vincent and the Grenadines"},
	{Code: "WS", Zh: "萨摩亚", En: "Samoa"},
	{Code: "SM", Zh: "圣马力诺", En: "San Marino"},
	{Code: "ST", Zh: "圣多美和普林西比", En: "Sao Tome and Principe"},
	{Code: "SA", Zh: "沙特阿拉伯", En: "Saudi Arabia"},
	{Code: "SN", Zh: "塞内加尔", En: "Senegal"},
	{Code: "RS", Zh: "塞尔维亚", En: "Serbia"},
	{Code: "SC", Zh: "塞舌尔", En: "Seychelles"},
	{Code: "SL", Zh: "塞拉利昂", En: "Sierra Leone"},
	{Code: "SG", Zh: "新加坡", En: "Singapore"},
	{Code: "SX", Zh: "辛特马尔滕", En: "Sint Maarten"},
	{Code: "SK", Zh: "斯洛伐克", En: "Slovakia"},
	{Code: "SI", Zh: "斯洛文尼亚", En: "Slovenia"},
	{Code: "SB", Zh: "所罗门群岛", En: "Solomon Islands"},
	{Code: "SO", Zh: "索马里", En: "Somalia"},
	{Code: "ZA", Zh: "南非", En: "South Africa"},
	{Code: "KR", Zh: "韩国", En: "South Korea"},
	{Code: "SS", Zh: "南苏丹", En: "South Sudan"},
	{Code: "ES", Zh: "西班牙", En: "Spain"},
	{Code: "LK", Zh: "斯里兰卡", En: "Sri Lanka"},
	{Code: "SD", Zh: "苏丹", En: "Sudan"},
	{Code: "SR", Zh: "苏里南", En: "Suriname"},
	{Code: "SJ", Zh: "斯瓦尔巴和扬马延", En: "Svalbard and Jan Mayen"},
	{Code: "SE", Zh: "瑞典", En: "Sweden"},
	{Code: "CH", Zh: "瑞士", En: "Switzerland"},
	{Code: "SY", Zh: "叙利亚", En: "Syria"},
	{Code: "TJ", Zh: "塔吉克斯坦", En: "Tajikistan"},
	{Code: "TZ", Zh: "坦桑尼亚", En: "Tanzania"},
	{Code: "TH", Zh: "泰国", En: "Thailand"},
	{Code: "TL", Zh: "东帝汶", En: "Timor-Leste"},
	{Code: "TG", Zh: "多哥", En: "Togo"},
	{Code: "TK", Zh: "托克劳", En: "Tokelau"},
	{Code: "TO", Zh: "汤加", En: "Tonga"},
	{Code: "TT", Zh: "特立尼达和多巴哥", En: "Trinidad and Tobago"},
	{Code: "TN", Zh: "突尼斯", En: "Tunisia"},
	{Code: "TM", Zh: "土库曼斯坦", En: "Turkmenistan"},
	{Code: "TC", Zh: "特克斯和凯科斯群岛", En: "Turks and Caicos Islands"},
	{Code: "TV", Zh: "图瓦卢", En: "Tuvalu"},
	{Code: "TR", Zh: "土耳其", En: "Türkiye"},
	{Code: "UG", Zh: "乌干达", En: "Uganda"},
	{Code: "UA", Zh: "乌克兰", En: "Ukraine"},
	{Code: "AE", Zh: "阿拉伯联合酋长国", En: "United Arab Emirates"},
	{Code: "GB", Zh: "英国", En: "United Kingdom"},
	{Code: "US", Zh: "美国", En: "United States"},
	{Code: "VI", Zh: "美属维尔京群岛", En: "United States Virgin Islands"},
	{Code: "UY", Zh: "乌拉圭", En: "Uruguay"},
	{Code: "UZ", Zh: "乌兹别克斯坦", En: "Uzbekistan"},
	{Code: "VU", Zh: "瓦努阿图", En: "Vanuatu"},
	{Code: "VE", Zh: "委内瑞拉", En: "Venezuela"},
	{Code: "VN", Zh: "越南", En: "Viet Nam"},
	{Code: "WF", Zh: "瓦利斯和富图纳", En: "Wallis and Futuna"},
	{Code: "YE", Zh: "也门", En: "Yemen"},
	{Code: "ZM", Zh: "赞比亚", En: "Zambia"},
	{Code: "ZW", Zh: "津巴布韦", En: "Zimbabwe"},
	{Code: "AX", Zh: "奥兰", En: "Åland"},
	{Code: "CN", Zh: "中国", En: "China"},
}

// 港澳台地区级选项(不进国家枚举, 只在自定义位置(海外)里出现)。
var countrySARTable = []CountryEntry{
	{Code: "HK", Zh: "香港", En: "Hong Kong"},
	{Code: "MO", Zh: "澳门", En: "Macau"},
	{Code: "TW", Zh: "台湾", En: "Taiwan"},
}

// 搜索别名: 常见异名也命中同一代码, 只影响搜索, 不影响存储与分类。
var countrySearchAlias = map[string]string{
	"turkey": "TR", "swaziland": "SZ", "cape verde": "CV", "czech republic": "CZ",
	"burma": "MM", "vietnam": "VN", "ivory coast": "CI", "south korea": "KR",
	"north korea": "KP", "russia": "RU", "tanzania": "TZ", "bolivia": "BO",
	"venezuela": "VE", "laos": "LA", "moldova": "MD", "syria": "SY", "iran": "IR",
	"palestine": "PS", "macao": "MO", "hongkong": "HK", "taiwan": "TW",
	"史瓦帝尼": "SZ", "土耳其耶": "TR", "维德角": "CV",
}

var (
	countryByCodeOnce sync.Once
	countryByCodeMap  map[string]CountryEntry
	countryByNameMap  map[string]CountryEntry
)

func countryIndexInit() {
	countryByCodeOnce.Do(func() {
		countryByCodeMap = map[string]CountryEntry{}
		countryByNameMap = map[string]CountryEntry{}
		for _, e := range countryTable {
			countryByCodeMap[e.Code] = e
			countryByNameMap[e.En] = e
			countryByNameMap[e.Zh] = e
			countryByNameMap[strings.ToLower(e.En)] = e
		}
		for _, e := range countrySARTable {
			countryByCodeMap[e.Code] = e
			countryByNameMap[e.Zh] = e
		}
	})
}

// countryEntryForCode 代码 -> 三方条目。
func countryEntryForCode(code string) (CountryEntry, bool) {
	countryIndexInit()
	e, ok := countryByCodeMap[strings.ToUpper(strings.TrimSpace(code))]
	return e, ok
}

// countryEntryForName 库原字符串/中文名/英文名 -> 三方条目。
func countryEntryForName(name string) (CountryEntry, bool) {
	countryIndexInit()
	if e, ok := countryByNameMap[strings.TrimSpace(name)]; ok {
		return e, true
	}
	if e, ok := countryByNameMap[strings.ToLower(strings.TrimSpace(name))]; ok {
		return e, true
	}
	return CountryEntry{}, false
}

// countryCodeForGeo 归属地 -> 归一化代码。港澳台优先(库里国家仍是中国,
// 靠省份判定); 再按库原国家字符串查表; 再按旧中文名表; 再用库自带代码。
func countryCodeForGeo(geo GeoInfo) string {
	if sar := geoSAR(geo); sar != "" {
		switch sar {
		case "香港":
			return "HK"
		case "澳门":
			return "MO"
		case "台湾":
			return "TW"
		}
	}
	if geo.Country != "" {
		if e, ok := countryEntryForName(geo.Country); ok {
			return e.Code
		}
		if code := countryCodeForName(geo.Country); code != "" {
			return code
		}
	}
	if len(geo.Code) == 2 {
		return strings.ToUpper(geo.Code)
	}
	return ""
}

// countryZhForCode 代码 -> 中文名, 查不到返回代码本身(不猜中文名)。
func countryZhForCode(code string) string {
	if e, ok := countryEntryForCode(code); ok {
		return e.Zh
	}
	return code
}
