package main

// v1.0.10 返工 UI 断言: 标题去重、统一多选组件对齐、国家双语搜索逻辑。

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestUITitleDedup: 组级说明标题(grp-head)已全部删除; 除品牌登录屏外,
// 每个静态卡片(scard/panel)都自带 h2/h3 标题, 不存在无标题卡片。
func TestUITitleDedup(t *testing.T) {
	html := string(indexHTML)
	if strings.Contains(html, "grp-head") {
		t.Fatal("下发 HTML 不应再含 grp-head 组标题")
	}
	// 按卡片起始切块, 块内前 1500 字必须有标题; 登录屏以品牌块为标题, 例外。
	type span struct{ start, end int }
	var starts []int
	for off := 0; ; {
		i := strings.Index(html[off:], `<div class="scard"`)
		j := strings.Index(html[off:], `<div class="panel"`)
		nx := -1
		if i >= 0 && (j < 0 || i < j) {
			nx = off + i
		} else if j >= 0 {
			nx = off + j
		}
		if nx < 0 {
			break
		}
		starts = append(starts, nx)
		off = nx + 1
	}
	for i, st := range starts {
		end := len(html)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		if sec := strings.Index(html[st:], "</section>"); sec >= 0 && st+sec < end {
			end = st + sec
		}
		block := html[st:end]
		head := block
		if len(head) > 1500 {
			head = head[:1500]
		}
		if strings.Contains(head, `id="loginView"`) {
			if !strings.Contains(head, "authbrand") {
				t.Error("登录屏应以品牌块为标题")
			}
			continue
		}
		if !strings.Contains(head, "<h2") && !strings.Contains(head, "<h3") {
			t.Errorf("无标题卡片: %.120s", strings.ReplaceAll(block[:min(120, len(block))], "\n", " "))
		}
	}
}

// TestUIMselComponent: 统一多选组件存在、对齐属性齐全、旧多选类无残留、
// 来源八项齐全且旧 custom_loc 选项已删除。
func TestUIMselComponent(t *testing.T) {
	html := string(indexHTML)
	for _, css := range []string{
		".msel{position:relative",
		".msel-drop{display:none;position:absolute",
		"left:0;width:100%",
		".msel.open .msel-drop{display:block}",
		"accent-color:var(--blue2)",
		"background:#fff;border:1px solid var(--line);border-radius:12px",
	} {
		if !strings.Contains(html, css) {
			t.Errorf("多选组件 CSS 缺失: %s", css)
		}
	}
	for _, id := range []string{
		"fwForeignField", "fwForeignDrop", "fwForeignSearch", "fwForeignList",
		"fwProvField", "fwProvDrop", "fwProvSearch", "fwProvList",
		"fwCityField", "fwCityDrop", "fwCitySearch", "fwCityList",
		"fwActionSeg", "fwEnabledSeg", "fwCnRow", "fwForeignRow", "fwIpRow",
	} {
		if !strings.Contains(html, id) {
			t.Errorf("对话框缺元素: %s", id)
		}
	}
	for _, old := range []string{
		"pgfield", "pgdrop", "pgrow", "pgchip", "pgwrap", "pgpair",
		"fwToggleDrop", "renderFwCountryList", "fwCountryField",
	} {
		if strings.Contains(html, old) {
			t.Errorf("旧多选实现残留: %s", old)
		}
	}
	for _, kind := range []string{
		`value="custom_ip"`, `value="all_v4"`, `value="all_v6"`,
		`value="cn_in"`, `value="cn_out"`, `value="custom_cn"`,
		`value="custom_foreign"`, `value="all"`,
	} {
		if !strings.Contains(html, kind) {
			t.Errorf("来源选项缺失: %s", kind)
		}
	}
	if strings.Contains(html, `value="custom_loc"`) {
		t.Error("旧 custom_loc 选项应已删除")
	}
	// 下发脚本语法校验
	script := html
	if i := strings.Index(script, "<script>"); i >= 0 {
		script = script[i+len("<script>"):]
	}
	if j := strings.Index(script, "</script>"); j >= 0 {
		script = script[:j]
	}
	tmp, err := os.CreateTemp("", "fw10-*.js")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(script); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	if out, err := exec.Command("node", "--check", tmp.Name()).CombinedOutput(); err != nil {
		t.Fatalf("下发脚本 node --check 失败: %v %s", err, out)
	}
}

// TestUICountrySearchJS: 抽取页内双语搜索函数, 用 node 实测中英搜索。
func TestUICountrySearchJS(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("无 node, 跳过 JS 搜索实测")
	}
	html := string(indexHTML)
	start := strings.Index(html, "function normSearch")
	if start < 0 {
		t.Fatal("页内无 normSearch")
	}
	// 截取到 fwCountryMatch 函数结束(行首右花括号)。
	mstart := strings.Index(html[start:], "function fwCountryMatch")
	if mstart < 0 {
		t.Fatal("页内无 fwCountryMatch")
	}
	rest := html[start+mstart:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatal("无法截取 fwCountryMatch")
	}
	fn := html[start : start+mstart+end+3]
	cases := `
const E=[
 {code:'US',zh:'美国',en:'United States'},
 {code:'JP',zh:'日本',en:'Japan'},
 {code:'HK',zh:'香港',en:'Hong Kong'},
 {code:'TR',zh:'土耳其',en:'Türkiye'},
 {code:'FR',zh:'法国',en:'France'},
 {code:'VN',zh:'越南',en:'Viet Nam'},
 {code:'CW',zh:'库拉索',en:'Curaçao'},
];
const C=[
 ['美国',['US']],['japan',['JP']],['JAPAN',['JP']],['turkey',['TR']],
 ['香港',['HK']],['hong',['HK']],['法国',['FR']],['xyz',[]],
 ['Viet',['VN']],['Cura',['CW']],['US',['US']],
];
let fail=0;
for(const [q,want] of C){
  const got=E.filter(e=>fwCountryMatch(e,q)).map(e=>e.code).join(',');
  if(got!==want.join(',')){console.error('q='+q+' got='+got+' want='+want.join(','));fail++}
}
if(fail)process.exit(1);
console.log('country search ok');
`
	tmp, err := os.CreateTemp("", "fw10search-*.js")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(fn + "\n" + cases); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	if out, err := exec.Command("node", tmp.Name()).CombinedOutput(); err != nil {
		t.Fatalf("双语搜索实测失败: %v %s", err, out)
	}
}
