package main

import (
	"strings"
	"testing"
)

// 防火墙下拉行对齐回归(2026-10-28): v1.0.11 的教训——
// .msel-row 的 grid 左列规则本身没错, 但 .cmcard .fld label(0,2,1) 特异性高于
// .msel-row(0,1,0), display:block 全程覆盖了 grid; .cmcard .fld input(0,2,1) 又与
// .msel-row input(0,2,1) 平手、后出胜出, 把复选框宽度从 16px 压成 100%。
// v1.0.11 的验证只断言了 grid 规则存在, 没断言它在层叠中获胜, 所以生产实测
// 依然是复选框在右。本测试锁死修复: 宽泛规则必须用 :not() 排除行与复选框,
// 且行规则在样式中唯一、模板 input 在 span 之前。
func TestUIMselRowNotOverridden(t *testing.T) {
	html := string(indexHTML)
	// 旧的未排除宽泛规则必须消失(否则行布局又被覆盖)。
	for _, old := range []string{
		`.cmcard .fld label{display:block`,
		`.cmcard .fld input,.cmcard .fld select,.cmcard .fld textarea{width:100%}`,
	} {
		if strings.Contains(html, old) {
			t.Errorf("下发 HTML 仍有未排除的宽泛规则 %q, 会覆盖 .msel-row", old)
		}
	}
	// 新的已排除规则必须存在。
	for _, want := range []string{
		`.cmcard .fld label:not(.msel-row){display:block`,
		`.cmcard .fld input:not([type=checkbox]):not([type=radio]),.cmcard .fld select,.cmcard .fld textarea{width:100%}`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("下发 HTML 缺已排除的宽泛规则 %q", want)
		}
	}
	// 行规则唯一且是 grid 左列(复选框 20px 列、文字自适应列)。
	if n := strings.Count(html, ".msel-row{display:grid;grid-template-columns:20px 1fr"); n != 1 {
		t.Errorf(".msel-row grid 左列规则应恰好出现 1 次, 实际 %d 次", n)
	}
	if strings.Contains(html, ".msel-row{display:flex") {
		t.Errorf("下发 HTML 仍有旧的 .msel-row flex 定义, 与 grid 冲突")
	}
	for _, want := range []string{
		`.msel-row input[type=checkbox]{grid-column:1`,
		`.msel-row span{grid-column:2`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("下发 HTML 缺行规则 %q", want)
		}
	}
	// 三个下拉的渲染函数模板: input 在 span 之前, 共 4 处
	// (国家 1 处 + 省份 1 处 + 城市 2 个分支: 按省列出与搜索列出)。
	if n := strings.Count(html, `<label class="msel-row"><input`); n != 4 {
		t.Errorf("行模板(input 在前)应恰好 4 处, 实际 %d 处", n)
	}
	if strings.Contains(html, `<label class="msel-row"><span`) {
		t.Errorf("下发 HTML 有 span 在前的行模板, 复选框会被推到文字之后")
	}
}
