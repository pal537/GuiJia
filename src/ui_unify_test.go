package main

import (
	"strings"
	"testing"
)

// 全站 UI 统一(2026-10-27): 下发 HTML 必须用首页 .srv-card 同款毛玻璃 +
// pill 按钮 + 行悬停 + .hint 说明, 且旧裸样式(内联文字墙/方角按钮)必须消失。
// 只断言表现层, 不碰任何接口、状态机、同步语义。

func unifyHTML(t *testing.T) string {
	t.Helper()
	return string(indexHTML)
}

func unifyMust(t *testing.T, html string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(html, s) {
			t.Errorf("下发 HTML 缺 %q", s)
		}
	}
}

func unifyMustNot(t *testing.T, html string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(html, s) {
			t.Errorf("下发 HTML 不应再有 %q", s)
		}
	}
}

// TestUIUnifyGlass: 总览统计卡 / 分区卡片与首页同款玻璃(52% 通透 + blur 24px + 内高光)。
// 弹窗卡片例外: 一律纯白底色(毛玻璃透底在遮罩上发灰, PAPA 明确不要)。
// 首页 .srv-card 本体与悬停回弹由 tenten_front_test.go 锁定, 这里只锁新统一的部分。
func TestUIUnifyGlass(t *testing.T) {
	html := unifyHTML(t)
	unifyMust(t, html,
		".stat{background:color-mix(in srgb, var(--card) 52%, transparent);backdrop-filter:blur(24px)",
		".stat.click:hover{transform:translateY(-6px) scale(1.015)",
		".panel{background:color-mix(in srgb, var(--card) 52%, transparent);backdrop-filter:blur(24px)",
		".scard{background:color-mix(in srgb, var(--card) 52%, transparent);backdrop-filter:blur(24px)",
		".cmcard{background:#fff",
		"#pop{position:absolute;width:320px;background:#fff",
		"inset 0 1px 0 rgba(255,255,255,.65),0 12px 32px rgba(37,99,235,.12)",
	)
	unifyMustNot(t, html,
		".stat{background:var(--card)",
		".panel{background:var(--card)",
		".scard{background:var(--card)",
		".stat.click:hover{transform:translateY(-1px)",
		".cmcard{background:color-mix",
		"#pop{background:color-mix",
	)
}

// TestUIUnifyButtons: 全部按钮 pill 化(品牌蓝底白字 + 圆角 + 阴影, 悬停抬升发光); 危险按钮同语言红色 pill。
func TestUIUnifyButtons(t *testing.T) {
	html := unifyHTML(t)
	unifyMust(t, html,
		".btn{font-size:12.5px;font-weight:600;padding:6px 14px;border-radius:999px",
		".btn.primary{background:var(--blue2);border-color:var(--blue2);color:#fff",
		".btn:hover{background:#f4f7fb;transform:translateY(-1px);box-shadow:0 6px 16px rgba(37,99,235,.18)}",
		".btn.dangerfill{background:var(--red);border-color:var(--red);color:#fff",
		".btn.danger:hover{background:rgba(212,58,47,.06);box-shadow:0 6px 16px rgba(212,58,47,.18)}",
	)
	unifyMustNot(t, html, ".btn{font-size:12.5px;font-weight:600;padding:6px 14px;border-radius:8px")
}

// TestUIUnifyTablesForms: 表格行悬停高亮; 页眉筛选 pill + 聚焦柔光; 全局聚焦柔光为 .18; 表单行间距统一。
func TestUIUnifyTablesForms(t *testing.T) {
	html := unifyHTML(t)
	unifyMust(t, html,
		".tblwrap tbody tr:hover td{background:rgba(37,99,235,.05)}",
		".ph input,.ph select{border-radius:999px}",
		".ph input:focus,.ph select:focus{border-color:var(--blue2);box-shadow:0 0 0 3px rgba(37,99,235,.18)}",
		".frow{display:flex;align-items:center;gap:12px;padding:11px 18px}",
		".seg button:hover,.fchip:hover,#pop .dur:hover{transform:translateY(-1px)",
		".sw input:focus-visible + i{box-shadow:0 0 0 3px rgba(37,99,235,.18)}",
	)
	if n := strings.Count(html, "rgba(37,99,235,.18)"); n < 3 {
		t.Errorf("聚焦柔光 .18 应至少出现 3 处(全局输入/省市框/页眉筛选), 实际 %d", n)
	}
	unifyMustNot(t, html, "rgba(37,99,235,.14)")
}

// TestUIUnifyHintWalls: 防护/设置/证书/黑白名单页的内联文字墙全部改成统一 .hint 类; 旧 pattern 归零。
func TestUIUnifyHintWalls(t *testing.T) {
	html := unifyHTML(t)
	unifyMustNot(t, html, `style="padding:2px 18px 0`)
	unifyMust(t, html,
		".scard>.hint,.panel>.hint{padding:2px 18px 0;color:var(--mut);font-size:12.5px;line-height:1.65}",
		".scard>.hint.warn,.panel>.hint.warn{padding-top:4px;color:var(--red)}",
		`<div class="hint">名单内 IP 不报警`,
		`<div class="hint">建议修改默认的 SSH 端口`,
		`<div class="hint">证书只有两个来源`,
		// 备份说明已收进备份与恢复弹窗(csub), 不再平铺在设置页。
		`设置备份 = 全部配置（设置 + 端口 + 蜜罐），不含数据`,
	)
}

// TestUIUnifyGroups: 标题去重(卡片有标题则上方组标题删除), 卡片顺序与 id 一律不动。
func TestUIUnifyGroups(t *testing.T) {
	html := unifyHTML(t)
	unifyMustNot(t, html, ".grp-head{", "grp-head mtitle")
	unifyMust(t, html,
		`.scard .savebar,.panel .savebar{border-top:1px solid var(--line)`,
	)
	// 标题去重不得打乱防护卡顺序(与 TestProtCardOrder 同口径)。
	sec := html[strings.Index(html, `<section id="tab-prot"`):]
	sec = sec[:strings.Index(sec, `<section id="tab-proxy"`)]
	for _, h3 := range []string{"安全建议", "防火墙", "重点端口洪峰防护 ", "爆破自动拉黑", "扫描识别 ", "蜜罐 ", "急救 ", "威胁情报 "} {
		if !strings.Contains(sec, `<h3 class="mtitle">`+h3) {
			t.Errorf("防护页应有卡片 %q", h3)
		}
	}
}

// TestUIUnifyPages: 9 个页面分区与关键新样式元素齐全; 减动效覆盖新组件; 绝不用紫色渐变与原生弹框。
func TestUIUnifyPages(t *testing.T) {
	html := unifyHTML(t)
	unifyMust(t, html,
		`id="tab-home"`, `id="tab-ov"`, `id="tab-ports"`, `id="tab-events"`, `id="tab-bans"`,
		`id="tab-prot"`, `id="tab-proxy"`, `id="tab-cert"`, `id="tab-set"`,
		`id="sessCard"`, `id="portStarWrap"`, `id="evQ"`, `id="banExpand"`, `id="trustExpand"`,
		`id="banIpSearch"`, `id="banStatusFilter"`, `id="pxRuleBody"`, `id="pxCertBody"`,
		`id="totpCard"`, `id="pairCard"`, `id="upCard"`, `id="cmodal"`, `id="pop"`,
		`border-radius:16px;margin:0 18px 12px`,
		"@media (prefers-reduced-motion: reduce){.btn,.stat,.seg button,.fchip,#pop .dur{transition:none}",
	)
	unifyMustNot(t, html, "purple", "128,0,128", "confirm(", "prompt(")
}
