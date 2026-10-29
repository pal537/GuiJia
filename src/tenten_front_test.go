package main

import (
	"strings"
	"testing"
)

// 10 项反馈(2026-10-27 晚 v1.0.6 实测后)的前端静态断言: 下发 HTML/CSS/JS 里的
// 关键实现必须存在, 且旧写法必须消失。真实浏览器点按在沙箱里无法验证,
// 故以这些断言 + 双机接口实测为准。

func tenHTML(t *testing.T) string {
	t.Helper()
	return string(indexHTML)
}

func tenMust(t *testing.T, html string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(html, s) {
			t.Errorf("下发 HTML 缺 %q", s)
		}
	}
}

// TestTenFrontLogos 第 1 项: Debian/Ubuntu 改用 simple-icons(CC0)官方路径数据,
// 不再是手画近似(旧同心弧红旋涡 / 三段弧); 品牌色与 24 视口保留。
func TestTenFrontLogos(t *testing.T) {
	html := tenHTML(t)
	i := strings.Index(html, "if(s.includes('debian'))svg='")
	if i < 0 {
		t.Fatalf("找不到 Debian LOGO 分支")
	}
	deb := html[i : i+4000]
	if !strings.Contains(deb, `viewBox="0 0 24 24"`) {
		t.Errorf("Debian LOGO 应为 24 视口 simple-icons 路径")
	}
	if !strings.Contains(deb, "M13.88 12.685") {
		t.Errorf("Debian LOGO 不是 simple-icons 官方路径起点")
	}
	if !strings.Contains(deb, "#D70A53") {
		t.Errorf("Debian 应为品牌红 #D70A53")
	}
	if strings.Contains(deb, `stroke="#D70A53"`) {
		t.Errorf("Debian 仍是旧手画描边旋涡, 应为填充官方路径")
	}
	j := strings.Index(html, "else if(s.includes('ubuntu'))svg='")
	if j < 0 {
		t.Fatalf("找不到 Ubuntu LOGO 分支")
	}
	ub := html[j : j+1500]
	if !strings.Contains(ub, "M12 0c6.623") {
		t.Errorf("Ubuntu LOGO 不是 simple-icons 官方路径起点")
	}
	if !strings.Contains(ub, "#E95420") {
		t.Errorf("Ubuntu 应为品牌橙 #E95420")
	}
}

// TestTenFrontGlassNav 第 8+10 项: 强毛玻璃、装饰底、悬停回弹、菜单 pill、减动效。
func TestTenFrontGlassNav(t *testing.T) {
	html := tenHTML(t)
	tenMust(t, html,
		".srv-card{background:color-mix(in srgb, var(--card) 52%, transparent);backdrop-filter:blur(24px)",
		"inset 0 1px 0 rgba(255,255,255,.65)",
		".srv-card:hover{transform:translateY(-6px) scale(1.015)",
		"cubic-bezier(.34,1.56,.64,1)",
		"home-wash",
		"rgba(186,230,253",
		"rgba(165,243,252",
		".nav button.on{background:var(--blue);color:#fff",
		".nav button:hover{transform:translateY(-1px)",
		".nav button{transition:none}",
	)
	w0 := strings.Index(html, "#tab-home>.home-wash{")
	if w0 < 0 {
		t.Fatalf("找不到装饰底规则")
	}
	w := html[w0 : w0+600]
	if strings.Contains(w, "purple") || strings.Contains(w, "128,0,128") {
		t.Errorf("装饰底绝不能用紫色: %s", w[:200])
	}
	if strings.Contains(html, "backdrop-filter:blur(14px)") {
		t.Errorf("旧 14px 毛玻璃应已替换为 24px")
	}
}

// TestTenFrontBansPage 第 5 项: 信任在上、两表 10 条分页展开。
func TestTenFrontBansPage(t *testing.T) {
	html := tenHTML(t)
	bans := html[strings.Index(html, `id="tab-bans"`):]
	if strings.Index(bans, "信任名单") > strings.Index(bans, "黑名单记录") {
		t.Errorf("信任名单应在黑名单上面")
	}
	tenMust(t, html,
		`id="trustList"`,
		`id="trustExpand"`,
		`id="banExpand"`,
		"bs.slice(0,banShown)",
		"arr.slice(0,trustShown)",
		"已全部显示",
		`id="trustAdd"`,
		`id="btnTrustAdd"`,
		"data-trust-del",
		`id="sTrusted" placeholder="203.0.113.10" style="display:none"`,
	)
}

// TestTenFrontGroupSyncModal 第 2 项: 草稿语义 + 保存按钮 + 立即同步先保存。
func TestTenFrontGroupSyncModal(t *testing.T) {
	html := tenHTML(t)
	tenMust(t, html,
		`id="gsSave">保存同步设置`,
		"gsDirty_",
		"$('#gsEn_'+g).onchange=dirty;",
		"$('#gsIv_'+g).onchange=dirty;",
		"正在保存并同步",
	)
	if strings.Contains(html, "$('#gsEn_'+g).onchange=save;") {
		t.Errorf("勾选改动不应再立即保存")
	}
	s := strings.Index(html, "async function openGroupSyncModal(){")
	e := strings.Index(html[s:], "\n}\n")
	seg := html[s : s+e]
	if strings.Index(seg, "saveAll()") > strings.Index(seg, "api/group-sync/now") {
		t.Errorf("立即同步应先保存当前表单再同步")
	}
	if strings.Contains(seg, "toast(") {
		t.Errorf("群控弹窗内不应弹顶部提示")
	}
}

// TestTenFrontVersionCard 第 3 项: 自动检查(缓存 1 小时) + 一次性升级消息。
func TestTenFrontVersionCard(t *testing.T) {
	html := tenHTML(t)
	tenMust(t, html,
		"upLatestCache",
		"3600000",
		"upJustDone",
		"sessionStorage.setItem('upJustDone'",
		"sessionStorage.removeItem('upJustDone'",
		"upAutoCheck()",
		"function verGt",
		"st.state==='done'&&justDone",
	)
	if strings.Contains(html, "else if(st&&st.state==='done'){upSetMsg('已升级到 '") {
		t.Errorf("旧的无条件“已升级到”提示应已改为一次性")
	}
}

// TestTenFrontNodeTG 第 4 项: 走主服务器模式也有测试行与测试按钮。
func TestTenFrontNodeTG(t *testing.T) {
	html := tenHTML(t)
	tenMust(t, html,
		"api/nodes/tg-test",
		`id="ntTestDesc"`,
		"经主服务器 bot 发送",
		"if(ntMode==='hub'){await apiLocal('POST','api/nodes/tg-test'",
	)
	s := strings.Index(html, "function ntApplyModeVisibility(){")
	e := strings.Index(html[s:], "\n}\n")
	seg := html[s : s+e]
	if strings.Contains(seg, "'ntTokenRow','ntChatRow','ntTestRow'") {
		t.Errorf("测试行不应再随 token/chat 行一起隐藏")
	}
	if !strings.Contains(seg, "tr.style.display=''") {
		t.Errorf("测试行在两种模式下都应显示")
	}
}

// TestTenFrontManagingLocal 第 7 项: 本机卡同样进“正在管理”态, 但绝不走代理。
func TestTenFrontManagingLocal(t *testing.T) {
	html := tenHTML(t)
	tenMust(t, html,
		"let managingLocal=false",
		"(!fp&&managingLocal)",
		"managingLocal=(fp==='')",
		"managingLocal=false;gotoTab",
		"正在管理：'+localDisplayName",
	)
	s := strings.Index(html, "$('#homeGrid').onclick=")
	e := strings.Index(html[s:], "/* 首页卡片操作")
	seg := html[s : s+e]
	if !strings.Contains(seg, "managingLocal=(fp==='')") {
		t.Errorf("卡片点击应按本机/节点分流 managingLocal")
	}
	if strings.Contains(seg, "api/nodes/proxy") {
		t.Errorf("卡片点击绝不能直接发代理调用")
	}
}

// TestTenFrontHomeLayout 第 9 项: 群控设置按钮在首页底部行左侧。
func TestTenFrontHomeLayout(t *testing.T) {
	html := tenHTML(t)
	i := strings.Index(html, `class="home-foot"`)
	if i < 0 {
		t.Fatalf("找不到首页底部行")
	}
	row := html[i : i+700]
	if strings.Index(row, "btnGroupSync") < 0 || strings.Index(row, "homeTime") < 0 {
		t.Fatalf("底部行应同时含群控设置按钮与更新时间")
	}
	if strings.Index(row, "btnGroupSync") > strings.Index(row, "homeTime") {
		t.Errorf("群控设置按钮应在底部行左侧(更新时间之前)")
	}
	if strings.Index(html, `<div class="home-wash"`) > strings.Index(html, `id="homeGrid"`) {
		t.Errorf("装饰底 div 应在网格之前")
	}
}

// TestTenFrontTrustLAN 第 6 项: 内网信任改成勾选框, 即时保存, 卡内反馈。
func TestTenFrontTrustLAN(t *testing.T) {
	html := tenHTML(t)
	tenMust(t, html,
		`id="chkTrustLAN"`,
		"s.trustLan=$('#chkTrustLAN').checked",
		"$('#chkTrustLAN').checked=!!s.trustLan",
		"'192.168.0.0/16','10.0.0.0/8','172.16.0.0/12','fc00::/7'",
		"已保存：全部内网段已隐式信任",
		"已保存：已取消内网信任",
	)
	if strings.Contains(html, "btnTrustLAN") {
		t.Errorf("旧“信任全部内网 IP”按钮应已删除")
	}
	s := strings.Index(html, "$('#chkTrustLAN').onchange=")
	e := strings.Index(html[s:], "\n};\n")
	seg := html[s : s+e]
	if strings.Contains(seg, "toast(") {
		t.Errorf("内网勾选反馈应在卡内, 不弹顶部提示")
	}
}
