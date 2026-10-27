package main

import (
	"strings"
	"testing"
)

// UI 弹窗与精简后的设置页: 新元素 ID 必须存在, 已删的旧 ID 必须消失。
// indexHTML 是内嵌的整页, 该测试直接断言下发内容, 防止改 UI 时漏改一处。
func TestUIIDs(t *testing.T) {
	html := string(indexHTML)
	for _, id := range []string{
		"btnPxAcmeApplyOpen",    // 反代页: 在线申请按钮(弹窗入口)
		"pxAcmeModal",           // 证书申请弹窗构建函数
		"openTotpModal",         // 2FA 二维码弹窗构建函数
		"cmTotpQR",              // 2FA 弹窗二维码图片
		"cmTotpSecret",          // 2FA 弹窗手动密钥
		"cmTotpCopy",            // 2FA 弹窗复制按钮
		"cmTotpRefresh",         // 2FA 弹窗换一个按钮
		"cmTotpStatus",          // 2FA 弹窗内状态行
		"cmTotpCode",            // 2FA 弹窗动态码输入
		"cmTotpEnable",          // 2FA 弹窗开通按钮
		"cmPwCur",               // 改密码弹窗当前密码
		"cmPwNew",               // 改密码弹窗新密码
		"cmPwNew2",              // 改密码弹窗再次输入
		"sPanelPort",            // 设置页面板端口输入
		"sServerName",           // 设置页面板服务器名称输入(TG 通知标题用)
		"btnPanelPortSave",      // 设置页面板端口保存按钮
		"panelPortHint",         // 面板端口提示行
		"pairCard",              // 设置页生成配对码卡片(面板设置卡正下方)
		"btnPairGen",            // 生成配对码按钮
		"pairCodeTx",            // 生成的配对码显示
		"pairCodeExp",           // 配对码有效期显示
		"btnPairCopy",           // 配对码复制按钮
		"pairMsg",               // 配对卡内状态行
		"pairPending",           // 待添加节点列表区
		"pairPendingMsg",        // 待添加区状态行
		"btnPairRefresh",        // 待添加刷新按钮
		"cmodalOnClose",         // 弹窗关闭清理钩子(证书申请轮询)
		"cmRuleErr",             // 反代规则弹窗内状态行
		"cmDelErr",              // 删除规则弹窗内状态行
		"cmCertErr",             // 添加证书弹窗内状态行
		"cmCertDelErr",          // 删除证书弹窗内状态行
		"btnPxAcmeNginxCheck",   // 证书申请弹窗检查代答配置按钮
		"msgbox",                // 申请状态彩色框（中性/绿/红）
		"cmCertEditErr",         // 证书编辑弹窗内状态行
		"pxCertEditModal",       // 证书编辑弹窗构建函数
		"data-px-certrefresh",   // 证书行刷新按钮
		"data-px-certedit",      // 证书行编辑按钮
		`data-tab="cert"`,       // 导航证书项
		`id="tab-cert"`,         // 证书页
		`data-tab="home"`,       // 导航首页项(仅有其他服务器时显示)
		`id="tab-home"`,         // 首页
		"navHome",               // 首页导航按钮
		"homeGrid",              // 首页服务器卡片网格
		"homeAlert",             // 首页新设备提醒条
		"btnHomeAck",            // 提醒条“知道了”按钮
		"managingTag",           // 顶部正在管理标识(拦截链 pill 左边, 点回首页)
		"managingTagTx",         // 正在管理标识文案
		"正在管理：",                 // 管理标识文案前缀
		"totpCard",              // 设置页 2FA 卡片(节点视图隐藏)
		"tgCard",                // 设置页通用通知方式卡片(节点视图隐藏)
		"sessCard",              // 总览当前登录会话卡片(节点视图隐藏)
		"ntTokenRow",            // 节点 TG 独立 Token 行(仅独立模式显示)
		"ntChatRow",             // 节点 TG 独立 Chat ID 行(仅独立模式显示)
		"ntTestRow",             // 节点 TG 连通性测试行(仅独立模式显示)
		"ntApplyModeVisibility", // 节点 TG 模式显隐函数
		"btnPairGoHome",         // 批准成功后配对卡内“去首页”按钮
		"已添加 ",                  // 批准成功提示文案
		"点击首页可查看管理",             // 批准成功提示文案
		"重新生成",                  // 配对码二次生成按钮文案
		"已过期，请重新生成",             // 配对码过期提示
		"设置归属地",                 // 卡片设置菜单内归属地项(原卡片按钮已改菜单)
		"移除管理",                  // 卡片设置菜单内移除项(原卡片按钮已改菜单)
		`data-act="menu"`,       // 卡片左下角设置菜单按钮
		"openCardMenu",          // 卡片设置菜单弹窗构建函数
		"srv-foot2",             // 卡片底部行样式(设置按钮左 + LOGO 右)
		"srv-logo",              // 卡片系统 LOGO 样式
		"osLogo",                // 系统 LOGO 自动匹配函数
		"flag-img",              // 卡片国旗图样式(真实国旗图片, 不用 emoji)
		"flagcdn",               // 国旗图源(flagcdn)
		"sline",                 // 卡内状态线样式(绿/红虚线框)
		"srv-card.managing",     // 正在管理卡片发光样式
		"btnGroupSync",          // 首页群控设置入口
		"openGroupSyncModal",    // 群控设置弹窗构建函数
		"共享黑名单",                 // 群控设置黑名单组
		"共享白名单",                 // 群控设置白名单组
		"立即同步",                  // 群控设置立即同步按钮
		"pwChangeRow",           // 面板设置修改密码行(节点视图隐藏)
		"面板端口已改，节点连接正常",          // 节点改端口重连成功卡内文案
		"backup-download",        // 节点备份按指纹路由端点
		"upgrade-push-status",    // 推送升级状态轮询端点
		"升级成功：",                  // 推送升级成功状态线文案
		"升级失败：",                  // 推送升级失败状态线文案
		"ntSeg",                  // 节点 TG 分段控制器
		"openLocModal",           // 归属地弹窗构建函数
		"openRemoveModal",        // 移除确认弹窗构建函数
		"homeSetMeta",            // 首页卡片元信息就地更新
		"srv-meta",               // 卡片元信息行样式
		"cmBackHost",             // 反代规则上游 IP 框
		"cmBackPort",             // 反代规则上游端口框
		"pxCertViewModal",        // 证书查看弹窗构建函数
		"data-px-certview",       // 证书行查看按钮
		"data-px-certdl",         // 证书行下载按钮
		"代理到内网已有应用端口",            // 反代规则上游新提示文案
		`<th>名称</th><th>监听</th>`, // 反代规则表首列改显示名称
		"http://127.0.0.1",       // 上游第一框可见预填 scheme+host（占位与预设）
		"上游格式为 http://IP:端口",     // 反代规则弹窗顶部上游格式提示
		"<th>域名</th>",            // 证书表 SAN 列改名域名
		"下载为 zip",                // 证书卡下载含私钥的 zip 说明
		"请填写上游地址",                // 上游空框校验
		"上游地址请带 http:// 前缀",      // 上游无 scheme 校验
		"由 nginx 接管",             // nginx 接管规则行状态（绿字，非红字失败）
		"portTakeover",           // 反代规则行接管集（快照 takeover 字段）
		"portManaged",            // 反代规则行管理集（快照 managed 字段，面板已生成 vhost）
		"genErr",                 // 反代规则行生成失败原因（快照 genErr 字段，红字）
	} {
		if !strings.Contains(html, id) {
			t.Errorf("UI 应包含 %s", id)
		}
	}
	for _, id := range []string{
		"sPanelSSLMode",    // 已删: 面板 SSL 模式下拉
		"sPanelSSLCert",    // 已删: SSL 证书下拉
		"sPanelSSLPort",    // 已删: SSL 端口输入
		"sPanelDomain",     // 已删: 直访域名输入
		"totpSetupBox",     // 已删: 2FA 平铺开通区
		"loadPanelCerts",   // 已删: 面板证书下拉加载
		"panelOld",         // 已删: 面板 SSL 旧值记录
		"pxPanelSelfModal", // 已删: 反代本面板单独弹窗（已改复用规则弹窗）
		"btnPxSelf",        // 已删: 反代本面板按钮（2026-10-26 用户要求去掉）
		"127.0.0.1:",       // 已删: 反代本面板上游预设（按钮已删，预设入口一并清理）
		"cmSelfErr",        // 已删: 反代本面板单独弹窗状态行
		"cmSelfBack",       // 已删: 反代本面板单独弹窗上游框
		`id="viewBar"`,     // 已删: 正在查看节点提示条(改顶部管理标识)
		"btnHomeBack",      // 已删: 返回首页按钮(管理标识点回首页)
		"viewBarName",      // 已删: 旧提示条名称元素
		"ntOn",             // 已删: 节点 TG 启用独立通知开关(单选即选择)
		"nodeTgMode",       // 已删: 节点 TG 原生 radio(已改分段控制器)
		"当前模式：",            // 已删: 节点 TG 重复显示当前模式行
		"正在查看：",            // 已删: 旧提示条文案
		`srv-btns`,         // 已删: 卡片底部双按钮行(已改左下设置菜单 + 右下 LOGO)
		`data-act="loc"`,   // 已删: 卡片直接设置归属地按钮(已进设置菜单)
		`data-act="rm"`,    // 已删: 卡片直接移除管理按钮(已进设置菜单)
		`data-k="sys"`,     // 已删: 卡片系统文字行(已集成到 LOGO title)
		"只代理到内网已有应用，不做静态文件搭建与重定向", // 已删: 反代上游旧提示文案
		"http://192.168.1.10:8080",           // 已删: 反代上游旧参考案例
		"127.0.0.1，留空默认本机",                   // 已删: 上游旧占位（scheme 改为可见预填）
		"上游只支持 host:port 或 http://host:port", // 已删: 反代规则弹窗顶部旧上游提示
		"<th>SAN</th>",                       // 已删: 证书表旧 SAN 表头
	} {
		if strings.Contains(html, id) {
			t.Errorf("UI 不应再有 %s", id)
		}
	}
}

// TestModalNoToast: 弹窗内反馈一律写弹窗内状态行，不弹顶部 toast。
// 按函数起止标记切片断言（标记缺失即失败，防文件结构变了断言 silently 失效）。
func TestModalNoToast(t *testing.T) {
	html := string(indexHTML)
	cases := []struct{ name, start, end string }{
		{"证书申请弹窗", "function pxAcmeModal(){", "$('#btnPxAcmeApplyOpen').onclick"},
		{"2FA 弹窗", "function openTotpModal(r){", "$('#btnTotpDisable').onclick"},
		{"反代规则弹窗", "function pxRuleModal(rule){", "function pxDelModal("},
		{"删除规则弹窗", "function pxDelModal(id,dom){", "$('#btnPxRetry').onclick"},
		{"添加证书弹窗", "function pxCertModal(){", "$('#btnPxCertAdd').onclick"},
		{"删除证书弹窗", "$$('#pxCertBody [data-px-certdel]')", "/* ---------- 总览 ---------- */"},
		{"改密码弹窗", "$('#btnPanelPwChange').onclick=()=>{", "$('#btnPanelPortSave').onclick"},
		{"证书编辑弹窗", "function pxCertEditModal(c){", "$('#btnPxCertAdd').onclick"},
		{"证书查看弹窗", "function pxCertViewModal(c){", "function bindPxRowEvents(){"},
	}
	for _, c := range cases {
		s := strings.Index(html, c.start)
		if s < 0 {
			t.Errorf("%s: 起始标记缺失 %q", c.name, c.start)
			continue
		}
		e := strings.Index(html[s:], c.end)
		if e < 0 {
			t.Errorf("%s: 结束标记缺失 %q", c.name, c.end)
			continue
		}
		if body := html[s : s+e]; strings.Contains(body, "toast(") {
			t.Errorf("%s 内不应有 toast( 调用", c.name)
		}
	}
}

// TestProtCardOrder: 防护页端口防护卡置顶到五项防护最前面（洪峰之前），
// 安全建议与急救等其他卡位置不动。
func TestProtCardOrder(t *testing.T) {
	html := string(indexHTML)
	sec := html[strings.Index(html, `<section id="tab-prot"`):]
	sec = sec[:strings.Index(sec, `<section id="tab-proxy"`)]
	idx := func(h3 string) int {
		i := strings.Index(sec, "<h3>"+h3)
		if i < 0 {
			t.Fatalf("防护页应有卡片 %q", h3)
		}
		return i
	}
	safe := idx("安全建议")
	pg := idx("端口防护 ")
	flood := idx("重点端口洪峰防护 ")
	autoban := idx("爆破自动拉黑")
	scan := idx("扫描识别 ")
	honey := idx("蜜罐 ")
	rescue := idx("急救 ")
	if !(safe < pg && pg < flood && flood < autoban && autoban < scan && scan < honey && honey < rescue) {
		t.Errorf("防护页卡顺序应为 安全建议 < 端口防护 < 洪峰 < 爆破 < 扫描 < 蜜罐 < 急救，实际下标 %d %d %d %d %d %d %d",
			safe, pg, flood, autoban, scan, honey, rescue)
	}
}
