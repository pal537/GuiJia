# 龟甲安全防护 Guijia

Linux 公网服务器（VPS / 云服务器）的安全防护面板：实时连接监控、入侵防护、蜜罐诱捕，Go 单二进制 + nftables，systemd 或 Docker 运行。

> 本仓库是通用版，与飞牛 fnOS 版彻底分开。飞牛版独立维护，不在这里。

## 功能

### 实时连接监控

- ss + conntrack 采集，含半开（SYN-RECV）连接
- 重点端口、实时流量、流量账本
- 当前登录会话卡片：登录 IP / 登录时间 / 最后活跃，当前会话置顶

### 防护五板斧

- **重点端口洪峰防护**：重点端口连接洪峰时自动封禁
- **爆破自动拉黑**：SSH 失败 10 分钟内 5 次即拉黑，首封 1 小时、再犯 24 小时、累犯永久；内网与信任名单豁免
- **扫描识别**：识别扫描行为并报警、拉黑
- **蜜罐**：蜜罐端口被触碰即报警、拉黑
- **端口防护**：只封新连接，已建立连接不踢

### 黑名单与信任

- 黑名单记录永不丢失：到期、解封只改状态，不删记录
- 信任白名单优先于一切：进了信任名单，即使在黑名单里也能连
- 手动封禁护栏：内网、回环、信任名单一律拒绝拉黑

### 威胁情报

- 公开聚合直链（默认 FireHOL），防护页底部独立板块，手动开启，默认关闭
- 名单不进黑名单、不计入黑名单总数与今日拉黑，底层 nft 全端口封禁
- 解析层 + 应用层两层过滤 IANA 保留段，链首回环放行

### Telegram 通知

- 报警消息带服务器名标题、一键拉黑 / 一键信任按钮
- 按钮带服务器指纹，串台回调只提示不执行；`/trust` 先确认再执行
- 急救命令与服务器本地 CLI（改密、解封等）

### 反代与证书

- 面板接管 nginx vhost 生命周期：规则启用即生成 vhost，停用 / 删除即真停，多域名互不影响
- ACME 在线申请：HTTP-01 / DNS-01 / nginx 代答，多域名一张 SAN 证书，到期前自动续期

### 登录安全

- 单管理员，首次登录强制设密：12 位起，含大写、小写、数字、符号
- 面板防爆破：密码连错 5 次封 IP 7 天，内网与信任名单豁免
- 2FA（手动开）：开通须输对一次动态码；信任设备——同 IP 同设备凭密码直登，换 IP 或换设备才重新输动态码；改密、关 2FA 时清空信任

### 多服务器

- 所有服务器装同一个包、同一安装命令；首次打开面板二选一：设密码独立用，或填主服务器地址 + 配对码进群控
- 被群控节点本地面板变只读状态页（被谁群控、引擎状态、连接状态、最后联系时间），脱离走主服务器上移除，主服务器彻底没了走节点本地 CLI 兜底
- 添加流程：主服务器生成一次性配对码 → 节点填码连上 → 主服务器首页弹“待添加” → 点确认上线，同时双向白名单生效；无码连接直接拒绝
- 首页：仅有其他服务器接入时出现，卡片式显示各台服务器（当前连接数、今日拉黑次数、监控端口数），点卡片切换到那台服务器的面板；新设备接入时首页出接入提醒
- 节点防护全独立，数据全在各台本地；主服务器只存登记（名字、指纹、在线状态）
- TG 默认走主服务器统一发，可在该服务器设置里切独立通知（切后主服务器不再替它发，防双发）

### 面板升级

- 设置页“版本与升级”：从 GitHub releases 检测新版，点一下升级，失败自动回滚
- 多机时主服务器上点一下可推给全部在线节点，单节点失败不影响其他节点
- 升级完成后自动刷新页面（从 v1.0.2 往后生效），重启后需重新登录

## 部署

### 要求

- Debian / Ubuntu，root，systemd（或 Docker）；架构 arm64 / amd64 自动识别
- 面板默认端口 59188，数据目录 `/var/lib/guijia`，均可配置

### 一键安装（推荐，systemd）

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/GuiJia/main/install-remote.sh | sudo bash
```

脚本会：识别架构 → 从本仓库 releases 拉对应包 + `guijia.service` → 先验 sha256（不过不装）→ 装到 `/usr/local/bin/guijia`、建数据目录、enable + restart → 健康检查并打印面板地址。

重跑即升级（幂等）；旧二进制与旧单元先备份到 `/root/guijia-install/`，重启失败自动还原，不留半装状态。

可配（装前用环境变量传，会写进 `/etc/default/guijia`；传变量时一键命令改用 `sudo -E bash`，否则 sudo 会丢环境变量）：

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/GuiJia/main/install-remote.sh | sudo -E bash
# 钉版本（默认 latest）：GUIJIA_VERSION=v1.0.2；改端口 / 数据目录：GUIJIA_PORT / GUIJIA_DATA_DIR
```

### 首次打开

打开 `http://服务器IP:59188`（端口按实际改），先设管理员密码，再二选一：

- **独立用**：设密码后即为独立面板
- **进群控**：填主服务器地址 + 配对码，加入后本地面板变只读状态页，管理全在主服务器

忘密码用服务器本地 root 命令：

```bash
guijia reset-password
```

### 管理命令（systemd）

```bash
systemctl status guijia
systemctl restart guijia
journalctl -u guijia -f
```

### 手动部署（从 releases 拿包）

```bash
# 从本仓库 releases 下载对应架构包 + guijia.service + SHA256SUMS，验签通过后再装
install -m 0755 guijia-linux-<arm64|amd64> /usr/local/bin/guijia
systemctl restart guijia
```

装完必验：`sha256sum /usr/local/bin/guijia` 与 releases 一致，`systemctl is-active guijia` 为 active，面板本地 `curl http://127.0.0.1:59188/login` 为 200。

### Docker 方式

```bash
docker compose up -d
```

host 网络 + NET_ADMIN 是必需的；不要与 systemd 双跑（同一台机上双跑会抢端口与 nft 表）。Docker 方式细节见 `INSTALL.md`。

### 注意

- 面板重启后内存 session 清空，需重新登录
- 面板升级在设置页“版本与升级”里做，不要手动混用两种升级路径
- 详细安装见 [INSTALL.md](INSTALL.md)，部署细节见 [DEPLOY.md](DEPLOY.md)，设计说明见 [DESIGN.md](DESIGN.md)

## 作者

pal537
