# 龟甲安全防护 Linux 通用版 — 安装

systemd 与 Docker 二选一, 不要双跑(同一台机上 systemd 与 Docker 同时跑会抢端口与 nft 表)。
systemd 安装有远程一键与本地两种拿包方式, 装出来是同一个服务。

## 方式一: 远程一键安装(systemd, 推荐)

要求: Debian/Ubuntu, root。推 GitHub pal537/GuiJia 后可用(此前 releases 不存在, 拉不到包)。

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/GuiJia/main/install-remote.sh | sudo bash
```

脚本会: `uname -m` 识别架构(arm64 / amd64) → 从 pal537/GuiJia releases 拉对应包
+ guijia.service → 先验 sha256(不过不装) → 拷二进制到 /usr/local/bin/guijia、
建 /var/lib/guijia、装服务并 enable + restart → 健康检查并打印面板地址。
重跑即升级(幂等), 旧二进制与旧单元先备份到 /root/guijia-install/,
重启失败自动还原并报错, 不留半装状态。

Release 资产命名(固定, 面板升级功能复用同一套):
`guijia-linux-arm64` / `guijia-linux-amd64` / `guijia.service` / `SHA256SUMS`。

可配(装前用环境变量传, 会写进 /etc/default/guijia, 服务下次启动生效;
传变量时一键命令改用 `sudo -E bash`, 否则 sudo 会丢环境变量):

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/GuiJia/main/install-remote.sh | sudo -E bash
# 钉版本(默认 latest): GUIJIA_VERSION=v1.0；改端口/数据目录: GUIJIA_PORT / GUIJIA_DATA_DIR
```

装完管理与首次登录见下方“首次登录”一节。

## 方式二: 本地安装(systemd)

要求: Debian/Ubuntu, root。

```bash
# 把 guijia 二进制、install.sh、guijia.service 放同一目录, root 执行:
./install.sh
```

脚本会: 验 root 与 Debian 系、装 nftables/conntrack/iproute2/ca-certificates、
把二进制拷到 /usr/local/bin/guijia、建 /var/lib/guijia、装服务并 enable + restart。
装完打印面板地址(实测 IP + 实际端口)。重跑脚本可覆盖升级(幂等)。

可配(装前用环境变量传, 会写进 /etc/default/guijia, 服务下次启动生效):

```bash
GUIJIA_PORT=59188 GUIJIA_DATA_DIR=/var/lib/guijia ./install.sh
```

装完管理:

```bash
systemctl status guijia
systemctl restart guijia
journalctl -u guijia -f
```

## 方式三: Docker 安装

要求: 已装 git、Docker 与 docker compose 插件, root(或 docker 组)跑容器。仓库目前没有发布 Docker Hub 镜像, 所以 Docker 方式是本地构建, 一条命令拉仓库 + 构建 + 启动:

```bash
git clone https://github.com/pal537/GuiJia.git && cd GuiJia && docker compose up -d --build
```

compose 说明(host 网络 + NET_ADMIN 是必需的, 见 docker-compose.yml 内注释):

- 面板端口: `GUIJIA_PORT=59188 docker compose up -d`(host 网络下即宿主机端口)。
- 数据目录: `GUIJIA_DATA_DIR=/srv/guijia docker compose up -d`(默认 ./guijia-data),
  容器内固定 /var/lib/guijia。
- 面板地址: `http://服务器IP:59188`(端口按实际改)。

Docker 方式注意事项:

- CLI 改密/关 SSL 后, CLI 提示的"手动重启"即 `docker restart guijia`。
- 宿主机 SSH 日志探测: 容器默认读容器内 /var/log; 如需探测宿主机 auth.log,
  另行只读挂载 `-v /var/log:/var/log:ro`(默认不挂)。
- 蜜罐默认关闭; Docker 方式下蜜罐的 docker 容器探测不可用(未挂 docker.sock)。
- ss 的进程归属在容器 PID 命名空间下可能看不到宿主机进程名, 不影响连接监控与封禁。

管理:

```bash
docker compose logs -f
docker restart guijia
docker compose down
```

## 首次登录

无论哪种方式, 首次打开面板都会强制设管理员密码(12 位起, 含大写+小写+数字+符号,
两次确认)。密码由你自己设, 忘密码用服务器本地 root 命令:

```bash
# systemd 方式: guijia reset-password
# Docker 方式: docker exec guijia guijia reset-password
```

面板默认端口 59188(可配置)。证书申请、反代、2FA 等见 DESIGN.md。
