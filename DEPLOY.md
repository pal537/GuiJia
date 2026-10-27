# 龟甲 Linux 通用版 — 部署说明（Oracle，systemd 主实例）

## 一键重部署（已装过一次的机器）

```sh
# 本机交叉编译（须在 src 目录，含 vendor）
cd ~/workspace/guijia/src
GOOS=linux GOARCH=arm64 ~/go-tool/go/bin/go build -trimpath -mod=vendor -o ../guijia-arm64-<日期> .

# 传到服务器并安装（不要只传到 /root/guijia-install 就重启，必须 install 到 /usr/local/bin/guijia）
scp ../guijia-arm64-<日期> vps:/root/guijia-install/
ssh vps "install -m 0755 /root/guijia-install/guijia-arm64-<日期> /usr/local/bin/guijia \
  && systemctl restart guijia && sleep 3 && systemctl is-active guijia"
```

## 关键位置（Oracle）

- 二进制：`/usr/local/bin/guijia`；服务：`guijia.service`；面板默认端口：59188
- 数据目录：`/var/lib/guijia`（设置、证书、封禁、事件、统计全在这里）
- 面板管理的 nginx vhost：`/etc/nginx/conf.d/guijia-proxy.conf`（ACME 常驻块 `guijia-acme-default.conf` 绝不能动）
- 证书续期自动 reload：`/root/guijia-install/nginx-cert-reload.sh` + root cron 每天 03:30

## 验证（部署后必做）

1. `sha256sum /usr/local/bin/guijia` 与本地构建一致，`systemctl is-active guijia` 为 active
2. 面板本地 `curl http://127.0.0.1:59188/login` 200；公网 `curl --resolve panel.example.com:443:203.0.113.10 https://panel.example.com/login` 200
3. `nginx -t` 通过；`journalctl -u guijia` 无错误
4. 注意：面板重启后内存 session 清空，需重新登录

## 回滚

上一个二进制仍在 `/root/guijia-install/guijia-arm64-*`，按同样 install + restart 步骤装回即可。

## 说明

- Docker 方式只验证构建、不与 systemd 主实例双跑（Dockerfile 在仓库根目录）。
- 源码构建前先跑 `go build ./... && go vet ./... && go test ./...` 与 `smoke-test.sh`（干跑）。
