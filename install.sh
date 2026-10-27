#!/bin/bash
# 龟甲安全防护 Linux 通用版安装脚本(Debian/Ubuntu, root 运行)。
# 用法: 把 guijia 二进制与本脚本、guijia.service 放同一目录, root 执行 ./install.sh。
# 只写文件与系统服务, 不改动现有业务服务; 覆盖安装会重启服务以加载新二进制。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行: sudo ./install.sh" >&2
  exit 1
fi

# 仅 Debian 系
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  echo "无法识别系统(缺少 /etc/os-release), 仅支持 Debian/Ubuntu" >&2
  exit 1
fi
case "${ID:-}" in
  debian|ubuntu) ;;
  *)
    case "${ID_LIKE:-}" in
      *debian*) ;;
      *)
        echo "仅支持 Debian/Ubuntu, 当前系统: ${ID:-未知}" >&2
        exit 1
        ;;
    esac
    ;;
esac

DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$DIR/guijia" ]; then
  echo "同目录下未找到 guijia 二进制, 请把二进制与本脚本放一起" >&2
  exit 1
fi
if [ ! -f "$DIR/guijia.service" ]; then
  echo "同目录下未找到 guijia.service" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "未找到 systemctl, 仅支持 systemd 的 Debian/Ubuntu" >&2
  exit 1
fi

# 端口与数据目录: 环境变量传入优先, 否则沿用已有的 /etc/default/guijia, 否则默认值。
# 重跑脚本不传变量时沿用旧配置, 不会把改过的端口/目录悄悄改回去。
ENV_PORT="${GUIJIA_PORT:-}"
ENV_DATA="${GUIJIA_DATA_DIR:-}"
if [ -f /etc/default/guijia ]; then
  # shellcheck disable=SC1091
  . /etc/default/guijia
fi
PORT="${ENV_PORT:-${GUIJIA_PORT:-59188}}"
DATA_DIR="${ENV_DATA:-${GUIJIA_DATA_DIR:-/var/lib/guijia}}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nftables conntrack iproute2 ca-certificates

install -m 0755 "$DIR/guijia" /usr/local/bin/guijia
mkdir -p "$DATA_DIR"
printf 'GUIJIA_PORT=%s\nGUIJIA_DATA_DIR=%s\n' "$PORT" "$DATA_DIR" > /etc/default/guijia
install -m 0644 "$DIR/guijia.service" /etc/systemd/system/guijia.service
systemctl daemon-reload
systemctl enable guijia
systemctl restart guijia

# 健康检查: 服务没起来就报错退出, 不让用户对着打不开的地址干等。
sleep 2
if ! systemctl is-active --quiet guijia; then
  echo "服务启动失败, 请看日志: journalctl -u guijia -n 100" >&2
  exit 1
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
IP="${IP:-127.0.0.1}"
echo "安装完成。"
echo "面板地址: http://${IP}:${PORT}"
echo "首次打开请设置管理员密码(12 位起, 含大写、小写、数字、符号)。"
echo "证书出问题进不去时, 服务器本地 root 执行: guijia cert-off"
