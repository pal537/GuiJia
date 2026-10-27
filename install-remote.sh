#!/bin/bash
# 龟甲安全防护 Linux 通用版一键安装脚本（远程版，Debian/Ubuntu，root 运行）。
#
# 一键命令（推 GitHub pal537/GuiJia 后可用）：
#   curl -fsSL https://raw.githubusercontent.com/pal537/GuiJia/main/install-remote.sh | sudo bash
#
# 行为：uname -m 识别架构 → 从 pal537/GuiJia releases 拉对应包 + guijia.service
# → 先验 sha256（不过不装）→ 装 /usr/local/bin/guijia + systemd 单元 → enable + restart
# → 健康检查 → 打印面板地址。首次打开面板二选一（独立用 / 进群控），脚本不管模式选择。
#
# 与本地 install.sh 的区别：本地版要求二进制与脚本、service 在同一目录；
# 本脚本自己从 releases 下载，同一安装命令适用所有服务器（多服务器定稿方案）。
#
# 幂等：重跑即升级。旧二进制与旧单元先备份到 /root/guijia-install/，
# 重启失败自动还原备份并报错退出，不留半装状态。
#
# Release 资产命名（固定，面板升级功能复用同一套）：
#   guijia-linux-arm64 / guijia-linux-amd64 / guijia.service / SHA256SUMS
# 版本：GUIJIA_VERSION，默认 latest；v1.0 或 1.0 均可（缺 v 自动补）。
#
# 环境变量：
#   GUIJIA_VERSION   版本（默认 latest）
#   GUIJIA_PORT      面板端口（默认 59188；重跑不传则沿用 /etc/default/guijia）
#   GUIJIA_DATA_DIR  数据目录（默认 /var/lib/guijia；同上）
#   GUIJIA_ARCH      覆盖架构检测（仅测试/排障：arm64 或 amd64）
#   GUIJIA_BASE_URL  覆盖下载基址（仅测试：此时按“基址/资产名”直接取文件）
#   GUIJIA_ENV_FILE  覆盖环境文件路径（仅测试，默认 /etc/default/guijia）
#   GUIJIA_DRY_RUN=1       只打印计划，不下载、不写任何东西
#   GUIJIA_DOWNLOAD_ONLY=1 只下载 + 验签，不安装（用于无 root / 无 systemd 的验证）
# 测试时 source 本文件：GUIJIA_SOURCE_ONLY=1 source install-remote.sh，然后直接调函数。
set -euo pipefail

REPO="pal537/GuiJia"
DEFAULT_PORT="59188"
DEFAULT_DATA_DIR="/var/lib/guijia"
BIN_DST="/usr/local/bin/guijia"
UNIT_DST="/etc/systemd/system/guijia.service"
ENV_FILE_DEFAULT="/etc/default/guijia"
BACKUP_DIR="/root/guijia-install"

die() { echo "错误: $*" >&2; exit 1; }

# 架构映射：uname -m（或 GUIJIA_ARCH）→ arm64 / amd64；未知则返回非零。
map_arch() {
  local m="${1:-$(uname -m)}"
  case "$m" in
    aarch64|arm64) echo "arm64" ;;
    x86_64|amd64) echo "amd64" ;;
    *) return 1 ;;
  esac
}

# 版本归一化：空或 latest → latest；缺 v 的数字版补 v。
normalize_version() {
  local v="${1:-}"
  case "$v" in
    ""|latest) echo "latest" ;;
    v*) echo "$v" ;;
    *) echo "v$v" ;;
  esac
}

# 下载基址：GUIJIA_BASE_URL 覆盖时直接用它；否则按版本拼 GitHub releases 地址。
release_base() {
  if [ -n "${GUIJIA_BASE_URL:-}" ]; then
    echo "${GUIJIA_BASE_URL%/}"
    return
  fi
  local v
  v="$(normalize_version "${GUIJIA_VERSION:-}")"
  if [ "$v" = "latest" ]; then
    echo "https://github.com/${REPO}/releases/latest/download"
  else
    echo "https://github.com/${REPO}/releases/download/${v}"
  fi
}

# 资产 URL。
asset_url() { echo "$(release_base)/$1"; }

# 验签：按 SHA256SUMS 里 name 对应的行比对文件实际 sha256；不符返回非零。
verify_sha() {
  local file="$1" sums="$2" name="$3" expected actual
  expected="$(awk -v n="$name" '{sub(/^\*/, "", $2); if ($2 == n) print $1}' "$sums" | head -n 1)"
  [ -n "$expected" ] || { echo "错误: SHA256SUMS 里没有 $name" >&2; return 1; }
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "错误: $name 校验失败（期望 $expected，实际 $actual）" >&2
    return 1
  fi
}

# 端口与数据目录解析：环境变量 > 已有环境文件 > 默认值（与本地 install.sh 同语义）。
# 输出两行：第一行端口，第二行数据目录。环境文件不可读时跳过（用默认值）。
resolve_port_data() {
  local env_file="${GUIJIA_ENV_FILE:-$ENV_FILE_DEFAULT}"
  local env_port="${GUIJIA_PORT:-}" env_data="${GUIJIA_DATA_DIR:-}"
  local file_port="" file_data=""
  if [ -r "$env_file" ]; then
    # 只读两个已知键，不执行文件其余内容。
    file_port="$(grep -E '^GUIJIA_PORT=' "$env_file" | tail -n 1 | cut -d= -f2- || true)"
    file_data="$(grep -E '^GUIJIA_DATA_DIR=' "$env_file" | tail -n 1 | cut -d= -f2- || true)"
  fi
  echo "${env_port:-${file_port:-$DEFAULT_PORT}}"
  echo "${env_data:-${file_data:-$DEFAULT_DATA_DIR}}"
}

main() {
  local arch asset bin_url svc_url sums_url
  if [ -n "${GUIJIA_ARCH:-}" ]; then
    arch="$(map_arch "$GUIJIA_ARCH")" || die "不支持的架构: $GUIJIA_ARCH（仅 arm64 / amd64）"
  else
    arch="$(map_arch)" || die "不支持的架构: $(uname -m)（仅 arm64 / amd64）"
  fi
  asset="guijia-linux-${arch}"
  bin_url="$(asset_url "$asset")"
  svc_url="$(asset_url "guijia.service")"
  sums_url="$(asset_url "SHA256SUMS")"

  # 干跑：只打印计划，不下载、不写东西、不要求 root。
  if [ "${GUIJIA_DRY_RUN:-}" = "1" ]; then
    local port data_dir
    port="$(resolve_port_data | sed -n 1p)"
    data_dir="$(resolve_port_data | sed -n 2p)"
    echo "架构: $arch"
    echo "二进制: $bin_url"
    echo "服务单元: $svc_url"
    echo "校验文件: $sums_url"
    echo "安装到: $BIN_DST"
    echo "单元到: $UNIT_DST"
    echo "端口: $port"
    echo "数据目录: $data_dir"
    return 0
  fi

  # 下载 + 验签：先验过才动系统，验不过直接退出，什么都不改。
  local tmp
  tmp="$(mktemp -d)"
  # 注意：trap 字符串在退出时才展开，而那时 main 的局部变量已销毁；
  # 必须在设 trap 时就把路径 baked 进去，否则 rm -rf "" 会让成功安装也返回 1。
  trap "rm -rf '$tmp'" EXIT
  echo "下载 $asset ..."
  curl -fsSL -o "$tmp/$asset" "$bin_url" || die "下载失败: $bin_url"
  curl -fsSL -o "$tmp/guijia.service" "$svc_url" || die "下载失败: $svc_url"
  curl -fsSL -o "$tmp/SHA256SUMS" "$sums_url" || die "下载失败: $sums_url"
  verify_sha "$tmp/$asset" "$tmp/SHA256SUMS" "$asset" || die "二进制校验失败，已中止，未改动系统"
  verify_sha "$tmp/guijia.service" "$tmp/SHA256SUMS" "guijia.service" || die "服务单元校验失败，已中止，未改动系统"
  echo "校验通过。"

  # 仅下载模式：到此为止，不安装（无 root / 无 systemd 也能跑）。
  if [ "${GUIJIA_DOWNLOAD_ONLY:-}" = "1" ]; then
    echo "已下载并验签（未安装）:"
    echo "  $tmp/$asset"
    echo "  $tmp/guijia.service"
    return 0
  fi

  # 以下需要 root + Debian 系 + systemd。
  if [ "$(id -u)" -ne 0 ]; then
    die "请用 root 运行"
  fi
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  else
    die "无法识别系统（缺少 /etc/os-release），仅支持 Debian/Ubuntu"
  fi
  case "${ID:-}" in
    debian|ubuntu) ;;
    *)
      case "${ID_LIKE:-}" in
        *debian*) ;;
        *) die "仅支持 Debian/Ubuntu，当前系统: ${ID:-未知}" ;;
      esac
      ;;
  esac
  command -v systemctl >/dev/null 2>&1 || die "未找到 systemctl，仅支持 systemd 的 Debian/Ubuntu"

  local port data_dir
  port="$(resolve_port_data | sed -n 1p)"
  data_dir="$(resolve_port_data | sed -n 2p)"

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y nftables conntrack iproute2 ca-certificates curl

  # 备份旧二进制与旧单元（存在才备），重启失败时还原。
  local ts backup_bin="" backup_unit=""
  ts="$(date +%Y%m%d%H%M%S)"
  mkdir -p "$BACKUP_DIR"
  if [ -f "$BIN_DST" ]; then
    backup_bin="$BACKUP_DIR/guijia-backup-$ts"
    cp -a "$BIN_DST" "$backup_bin"
  fi
  if [ -f "$UNIT_DST" ]; then
    backup_unit="$BACKUP_DIR/guijia.service-backup-$ts"
    cp -a "$UNIT_DST" "$backup_unit"
  fi

  install -m 0755 "$tmp/$asset" "$BIN_DST"
  mkdir -p "$data_dir"
  printf 'GUIJIA_PORT=%s\nGUIJIA_DATA_DIR=%s\n' "$port" "$data_dir" > "${GUIJIA_ENV_FILE:-$ENV_FILE_DEFAULT}"
  install -m 0644 "$tmp/guijia.service" "$UNIT_DST"
  systemctl daemon-reload
  systemctl enable guijia
  systemctl restart guijia

  # 健康检查：没起来就还原备份并报错，不留半装状态。
  sleep 2
  if ! systemctl is-active --quiet guijia; then
    echo "服务启动失败，正在还原备份..." >&2
    if [ -n "$backup_bin" ]; then
      install -m 0755 "$backup_bin" "$BIN_DST"
    fi
    if [ -n "$backup_unit" ]; then
      install -m 0644 "$backup_unit" "$UNIT_DST"
    fi
    systemctl daemon-reload || true
    systemctl restart guijia || true
    die "安装已回滚，请看日志: journalctl -u guijia -n 100"
  fi

  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ip="${ip:-127.0.0.1}"
  echo "安装完成。"
  echo "面板地址: http://${ip}:${port}"
  echo "首次打开请设置管理员密码（12 位起，含大写、小写、数字、符号）。"
  echo "证书出问题进不去时，服务器本地 root 执行: guijia cert-off"
}

if [ "${GUIJIA_SOURCE_ONLY:-}" != "1" ]; then
  main "$@"
fi
