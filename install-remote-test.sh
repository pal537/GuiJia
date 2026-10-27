#!/bin/bash
# install-remote.sh 本地测试（无需 root、无需 systemd、无需真实网络）。
# 用法：./install-remote-test.sh
# 覆盖：bash 语法、架构映射、版本归一化、URL 拼装、sha 验签、端口/数据目录解析、
# 干跑输出、本地假 release 站的下载 + 验签（通过与篡改两种情况）。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 先 source 被测脚本（只定义函数，不跑 main），随后关掉 -e/-u，让失败用例可断言。
GUIJIA_SOURCE_ONLY=1
# shellcheck disable=SC1091
source "$SCRIPT_DIR/install-remote.sh"
set +eu

PASS=0
FAIL=0
ok() { # ok <描述> <实际> <期望>
  if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "PASS: $1";
  else FAIL=$((FAIL + 1)); echo "FAIL: $1（期望 [$3]，实际 [$2]）"; fi
}
ok_rc() { # ok_rc <描述> <实际退出码> <期望退出码>
  if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "PASS: $1";
  else FAIL=$((FAIL + 1)); echo "FAIL: $1（期望退出码 $3，实际 $2）"; fi
}
ok_contains() { # ok_contains <描述> <文本> <子串>
  case "$2" in
    *"$3"*) PASS=$((PASS + 1)); echo "PASS: $1" ;;
    *) FAIL=$((FAIL + 1)); echo "FAIL: $1（输出里没有 [$3]）" ;;
  esac
}

# 1. bash 语法。
bash -n "$SCRIPT_DIR/install-remote.sh"; ok_rc "bash -n install-remote.sh" "$?" 0
bash -n "$SCRIPT_DIR/install-remote-test.sh"; ok_rc "bash -n install-remote-test.sh" "$?" 0

# 2. 架构映射。
ok "map_arch aarch64" "$(map_arch aarch64)" "arm64"
ok "map_arch arm64" "$(map_arch arm64)" "arm64"
ok "map_arch x86_64" "$(map_arch x86_64)" "amd64"
ok "map_arch amd64" "$(map_arch amd64)" "amd64"
map_arch riscv64 >/dev/null 2>&1; ok_rc "map_arch riscv64 失败" "$?" 1
map_arch wasm32 >/dev/null 2>&1; ok_rc "map_arch wasm32 失败" "$?" 1

# 3. 版本归一化与 URL 拼装。
ok "normalize_version 空" "$(normalize_version "")" "latest"
ok "normalize_version latest" "$(normalize_version latest)" "latest"
ok "normalize_version v1.0" "$(normalize_version v1.0)" "v1.0"
ok "normalize_version 1.0 补 v" "$(normalize_version 1.0)" "v1.0"
unset GUIJIA_BASE_URL GUIJIA_VERSION
ok "release_base 默认 latest" "$(release_base)" "https://github.com/pal537/GuiJia/releases/latest/download"
GUIJIA_VERSION=1.0
ok "release_base 钉版本" "$(release_base)" "https://github.com/pal537/GuiJia/releases/download/v1.0"
GUIJIA_VERSION=v2.3
ok "asset_url 钉版本" "$(asset_url guijia-linux-arm64)" "https://github.com/pal537/GuiJia/releases/download/v2.3/guijia-linux-arm64"
GUIJIA_BASE_URL="http://127.0.0.1:18765/"
ok "release_base 覆盖去尾斜杠" "$(release_base)" "http://127.0.0.1:18765"
ok "asset_url 覆盖" "$(asset_url guijia-linux-amd64)" "http://127.0.0.1:18765/guijia-linux-amd64"
unset GUIJIA_BASE_URL GUIJIA_VERSION

# 4. sha 验签（真 sha256sum 生成的校验文件）。
TMP="$(mktemp -d)"
printf 'fake-binary-content' > "$TMP/guijia-linux-arm64"
cp "$SCRIPT_DIR/guijia.service" "$TMP/guijia.service"
(cd "$TMP" && sha256sum guijia-linux-arm64 guijia.service > SHA256SUMS)
verify_sha "$TMP/guijia-linux-arm64" "$TMP/SHA256SUMS" "guijia-linux-arm64"; ok_rc "verify_sha 通过" "$?" 0
verify_sha "$TMP/guijia.service" "$TMP/SHA256SUMS" "guijia.service"; ok_rc "verify_sha 服务单元通过" "$?" 0
printf 'tampered' > "$TMP/bad"
verify_sha "$TMP/bad" "$TMP/SHA256SUMS" "guijia-linux-arm64" 2>/dev/null; ok_rc "verify_sha 篡改失败" "$?" 1
verify_sha "$TMP/guijia-linux-arm64" "$TMP/SHA256SUMS" "不存在的文件" 2>/dev/null; ok_rc "verify_sha 缺条目失败" "$?" 1

# 5. 端口 / 数据目录解析：环境变量 > 文件 > 默认值。
unset GUIJIA_PORT GUIJIA_DATA_DIR
GUIJIA_ENV_FILE="$TMP/nonexistent"
out="$(resolve_port_data)"
ok "解析 默认端口" "$(echo "$out" | sed -n 1p)" "59188"
ok "解析 默认数据目录" "$(echo "$out" | sed -n 2p)" "/var/lib/guijia"
printf 'GUIJIA_PORT=18081\nGUIJIA_DATA_DIR=/tmp/y\n' > "$TMP/envfile"
GUIJIA_ENV_FILE="$TMP/envfile"
out="$(resolve_port_data)"
ok "解析 文件端口" "$(echo "$out" | sed -n 1p)" "18081"
ok "解析 文件数据目录" "$(echo "$out" | sed -n 2p)" "/tmp/y"
GUIJIA_PORT=18080 GUIJIA_DATA_DIR=/tmp/x
out="$(resolve_port_data)"
ok "解析 环境变量胜过文件" "$(echo "$out" | sed -n 1p)" "18080"
ok "解析 环境变量数据目录" "$(echo "$out" | sed -n 2p)" "/tmp/x"
unset GUIJIA_PORT GUIJIA_DATA_DIR GUIJIA_ENV_FILE

# 6. 干跑（不下载、不写东西、不要求 root）。
out="$(GUIJIA_DRY_RUN=1 GUIJIA_ARCH=arm64 GUIJIA_PORT=18082 GUIJIA_DATA_DIR=/tmp/z bash "$SCRIPT_DIR/install-remote.sh" 2>&1)"; rc=$?
ok_rc "干跑退出码" "$rc" 0
ok_contains "干跑 架构" "$out" "架构: arm64"
ok_contains "干跑 二进制 URL" "$out" "https://github.com/pal537/GuiJia/releases/latest/download/guijia-linux-arm64"
ok_contains "干跑 端口" "$out" "端口: 18082"
ok_contains "干跑 数据目录" "$out" "数据目录: /tmp/z"
GUIJIA_DRY_RUN=1 GUIJIA_ARCH=wasm32 bash "$SCRIPT_DIR/install-remote.sh" >/dev/null 2>&1; ok_rc "干跑 未知架构失败" "$?" 1

# 7. 本地假 release 站：下载 + 验签全链路（DOWNLOAD_ONLY，不安装）。
FIXTURE="$(mktemp -d)"
printf 'fake-guijia-binary-arm64' > "$FIXTURE/guijia-linux-arm64"
cp "$SCRIPT_DIR/guijia.service" "$FIXTURE/guijia.service"
(cd "$FIXTURE" && sha256sum guijia-linux-arm64 guijia.service > SHA256SUMS)
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$FIXTURE" >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$TMP" "$FIXTURE"' EXIT
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PORT/SHA256SUMS" >/dev/null 2>&1 && break
  sleep 0.1
done
out="$(GUIJIA_BASE_URL="http://127.0.0.1:$PORT" GUIJIA_ARCH=arm64 GUIJIA_DOWNLOAD_ONLY=1 bash "$SCRIPT_DIR/install-remote.sh" 2>&1)"; rc=$?
ok_rc "假站下载+验签退出码" "$rc" 0
ok_contains "假站下载+验签输出" "$out" "校验通过"
ok_contains "假站下载+验签未安装" "$out" "未安装"
# 篡改校验文件：必须失败，且不安装任何东西。
printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  guijia-linux-arm64\n' > "$FIXTURE/SHA256SUMS"
GUIJIA_BASE_URL="http://127.0.0.1:$PORT" GUIJIA_ARCH=arm64 GUIJIA_DOWNLOAD_ONLY=1 bash "$SCRIPT_DIR/install-remote.sh" >/dev/null 2>&1; ok_rc "假站篡改后下载失败" "$?" 1

echo "----"
echo "PASS: $PASS, FAIL: $FAIL"
[ "$FAIL" = "0" ]
