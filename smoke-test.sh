#!/bin/bash
# 龟甲 Linux 通用版本地冒烟脚本(开发机用, 不动系统防火墙与内核状态)。
# 覆盖: 未登录 401、弱密码拒绝、设密/登录/登出、2FA 全流程、端口模式 TLS 监听。
# 数据目录与二进制都在 /tmp, 跑完清理。DRYBAN=1, 流量统计预先关闭。
set -u
cd "$(dirname "$0")/src" || exit 1
GO=$HOME/go-tool/go/bin/go
BIN=/tmp/guijia-smoke-bin
rm -rf "$BIN" /tmp/guijia-smoke-a /tmp/guijia-smoke-b
mkdir -p "$BIN"
$GO build -o "$BIN/guijia" . || exit 1

fail=0
ck() { # ck <描述> <实际> <期望>
  if [ "$2" = "$3" ]; then echo "PASS: $1 ($2)"; else echo "FAIL: $1 (实际 $2, 期望 $3)"; fail=1; fi
}
jcode() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

# ---------- Phase A: HTTP 登录流程 ----------
DA=/tmp/guijia-smoke-a
mkdir -p "$DA"
echo '{"trafficAcct":false}' > "$DA/settings.json"
GUIJIA_DATA_DIR=$DA GUIJIA_PORT=15988 GUIJIA_DRYBAN=1 "$BIN/guijia" > /tmp/smoke-a.log 2>&1 &
PIDA=$!
trap 'kill $PIDA 2>/dev/null; kill $PIDB 2>/dev/null' EXIT
for i in $(seq 1 50); do
  if curl -s -o /dev/null http://127.0.0.1:15988/api/auth/status; then break; fi
  sleep 0.2
done
B=http://127.0.0.1:15988
JAR=/tmp/smoke-jar.txt; rm -f "$JAR"
ck "未登录 overview 应 401" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/overview)" "401"
ck "弱密码设密应 400" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/auth/setup -H 'Content-Type: application/json' -d '{"password":"weak","confirm":"weak"}')" "400"
ck "强密码设密应 200" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/auth/setup -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","confirm":"StrongPass1!xx"}')" "200"
ck "重复设密应 403" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/auth/setup -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","confirm":"StrongPass1!xx"}')" "403"
ck "错密码登录应 401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"password":"WrongPass1!xx","remember":false}')" "401"
ck "正确登录应 200" "$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","remember":false}')" "200"
ck "登录后 overview 应 200" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" $B/api/overview)" "200"
ck "登出应 200" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST $B/api/auth/logout -H 'Content-Type: application/json' -d '{}')" "200"
ck "登出后 overview 应 401" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" $B/api/overview)" "401"
# 2FA 全流程
curl -s -c "$JAR" -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","remember":false}' > /dev/null
SECRET=$(curl -s -b "$JAR" -X POST $B/api/auth/totp/setup -H 'Content-Type: application/json' -d '{}' | jcode secret)
if [ -z "$SECRET" ]; then echo "FAIL: 获取 2FA 密钥为空"; fail=1; else echo "PASS: 获取 2FA 密钥"; fi
totp() {
  python3 - "$SECRET" <<'PYEOF'
import hmac, hashlib, base64, struct, time, sys
key = base64.b32decode(sys.argv[1])
msg = struct.pack(">Q", int(time.time()) // 30)
h = hmac.new(key, msg, hashlib.sha1).digest()
off = h[-1] & 0x0f
print("%06d" % ((struct.unpack(">I", h[off:off+4])[0] & 0x7fffffff) % 1000000))
PYEOF
}
CODE=$(totp)
ck "2FA 错码开通应 401" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST $B/api/auth/totp/enable -H 'Content-Type: application/json' -d '{"code":"000000"}')" "401"
ENABLERESP=$(curl -s -b "$JAR" -X POST $B/api/auth/totp/enable -H 'Content-Type: application/json' -d "{\"code\":\"$CODE\"}")
RC1=$(echo "$ENABLERESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recoveryCodes',[''])[0])" 2>/dev/null)
NRC=$(echo "$ENABLERESP" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('recoveryCodes',[])))" 2>/dev/null)
ck "2FA 对码开通应返回 10 个恢复码" "$NRC" "10"
curl -s -b "$JAR" -X POST $B/api/auth/logout -H 'Content-Type: application/json' -d '{}' > /dev/null
LOGIN2=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","remember":false}')
NEED2FA=$(echo "$LOGIN2" | jcode need2fa)
PENDING=$(echo "$LOGIN2" | jcode pending)
ck "2FA 开通后登录应返回 need2fa" "$NEED2FA" "True"
ck "2FA 错码验证应 401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/auth/totp/verify -H 'Content-Type: application/json' -d "{\"pending\":\"$PENDING\",\"code\":\"000000\"}")" "401"
LOGIN3=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","remember":false}')
PENDING3=$(echo "$LOGIN3" | jcode pending)
CODE3=$(totp)
ck "2FA 对码验证应 200" "$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST $B/api/auth/totp/verify -H 'Content-Type: application/json' -d "{\"pending\":\"$PENDING3\",\"code\":\"$CODE3\"}")" "200"
ck "2FA 登录后 overview 应 200" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" $B/api/overview)" "200"
# 恢复码路径
curl -s -b "$JAR" -X POST $B/api/auth/logout -H 'Content-Type: application/json' -d '{}' > /dev/null
LOGIN4=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","remember":false}')
PENDING4=$(echo "$LOGIN4" | jcode pending)
ck "恢复码验证应 200" "$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST $B/api/auth/totp/verify -H 'Content-Type: application/json' -d "{\"pending\":\"$PENDING4\",\"code\":\"$RC1\"}")" "200"
LOGIN5=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"password":"StrongPass1!xx","remember":false}')
PENDING5=$(echo "$LOGIN5" | jcode pending)
ck "用过的恢复码应 401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/auth/totp/verify -H 'Content-Type: application/json' -d "{\"pending\":\"$PENDING5\",\"code\":\"$RC1\"}")" "401"
kill $PIDA 2>/dev/null; wait $PIDA 2>/dev/null

# ---------- Phase B: 端口模式 TLS ----------
DB=/tmp/guijia-smoke-b
mkdir -p "$DB/certs"
openssl req -x509 -newkey rsa:2048 -keyout "$DB/certs/example.key" -out "$DB/certs/example.crt" -days 2 -nodes -subj "/CN=localhost" > /dev/null 2>&1
echo '{"trafficAcct":false,"panelSslMode":"port","panelSslCert":"upload:example","panelSslPort":15989}' > "$DB/settings.json"
GUIJIA_DATA_DIR=$DB GUIJIA_PORT=15988 GUIJIA_DRYBAN=1 "$BIN/guijia" > /tmp/smoke-b.log 2>&1 &
PIDB=$!
for i in $(seq 1 50); do
  if curl -sk -o /dev/null https://127.0.0.1:15989/api/auth/status; then break; fi
  sleep 0.2
done
HTTPOLD=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:15988/api/auth/status 2>/dev/null || true)
if [ "$HTTPOLD" = "000" ]; then echo "PASS: 端口模式 HTTP 原端口应拒绝连接 (000)"; else echo "FAIL: 端口模式 HTTP 原端口应拒绝连接 (实际 $HTTPOLD)"; fail=1; fi
TLSSTATUS=$(curl -sk https://127.0.0.1:15989/api/auth/status)
ck "端口模式 HTTPS 应 200 且未设密" "$(echo "$TLSSTATUS" | jcode setupRequired)" "True"
kill $PIDB 2>/dev/null; wait $PIDB 2>/dev/null
trap - EXIT

rm -rf "$BIN" /tmp/guijia-smoke-a /tmp/guijia-smoke-b /tmp/smoke-jar.txt /tmp/smoke-a.log /tmp/smoke-b.log
if [ "$fail" = 0 ]; then echo "SMOKE ALL PASS"; exit 0; else echo "SMOKE FAILED"; exit 1; fi
