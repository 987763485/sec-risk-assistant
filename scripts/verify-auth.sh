#!/usr/bin/env bash
# ============================================================================
# P1 认证与授权守门验证
#
# 覆盖范围：三角色权限矩阵、CSRF 双提交、Cookie 属性、令牌轮换与重放检测、
#           账号锁定、禁用即时生效、最后一个管理员保护、审计落库、登出。
#
# 用法：bash scripts/verify-auth.sh
# 退出码：0 = 全部通过；1 = 存在失败项
#
# 前置条件：MySQL 已启动（make infra）。脚本自行构建并启动 API 服务，
#           结束后自动清理进程、临时文件与临时库。
#
# 数据隔离：本脚本**不碰开发库**。它自建一个临时库 sec_risk_auth_e2e，
#   把后端指过去，退出时整体 DROP。
#
#   历史版本直接跑在开发库 sec_risk 上，每跑一次就往 users 表堆 4 个
#   vassess_*/vaudit_*/vuser_*/vlock_* 账号，还会往 audit_logs 里塞测试
#   记录。「清理」一节只是把账号置为 disabled，行永久留存 —— 那是错的，
#   测试脚本必须自己收尾。改隔离库之后，「清理」不再是打补丁，而是整体销毁。
#
# 端口：用 18081，不用 8080。8080 是本机 dev server 的端口，而脚本启动前会
#   杀掉端口占用者（避免断言打在残留的旧进程上），占 8080 就会顺手把开发者
#   正在跑的后端进程杀掉。verify-asset.sh 用 18080，两者互不冲突。
#
# 说明：登录接口的**来源 IP 限流**不在此脚本验证——脚本本身需要在短时间
#       内发起二十余次登录，与限流阈值直接冲突。限流逻辑由
#       internal/middleware/ratelimit_test.go 的单元测试覆盖，
#       这里通过调高阈值让端到端流程可以完整跑完。
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=18081
BASE="http://127.0.0.1:${PORT}"
BIN="/tmp/secrisk-verify-api"
SRV_LOG="/tmp/secrisk-verify-srv.log"
BODY="/tmp/.sr-verify-body"
HDR="/tmp/.sr-verify-hdr"

# 隔离临时库与引导管理员（见文件头「数据隔离」）
E2E_DB="sec_risk_auth_e2e"
E2E_ADMIN="admin"
E2E_ADMIN_PW="Admin@12345"
E2E_ADMIN_PW_NEW="Admin@2026#verify"

PASS=0
FAIL=0
FAILED_ITEMS=()

if [ -t 1 ]; then
  C_GREEN='\033[32m'; C_RED='\033[31m'; C_DIM='\033[2m'; C_RESET='\033[0m'
else
  C_GREEN=''; C_RED=''; C_DIM=''; C_RESET=''
fi

ok()   { PASS=$((PASS + 1)); printf "  ${C_GREEN}✅${C_RESET} %s\n" "$1"; }
bad()  {
  FAIL=$((FAIL + 1)); FAILED_ITEMS+=("$1")
  printf "  ${C_RED}❌${C_RESET} %s\n" "$1"
  [ -n "${2:-}" ] && printf "     ${C_DIM}%s${C_RESET}\n" "$2"
}
section() { printf "\n${C_DIM}── %s ──${C_RESET}\n" "$1"; }

# ---------------------------------------------------------------- HTTP 工具

LAST_STATUS=0
LAST_CODE=""

# jget <点号路径> — 从 $BODY 中取值
#
# ⚠️ 数据文件路径通过参数传入，而不是用 stdin 重定向。
# 若写成 `python3 - <<'PY' < "$BODY"`，两个 stdin 重定向会互相覆盖，
# python 会把数据文件当脚本读取，函数永远返回空值——静默失效，极难排查。
jget() {
  python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[2], encoding="utf-8"))
except Exception:
    print(""); raise SystemExit
for k in sys.argv[1].split("."):
    if not k:
        continue
    if isinstance(d, list):
        try: d = d[int(k)]
        except Exception: print(""); raise SystemExit
    elif isinstance(d, dict):
        d = d.get(k)
    else:
        print(""); raise SystemExit
    if d is None:
        print(""); raise SystemExit
print(d)
' "$1" "$BODY" 2>/dev/null
}

# req <method> <path> [curl args...]
req() {
  local method="$1" path="$2"; shift 2
  LAST_STATUS=$(curl -sS --noproxy '*' -o "$BODY" -w '%{http_code}' \
    -X "$method" "$BASE$path" "$@" 2>/dev/null)
  LAST_CODE=$(jget code)
  [ -z "$LAST_CODE" ] && LAST_CODE="<no-json>"
}

# expect <描述> <期望状态码> [期望业务码]
expect() {
  local desc="$1" want_status="$2" want_code="${3:-}"
  if [ "$LAST_STATUS" = "$want_status" ] && { [ -z "$want_code" ] || [ "$LAST_CODE" = "$want_code" ]; }; then
    ok "$desc"
  else
    bad "$desc" "期望 HTTP $want_status${want_code:+ / $want_code}，实际 HTTP $LAST_STATUS / $LAST_CODE"
  fi
}

# ---------------------------------------------------------------- 会话工具

# csrf_token <jar> — 取一枚 CSRF 令牌（同时刷新 jar 中的 sr_csrf）
csrf_token() {
  curl -sS --noproxy '*' -c "$1" -b "$1" "$BASE/api/auth/csrf" -o "$BODY" 2>/dev/null
  jget data.csrf_token
}

# login <jar> <user> <pass> — 登录；结果状态写入 LAST_STATUS，
# 并把响应头落盘到 $HDR 供 Cookie 属性断言使用。
#
# ⚠️ 调用时**不要**写成 `X=$(login ...)`：命令替换会让函数在子 shell 中执行，
# 函数内对 LAST_STATUS 的赋值无法传回父 shell，后续断言会读到上一次的残留值，
# 产生「实际失败却报通过」的假绿。需要令牌时请用 login_token。
login() {
  local jar="$1" user="$2" pass="$3"
  local token
  token=$(csrf_token "$jar")
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$jar" -b "$jar" -D "$HDR" -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $token" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# 最近一次 login_token 得到的会话 CSRF 令牌
SESSION_CSRF=""

# login_token <jar> <user> <pass> — 登录并把会话 CSRF 令牌写入 SESSION_CSRF
login_token() {
  login "$1" "$2" "$3"
  SESSION_CSRF=$(jget data.csrf_token)
}

# ---------------------------------------------------------------- 启动与清理

SERVER_PID=""

# env_value <KEY> — 从 .env 读一个值（剥掉引号与行尾 CR）。
# 不用 source：.env 里有带空格的值，直接 source 会在某些行上报错并中断。
env_value() {
  sed -n "s/^$1=//p" "$ROOT/.env" 2>/dev/null | head -1 | tr -d '"'\''' | tr -d '\r'
}

MYSQL_ROOT_PW="$(env_value MYSQL_ROOT_PASSWORD)"
MYSQL_USER_VAL="$(env_value MYSQL_USER)"; MYSQL_USER_VAL="${MYSQL_USER_VAL:-secrisk}"

compose() { docker compose "$@"; }

cleanup() {
  # wait 不只是回收僵尸：少了它 bash 会在退出前额外打印一行
  #   `verify-auth.sh: line 166: 76971 Killed: 9  "$BIN"`
  # 夹在「全部通过」和「已删除临时库」之间，看上去像出了错。
  if [ -n "$SERVER_PID" ]; then
    kill -9 "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  rm -f /tmp/sr-admin.jar /tmp/sr-assessor.jar /tmp/sr-auditor.jar \
        /tmp/sr-victim.jar /tmp/sr-lock.jar /tmp/.sr-probe.jar "$BODY" "$HDR"
  # 整个临时库（账号 + 角色关联 + 审计记录 + 令牌）一起消失。
  # 这才是「自清理」：不是把造出来的数据标记成不可用，而是让它不存在。
  if [ -n "$MYSQL_ROOT_PW" ]; then
    compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
      -e "DROP DATABASE IF EXISTS \`$E2E_DB\`;" >/dev/null 2>&1 \
      && printf "  ${C_DIM}已删除临时库 %s${C_RESET}\n" "$E2E_DB"
  fi
}
trap cleanup EXIT
# Ctrl-C / kill 也要收尾。挂 EXIT 在脚本正常退出与多数信号下都会触发，
# 但若进程正阻塞在等待子命令，bash 会先处理信号；显式把 INT/TERM 转成
# exit，确保 cleanup 一定跑到，不留半个临时库。
trap 'exit 130' INT TERM

# free_port — 清理仍占用端口的残留进程
#
# 不做这一步的后果很隐蔽：新服务启动失败退出，而 curl 会连上那个残留的
# 旧进程，于是全部断言都打在旧代码上——测试看起来跑完了，结论却毫无意义。
free_port() {
  local pids
  pids=$(lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null)
  if [ -n "$pids" ]; then
    printf "${C_DIM}检测到端口 %s 被占用（PID: %s），正在清理${C_RESET}\n" \
      "$PORT" "$(echo "$pids" | tr '\n' ' ')"
    echo "$pids" | xargs kill -9 2>/dev/null
    sleep 1
  fi
}

start_server() {
  echo "── 构建并启动 API 服务 ──"
  ( cd "$ROOT/server" && go build -o "$BIN" ./cmd/api ) || { echo "构建失败"; exit 1; }

  free_port

  # ---- 隔离临时库：先删后建，保证每次都是全新状态
  # 「先删」不是多余的：上一次运行若被 kill -9 打断（EXIT trap 不执行），
  # 这个库会留在磁盘上。先删后建让脚本对任何残留免疫，也顺手把上次的残骸收掉。
  if [ -z "$MYSQL_ROOT_PW" ]; then
    echo "未能从 .env 读取 MYSQL_ROOT_PASSWORD，无法创建隔离临时库"
    exit 1
  fi
  compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" -e \
    "DROP DATABASE IF EXISTS \`$E2E_DB\`;
     CREATE DATABASE \`$E2E_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
     GRANT ALL PRIVILEGES ON \`$E2E_DB\`.* TO '$MYSQL_USER_VAL'@'%';
     FLUSH PRIVILEGES;" >/dev/null 2>&1 || true
  if ! compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
       -e "USE \`$E2E_DB\`;" >/dev/null 2>&1; then
    echo "创建隔离临时库 $E2E_DB 失败，请确认 make infra 已就绪"
    exit 1
  fi
  printf "  ${C_DIM}已创建隔离临时库 %s${C_RESET}\n" "$E2E_DB"

  # shellcheck disable=SC1091
  set -a; source "$ROOT/.env"; set +a
  export SR_SERVER_HOST=127.0.0.1 SR_SERVER_PORT="$PORT" SR_APP_LOG_LEVEL=warn
  # 指向临时库。.env 里的 SR_DATABASE_NAME=sec_risk 是开发库，
  # 这一行是「不污染开发库」的唯一保证 —— 删掉它就会前功尽弃。
  export SR_DATABASE_NAME="$E2E_DB"
  export SR_AUTH_BOOTSTRAP_USERNAME="$E2E_ADMIN"
  export SR_AUTH_BOOTSTRAP_PASSWORD="$E2E_ADMIN_PW"
  # 调高登录限流阈值，理由见文件头说明
  export SR_AUTH_LOGIN_RATE_LIMIT="${SR_VERIFY_LOGIN_RATE_LIMIT:-2000}"

  "$BIN" > "$SRV_LOG" 2>&1 &
  SERVER_PID=$!

  for _ in $(seq 1 60); do
    curl -sS --noproxy '*' -o /dev/null "$BASE/healthz" 2>/dev/null && return 0
    sleep 0.5
  done
  echo "服务启动超时，日志："; tail -20 "$SRV_LOG"; exit 1
}

# ============================================================================
ADMIN_USER="$E2E_ADMIN"
ADMIN_PASS="$E2E_ADMIN_PW"

start_server

# 临时库每次都是空的，admin 必然由引导流程刚刚创建、且带 must_change_password。
# 因此不再需要「两段式探测」——那是跑在开发库上留下的包袱：密码被人改过，
# 脚本只能拿候选值去猜，猜不中就退出让人手工设环境变量。空库方案下这个密码
# 是脚本自己写进去的，不存在不确定性。
echo "管理员账号：$ADMIN_USER"

STAMP="$(date +%s)"
U_ASSESSOR="vassess_${STAMP}"
U_AUDITOR="vaudit_${STAMP}"
U_VICTIM="vuser_${STAMP}"
U_LOCK="vlock_${STAMP}"
PASSWORD='Verify@2026'
PASSWORD2="${PASSWORD}x"

# ============================================================ 1. CSRF
section "1. CSRF 双提交令牌"

req GET /api/auth/csrf
expect "获取 CSRF 令牌" 200

req POST /api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"x"}'
expect "缺少 CSRF 请求头时写请求被拒绝" 403 AUTH_CSRF_INVALID

req POST /api/auth/login -H 'Content-Type: application/json' \
  -H 'X-CSRF-Token: forged-token-value' -d '{"username":"admin","password":"x"}'
expect "CSRF 令牌伪造时被拒绝" 403 AUTH_CSRF_INVALID

req POST /api/auth/login -H 'Content-Type: application/json' \
  -H 'Origin: http://evil.example.com' -d '{"username":"admin","password":"x"}'
expect "不可信 Origin 被拒绝" 403 AUTH_CSRF_INVALID

# 允许的来源应当放行（Origin 白名单命中后仍要靠令牌，所以预期仍是 403）
req POST /api/auth/login -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:5173' -d '{"username":"admin","password":"x"}'
expect "可信 Origin 但缺令牌时仍被拒绝" 403 AUTH_CSRF_INVALID

# ============================================================ 2. 登录与 Cookie
section "2. 登录与会话 Cookie"

login /tmp/sr-admin.jar "$ADMIN_USER" "definitely-wrong-password"
expect "错误密码登录被拒" 401 AUTH_INVALID_CREDENTIALS

login /tmp/sr-admin.jar "$ADMIN_USER" "$ADMIN_PASS"
expect "正确凭据登录成功" 200

AT_LINE=$(grep -i '^set-cookie: sr_at=' "$HDR" | head -1)
RT_LINE=$(grep -i '^set-cookie: sr_rt=' "$HDR" | head -1)
CS_LINE=$(grep -i '^set-cookie: sr_csrf=' "$HDR" | head -1)

case "$AT_LINE" in *HttpOnly*) ok "sr_at 为 httpOnly（XSS 无法窃取）";; *) bad "sr_at 缺少 httpOnly" "${AT_LINE:-未收到该 Cookie}";; esac
case "$RT_LINE" in *HttpOnly*) ok "sr_rt 为 httpOnly";; *) bad "sr_rt 缺少 httpOnly" "${RT_LINE:-未收到该 Cookie}";; esac
case "$RT_LINE" in *"Path=/api/auth"*) ok "sr_rt 限定 Path=/api/auth（业务请求不携带）";; *) bad "sr_rt 路径未限定" "${RT_LINE:-未收到该 Cookie}";; esac
case "$CS_LINE" in *HttpOnly*) bad "sr_csrf 不应为 httpOnly（前端必须能读到）" "$CS_LINE";; *) ok "sr_csrf 未设 httpOnly（双提交前提）";; esac

req GET /api/auth/me
expect "无 Cookie 访问 /api/auth/me" 401

req GET /api/auth/me -b /tmp/sr-admin.jar
expect "已登录访问 /api/auth/me" 200

ADMIN_ID=$(curl -sS --noproxy '*' -b /tmp/sr-admin.jar -o "$BODY" "$BASE/api/auth/me" 2>/dev/null; jget data.user_id)
PERM_COUNT=$(jget data.permissions | tr -c -d ':' | wc -c | tr -d ' ')
if [ "${PERM_COUNT:-0}" -ge 20 ]; then
  ok "管理员权限码已下发（前端动态路由的唯一依据）"
else
  bad "管理员权限码异常" "数量 ${PERM_COUNT:-0}"
fi

# ---- 引导管理员必须先改密 ------------------------------------------------
# 空库首启时 admin 带 must_change_password=1，业务接口一律 403。
# 这一段在旧的「跑开发库」方案里是覆盖不到的（那边的 admin 早被人改过密），
# 换成隔离库反而把它从盲区变成了必测项。
req GET /api/users -b /tmp/sr-admin.jar
expect "管理员未改初始密码时业务接口被拦截" 403 AUTH_MUST_CHANGE_PASSWORD

ADMIN_CSRF=$(csrf_token /tmp/sr-admin.jar)
LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-admin.jar -o "$BODY" -w '%{http_code}' \
  -X PATCH "$BASE/api/auth/password" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $ADMIN_CSRF" \
  -d "{\"old_password\":\"$E2E_ADMIN_PW\",\"new_password\":\"$E2E_ADMIN_PW_NEW\"}" 2>/dev/null)
LAST_CODE=$(jget code)
expect "引导管理员完成强制改密" 200

# 改密会 bump token epoch，旧会话全部失效 —— 必须用新密码重新登录
ADMIN_PASS="$E2E_ADMIN_PW_NEW"
login /tmp/sr-admin.jar "$ADMIN_USER" "$E2E_ADMIN_PW"
expect "改密后旧密码失效" 401 AUTH_INVALID_CREDENTIALS
login /tmp/sr-admin.jar "$ADMIN_USER" "$ADMIN_PASS"
expect "改密后新密码可登录" 200

# ============================================================ 3. 测试账号
section "3. 准备三个角色的测试账号"

login_token /tmp/sr-admin.jar "$ADMIN_USER" "$ADMIN_PASS"
ADMIN_CSRF="$SESSION_CSRF"
[ "$LAST_STATUS" = "200" ] || { echo "管理员登录失败，终止"; tail -10 "$SRV_LOG"; exit 1; }

CREATED_ID=""
create_user() {
  local name="$1" roles="$2"
  LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-admin.jar -o "$BODY" -w '%{http_code}' \
    -X POST "$BASE/api/users" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $ADMIN_CSRF" \
    -d "{\"username\":\"$name\",\"display_name\":\"$name\",\"password\":\"$PASSWORD\",\"roles\":$roles}" 2>/dev/null)
  LAST_CODE=$(jget code)
  CREATED_ID=$(jget data.id)
}

create_user "$U_ASSESSOR" '["assessor"]'; expect "创建评估员账号" 201; ID_ASSESSOR="$CREATED_ID"
create_user "$U_AUDITOR"  '["auditor"]';  expect "创建审计员账号" 201; ID_AUDITOR="$CREATED_ID"
create_user "$U_VICTIM"   '["auditor"]';  expect "创建待禁用账号" 201; ID_VICTIM="$CREATED_ID"
create_user "$U_LOCK"     '["assessor"]'; expect "创建待锁定账号" 201; ID_LOCK="$CREATED_ID"

# 新建账号带 must_change_password，重复创建必须被拒
create_user "$U_ASSESSOR" '["assessor"]'
expect "重复的登录名被拒绝" 409 USER_USERNAME_TAKEN

# ============================================================ 4. 权限矩阵
section "4. 三角色权限矩阵"

# 新账号带强制改密标记，先改密以解锁业务接口
change_pw() {
  local jar="$1" csrf="$2"
  LAST_STATUS=$(curl -sS --noproxy '*' -b "$jar" -o "$BODY" -w '%{http_code}' \
    -X PATCH "$BASE/api/auth/password" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d "{\"old_password\":\"$PASSWORD\",\"new_password\":\"$PASSWORD2\"}" 2>/dev/null)
  LAST_CODE=$(jget code)
}

login_token /tmp/sr-assessor.jar "$U_ASSESSOR" "$PASSWORD"
expect "评估员登录成功" 200
A_CSRF="$SESSION_CSRF"

# 未改密前不得访问业务接口
req GET /api/users -b /tmp/sr-assessor.jar
expect "未改初始密码时业务接口被拦截" 403 AUTH_MUST_CHANGE_PASSWORD

change_pw /tmp/sr-assessor.jar "$A_CSRF"
expect "评估员完成强制改密" 200

login_token /tmp/sr-auditor.jar "$U_AUDITOR" "$PASSWORD"
expect "审计员登录成功" 200
U_CSRF="$SESSION_CSRF"
change_pw /tmp/sr-auditor.jar "$U_CSRF"
expect "审计员完成强制改密" 200

login_token /tmp/sr-assessor.jar "$U_ASSESSOR" "$PASSWORD2"
A_CSRF="$SESSION_CSRF"
login_token /tmp/sr-auditor.jar "$U_AUDITOR" "$PASSWORD2"
U_CSRF="$SESSION_CSRF"
if [ -n "$A_CSRF" ] && [ -n "$U_CSRF" ]; then
  ok "两个测试账号改密后重新登录成功"
else
  bad "测试账号重新登录失败" "assessor=${A_CSRF:0:8} auditor=${U_CSRF:0:8}"
fi

# —— 评估员 ——
req GET /api/users -b /tmp/sr-assessor.jar
expect "评估员 读用户列表（持 user:read）" 200

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-assessor.jar -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/users" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $A_CSRF" \
  -d "{\"username\":\"nope_$STAMP\",\"password\":\"Whatever@2026\",\"roles\":[\"assessor\"]}" 2>/dev/null)
LAST_CODE=$(jget code)
expect "评估员 新建用户被拒（无 user:write）" 403 FORBIDDEN

req GET /api/audit-logs -b /tmp/sr-assessor.jar
expect "评估员 读审计日志被拒（无 audit:read）" 403 FORBIDDEN

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-assessor.jar -o "$BODY" -w '%{http_code}' \
  -X PATCH "$BASE/api/users/$ID_VICTIM" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $A_CSRF" -d '{"display_name":"hacked"}' 2>/dev/null)
LAST_CODE=$(jget code)
expect "评估员 修改用户被拒" 403 FORBIDDEN

# —— 审计员 ——
req GET /api/audit-logs -b /tmp/sr-auditor.jar
expect "审计员 读审计日志（持 audit:read）" 200

req GET /api/users -b /tmp/sr-auditor.jar
expect "审计员 读用户列表（只读权限）" 200

req GET /api/roles -b /tmp/sr-auditor.jar
expect "审计员 读角色字典" 200

# 角色字典的字段风格必须与全局一致（snake_case）。
# 这一条是回归护栏：接口最初直接返回 model.Role，而该结构体没有 json tag，
# 于是输出成了 Go 风格的 PascalCase（Code / IsBuiltin），
# 前端拿到后得为这一个接口写一套不同的取值逻辑。已改为显式的视图对象。
ROLES_BODY=$(cat "$BODY")
if printf '%s' "$ROLES_BODY" | grep -q '"is_builtin"'; then
  ok "角色字典字段为 snake_case（对外契约由接口层显式定义）"
else
  bad "角色字典字段风格不符：期望出现 is_builtin，实际响应为 $(printf '%s' "$ROLES_BODY" | head -c 200)"
fi
if printf '%s' "$ROLES_BODY" | grep -q '"IsBuiltin"'; then
  bad "角色字典泄漏了模型字段名 IsBuiltin（缺少对外视图对象）"
else
  ok "角色字典未泄漏 Go 风格字段名"
fi

# 角色到权限码的映射不下发给前端：前端只用 /auth/me 的 permissions 做动态路由，
# 下发映射会诱使前端维护第二份权限表，而两份表必然逐渐失配
if printf '%s' "$ROLES_BODY" | grep -q '"permissions"'; then
  bad "角色字典下发了权限映射，前端可能据此绕过 permissions 单一路径"
else
  ok "角色字典未下发权限映射（权限只经 /auth/me 下发）"
fi

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-auditor.jar -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/users" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $U_CSRF" \
  -d "{\"username\":\"nope2_$STAMP\",\"password\":\"Whatever@2026\",\"roles\":[\"auditor\"]}" 2>/dev/null)
LAST_CODE=$(jget code)
expect "审计员 新建用户被拒" 403 FORBIDDEN

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-auditor.jar -o "$BODY" -w '%{http_code}' \
  -X PATCH "$BASE/api/users/$ID_VICTIM" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $U_CSRF" -d '{"display_name":"hacked"}' 2>/dev/null)
LAST_CODE=$(jget code)
expect "审计员 修改用户被拒" 403 FORBIDDEN

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-auditor.jar -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/users/$ID_VICTIM/reset-password" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $U_CSRF" -d '{"new_password":"Hacked@2026x"}' 2>/dev/null)
LAST_CODE=$(jget code)
expect "审计员 重置他人密码被拒" 403 FORBIDDEN

# —— 管理员 ——
req GET /api/audit-logs -b /tmp/sr-admin.jar
expect "管理员 读审计日志" 200

# ============================================================ 5. 管理员保护
section "5. 管理员自身保护"

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-admin.jar -o "$BODY" -w '%{http_code}' \
  -X PATCH "$BASE/api/users/$ADMIN_ID" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $ADMIN_CSRF" -d '{"status":"disabled"}' 2>/dev/null)
LAST_CODE=$(jget code)
expect "禁止禁用自己的账号" 409 USER_SELF_OPERATION

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-admin.jar -o "$BODY" -w '%{http_code}' \
  -X PATCH "$BASE/api/users/$ADMIN_ID" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $ADMIN_CSRF" -d '{"roles":["assessor"]}' 2>/dev/null)
LAST_CODE=$(jget code)
expect "禁止移除最后一个管理员的 admin 角色" 409 USER_LAST_ADMIN

# ============================================================ 6. 禁用即时生效
section "6. 禁用账号立即失效"

login_token /tmp/sr-victim.jar "$U_VICTIM" "$PASSWORD"
V_CSRF="$SESSION_CSRF"
change_pw /tmp/sr-victim.jar "$V_CSRF"
expect "待禁用账号完成强制改密" 200

login_token /tmp/sr-victim.jar "$U_VICTIM" "$PASSWORD2"
V_CSRF="$SESSION_CSRF"
req GET /api/auth/me -b /tmp/sr-victim.jar
expect "待禁用账号登录后 /me 正常" 200

V_OLD_REFRESH=$(awk '$6=="sr_rt" {print $7}' /tmp/sr-victim.jar | tail -1)

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-admin.jar -o "$BODY" -w '%{http_code}' \
  -X PATCH "$BASE/api/users/$ID_VICTIM" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $ADMIN_CSRF" -d '{"status":"disabled"}' 2>/dev/null)
LAST_CODE=$(jget code)
expect "管理员禁用该账号" 200

req GET /api/auth/me -b /tmp/sr-victim.jar
expect "禁用后原有 Cookie 立即失效（无需等令牌过期）" 403 AUTH_ACCOUNT_DISABLED

LAST_STATUS=$(curl -sS --noproxy '*' -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/auth/refresh" \
  -H "Cookie: sr_rt=$V_OLD_REFRESH; sr_csrf=$V_CSRF" -H "X-CSRF-Token: $V_CSRF" 2>/dev/null)
LAST_CODE=$(jget code)
if [ "$LAST_STATUS" = "403" ] || [ "$LAST_STATUS" = "401" ]; then
  ok "禁用后刷新令牌已作废"
else
  bad "禁用后刷新令牌仍可用" "HTTP $LAST_STATUS / $LAST_CODE"
fi

# ============================================================ 7. 令牌轮换
section "7. 刷新令牌轮换与重放检测"

login_token /tmp/sr-auditor.jar "$U_AUDITOR" "$PASSWORD2"
K_CSRF="$SESSION_CSRF"
REFRESH_1=$(awk '$6=="sr_rt" {print $7}' /tmp/sr-auditor.jar | tail -1)

LAST_STATUS=$(curl -sS --noproxy '*' -o "$BODY" -D "$HDR" -w '%{http_code}' \
  -X POST "$BASE/api/auth/refresh" \
  -H "Cookie: sr_rt=$REFRESH_1; sr_csrf=$K_CSRF" -H "X-CSRF-Token: $K_CSRF" 2>/dev/null)
LAST_CODE=$(jget code)
expect "用刷新令牌换取新会话" 200

REFRESH_2=$(grep -i '^set-cookie: sr_rt=' "$HDR" | sed 's/.*sr_rt=\([^;]*\).*/\1/' | tr -d '\r')
if [ -n "$REFRESH_2" ] && [ "$REFRESH_2" != "$REFRESH_1" ]; then
  ok "刷新令牌已轮换（新旧令牌不同）"
else
  bad "刷新令牌未轮换" "old=${REFRESH_1:0:12} new=${REFRESH_2:0:12}"
fi

LAST_STATUS=$(curl -sS --noproxy '*' -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/auth/refresh" \
  -H "Cookie: sr_rt=$REFRESH_1; sr_csrf=$K_CSRF" -H "X-CSRF-Token: $K_CSRF" 2>/dev/null)
LAST_CODE=$(jget code)
expect "旧刷新令牌重放被拒绝" 401 AUTH_TOKEN_INVALID

LAST_STATUS=$(curl -sS --noproxy '*' -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/auth/refresh" \
  -H "Cookie: sr_rt=$REFRESH_2; sr_csrf=$K_CSRF" -H "X-CSRF-Token: $K_CSRF" 2>/dev/null)
LAST_CODE=$(jget code)
expect "检测到重放后整条会话链被吊销（新令牌同样失效）" 401 AUTH_TOKEN_INVALID

# ============================================================ 8. 账号锁定
section "8. 登录失败锁定"

LOCK_HITS=0
for i in 1 2 3 4 5 6; do
  T=$(csrf_token /tmp/sr-lock.jar)
  LAST_STATUS=$(curl -sS --noproxy '*' -c /tmp/sr-lock.jar -b /tmp/sr-lock.jar -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $T" \
    -d "{\"username\":\"$U_LOCK\",\"password\":\"bad-$i\"}" 2>/dev/null)
  LAST_CODE=$(jget code)
  [ "$LAST_CODE" = "AUTH_ACCOUNT_LOCKED" ] && LOCK_HITS=$((LOCK_HITS + 1))
done

if [ "$LOCK_HITS" -ge 1 ]; then
  ok "连续失败达阈值后账号被锁定"
else
  bad "连续失败未触发锁定" "最后一次：HTTP $LAST_STATUS / $LAST_CODE"
fi

T=$(csrf_token /tmp/sr-lock.jar)
LAST_STATUS=$(curl -sS --noproxy '*' -c /tmp/sr-lock.jar -b /tmp/sr-lock.jar -o "$BODY" \
  -w '%{http_code}' -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $T" \
  -d "{\"username\":\"$U_LOCK\",\"password\":\"$PASSWORD\"}" 2>/dev/null)
LAST_CODE=$(jget code)
expect "锁定期间即使密码正确也拒绝" 423 AUTH_ACCOUNT_LOCKED

# 管理员解锁后应可正常登录
LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-admin.jar -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/users/$ID_LOCK/unlock" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $ADMIN_CSRF" 2>/dev/null)
LAST_CODE=$(jget code)
expect "管理员解除账号锁定" 200

T=$(csrf_token /tmp/sr-lock.jar)
LAST_STATUS=$(curl -sS --noproxy '*' -c /tmp/sr-lock.jar -b /tmp/sr-lock.jar -o "$BODY" \
  -w '%{http_code}' -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $T" \
  -d "{\"username\":\"$U_LOCK\",\"password\":\"$PASSWORD\"}" 2>/dev/null)
LAST_CODE=$(jget code)
expect "解锁后可正常登录" 200

# ============================================================ 9. 审计
section "9. 审计日志"

req GET "/api/audit-logs?pageSize=100" -b /tmp/sr-admin.jar
expect "管理员查询审计日志" 200
AUDIT_DUMP=$(cat "$BODY")

check_audit() {
  if printf '%s' "$AUDIT_DUMP" | grep -q "\"action\":\"$1\""; then
    ok "审计记录存在：$1"
  else
    bad "审计记录缺失：$1"
  fi
}
check_audit "auth.login"
check_audit "auth.login_failed"
check_audit "auth.token_reuse_detected"
check_audit "auth.password_change"
check_audit "user.create"
check_audit "user.update"
# 注意：auth.logout 的断言不在这里。
# 本节点尚未发生任何登出（登出在第 10 节），在此断言属于「提前断言」，
# 必然失败且掩盖真实问题。该断言移到第 10 节登出之后执行。

if printf '%s' "$AUDIT_DUMP" | grep -q '"client_ip":"127.0.0.1"'; then
  ok "审计记录含 client_ip（来源可追溯）"
else
  bad "审计记录缺少 client_ip"
fi

if printf '%s' "$AUDIT_DUMP" | grep -q '"request_id":"[0-9a-f-]\{36\}"'; then
  ok "审计记录含 request_id（可与访问日志串联）"
else
  bad "审计记录缺少 request_id"
fi

if printf '%s' "$AUDIT_DUMP" | grep -qiE "$PASSWORD|$PASSWORD2|Admin@12345"; then
  bad "审计日志中出现了明文密码"
else
  ok "审计日志未泄漏任何明文密码"
fi

# ============================================================ 10. 登出
section "10. 登出"

login_token /tmp/sr-auditor.jar "$U_AUDITOR" "$PASSWORD2"
expect "审计员重新登录成功" 200
K2_CSRF="$SESSION_CSRF"
REFRESH_OUT=$(awk '$6=="sr_rt" {print $7}' /tmp/sr-auditor.jar | tail -1)

LAST_STATUS=$(curl -sS --noproxy '*' -b /tmp/sr-auditor.jar -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/auth/logout" -H "X-CSRF-Token: $K2_CSRF" 2>/dev/null)
LAST_CODE=$(jget code)
expect "登出成功" 200

LAST_STATUS=$(curl -sS --noproxy '*' -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE/api/auth/refresh" \
  -H "Cookie: sr_rt=$REFRESH_OUT; sr_csrf=$K2_CSRF" -H "X-CSRF-Token: $K2_CSRF" 2>/dev/null)
LAST_CODE=$(jget code)
expect "登出后刷新令牌已作废" 401 AUTH_TOKEN_INVALID

req GET /api/auth/me -b /tmp/sr-auditor.jar
expect "登出后访问受保护接口被拒" 401

# 登出必须留痕：它被审计中间件豁免（失败路径也需记录），由 service 层自行写入。
# 这里在登出**之后**重新拉取审计日志，验证这条自记录路径真的生效。
req GET "/api/audit-logs?pageSize=100" -b /tmp/sr-admin.jar
expect "管理员查询审计日志（登出后）" 200
AUDIT_DUMP=$(cat "$BODY")
check_audit "auth.logout"

# ============================================================ 11. 清理
# 临时库由退出时的 cleanup 整体 DROP —— 账号、角色关联、审计记录一并消失，
# 所以「逐个把账号置为 disabled」这一步没有必要了。
#
# 旧版本必须这么做，是因为它跑在开发库上：删不掉，就只能标记，而标记完
# 账号行仍然留在 users 表里，跑十次就积四十个 —— 「清理」反而成了污染源。
section "11. 清理"
printf "  ${C_DIM}测试数据全部在临时库 %s 内，随脚本退出整体删除${C_RESET}\n" "$E2E_DB"

# ============================================================
printf "\n══════════════════════════════════════════\n"
if [ "$FAIL" -eq 0 ]; then
  printf "认证与授权守门验证全部通过 ✅  通过 %d/%d 项\n" "$PASS" "$PASS"
  printf "══════════════════════════════════════════\n"
  exit 0
else
  printf "存在失败项 ❌  通过 %d/%d 项\n" "$PASS" "$((PASS + FAIL))"
  printf "失败清单：\n"
  for item in "${FAILED_ITEMS[@]}"; do printf "  - %s\n" "$item"; done
  printf "══════════════════════════════════════════\n"
  exit 1
fi
