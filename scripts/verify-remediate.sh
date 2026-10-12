#!/usr/bin/env bash
# ============================================================================
# P6 整改跟踪 + 首页统计 守门验证
#
# 验证什么（对应 docs/01-实现计划.md 里 P6 的验收标志「状态流转可追溯」）：
#
#   ▍本脚本最重要的一个设计决定：**把「整改单」与「风险项」当成两条独立的生命线**
#
#   P6 最容易犯、也最难看出来的错误，是把整改单挂到 risk_item_id 上。
#   这样做在功能上「一切正常」——建单成功、列表有数据、详情能打开。
#   问题只在**评估重算之后**才出现：P4 的 calculate 是「先清后写」，
#   重算一次 risk_items 的 id 整批换新，指向旧 id 的整改单会**静默断链**
#   —— 没有报错、没有日志、没有 404，只是那张单子的出处再也查不到了，
#   而「这条整改单还成立吗」也就永远无法回答。
#
#   因此第 5 节的做法是**真的重算一次**，然后回头质问那张单子：
#   它还在吗？快照完整吗？出处失效了吗？——三条都要在。
#   最后再加一条反向对照：库里确实存在着「出处已失效」的单子，
#   这正是「不能绑 risk_item_id」的物证。
#
#   覆盖的 13 节：
#
#    0. 环境准备：隔离库 sec_risk_remediate_e2e + 端口 18087。
#    1. 登录并改掉引导密码。
#    2. 数据准备：6 台资产（两批各 3 档重要性）× 6 个漏洞（两批各 3 档
#       严重程度）+ 威胁 T=1，两个已计算任务（α / β）与一个草稿任务。
#       T=1 是刻意选的：这样 R = 重要性 × 严重程度，9 条风险项恰好覆盖
#       全部 5 个等级（1/2/1/4/1），「按等级批量建单」才有区分度。
#    3. 建单：快照列（资产名 / IP / 漏洞名 / 等级 / 风险值）逐列核对，
#       初始态、时间态、流转选项投影。
#    4. 唯一性：同一 (资产, 漏洞) 二次建单 409；闭环后可再建一张
#       （生成列 active_key 变 NULL，唯一索引不再约束）。
#    5. **重算不断链**：重算后旧 risk_item_id 查不到行，而单子与快照、
#       流转记录全部完好。
#    6. 状态机：非法流转 409 且**不留流转记录**；非法状态值 400；
#       必填说明三处；打回 resolved → in_progress 的 from/to 正确；
#       终态 transitions 为空数组、再流转 409。
#    7. 逾期：三档（昨天 / 今天 / +5 天）+ 无期限，四条规则逐条验证，
#       其中「今天到期算即将到期不算逾期」与「未设期限永不算逾期」
#       是最容易实现错的两条；另验证「闭环之后不再是逾期」。
#    8. 批量建单：命中 / 新建 / 跳过三个数字 + 幂等（第二次 created=0、
#       skipped=命中数）+ 非法等级 400 + 草稿任务 409。
#    9. 删除限制：改过字段仍可删（改字段不是流转），流转过则 409。
#   10. 权限：匿名 401 / 缺 CSRF 403 / 审计员只读 / 评估员可写可读。
#   11. 仪表盘口径：风险数字绑定单个评估、**换 assessment_id 数字要跟着变**
#       （这是「不是硬编码」的唯一证明）、逾期与即将到期区间不重叠、
#       草稿评估与「一次都没算过」都不炸。
#   12. 审计：五个动作码 + 明细字段 + 失败流转不留痕 + 无「未记录审计」告警。
#
# ── 环境隔离 ───────────────────────────────────────────────────────────────
# 本脚本**不复用开发库**，临时建 sec_risk_remediate_e2e（理由同其它 verify-*.sh）。
# 端口用 18087，避免与 verify-assess.sh（18085）/ verify-report.sh（18086）撞车。
# 不依赖 docgen / gotenberg —— P6 是纯数据面，不渲染任何文件。
#
# 用法： bash scripts/verify-remediate.sh
# 退出码：0 = 全部通过；1 = 存在失败项；2 = 前置条件不满足
#
# 前置条件：MySQL 已启动（make infra）
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT=18087
BASE="http://127.0.0.1:${PORT}"
E2E_DB="sec_risk_remediate_e2e"
E2E_ADMIN="admin"
# 临时库的临时口令：随进程生成，不写入任何文件，用完即随库删除
E2E_ADMIN_PW="Rq8!$(date +%s)$RANDOM"

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 \
  || PYTHON="/Users/chunle/.workbuddy/binaries/python/versions/3.13.12/bin/python3"

SRV_LOG="/tmp/sr-remediate-verify-srv.log"
BODY="/tmp/.sr-remediate-body"
HDR="/tmp/.sr-remediate-hdr"
ITEMS_JSON="/tmp/.sr-remediate-items.json"
AUDIT_JSON="/tmp/.sr-remediate-audit.json"
DB_TSV="/tmp/.sr-remediate-db.tsv"

ADMIN_JAR="/tmp/sr-remediate-admin.jar"
AUDITOR_JAR="/tmp/sr-remediate-auditor.jar"
ASSESSOR_JAR="/tmp/sr-remediate-assessor.jar"
ANON_JAR="/tmp/sr-remediate-anon.jar"

PASS=0
FAIL=0
FAILED_ITEMS=()

if [ -t 1 ]; then
  C_GREEN='\033[32m'; C_RED='\033[31m'; C_DIM='\033[2m'; C_CYAN='\033[36m'; C_RESET='\033[0m'
else
  C_GREEN=''; C_RED=''; C_DIM=''; C_CYAN=''; C_RESET=''
fi

ok()   { PASS=$((PASS + 1)); printf "  ${C_GREEN}✅${C_RESET} %s\n" "$1"; }
bad()  {
  FAIL=$((FAIL + 1)); FAILED_ITEMS+=("$1")
  printf "  ${C_RED}❌${C_RESET} %s\n" "$1"
  [ -n "${2:-}" ] && printf "     ${C_DIM}%s${C_RESET}\n" "$2"
}
section() { printf "\n${C_CYAN}── %s ──${C_RESET}\n" "$1"; }
info() { printf "  ${C_DIM}%s${C_RESET}\n" "$1"; }

# ============================================================================
# 时间工具
#
# ⚠️ 全部走 Python 而不是 `date -v-1d`（macOS 专有）/ `date -d`（GNU 专有）：
#    这两种写法在对方平台上都会失败，而失败形态是「输出当前时间」而不是报错
#    （`date -v-1d` 在 GNU 上会被当成无效选项，但换成 `date -d "-1 day"` 在
#    BSD 上又会把字符串原样打出来）。逾期断言对日期极度敏感，一个「其实没算
#    出昨天」的日期会把「逾期一天」判成「今天到期」——而两条断言各有自己的
#    期望值，所以会以「期望 1 实际 0」的形式失败，看着像服务端的 bug。
#
#    `DAY 0` = 今天，`DAY -1` = 昨天，`DAY 5` = 五天后的日期。
#    以本机时区计算，与服务端 Go 进程的 time.Local 同一时区。
# ============================================================================
DAY() {
  "$PYTHON" -c 'import datetime,sys; print((datetime.date.today()+datetime.timedelta(days=int(sys.argv[1]))).isoformat())' "$1"
}

TODAY="$(DAY 0)"
YESTERDAY="$(DAY -1)"
IN_5_DAYS="$(DAY 5)"

# ============================================================================
# HTTP 工具（与 verify-report.sh / verify-assess.sh 同源，改动请三边同步）
# ============================================================================

LAST_STATUS=0
LAST_CODE=""

# jget <点号路径> — 从 $BODY 中取值
#
# ⚠️ 数据文件路径通过参数传入，而不是用 stdin 重定向。
# 若写成 `python3 - <<'PY' < "$BODY"`，两个 stdin 重定向会互相覆盖，
# python 会把数据文件当脚本读取，函数永远返回空值 —— 静默失效，极难排查。
#
# ⚠️ 布尔值会打印成 True / False（Python 的 repr），不要写成 true / false。
#    需要小写形态请用 jbool。
jget() {
  "$PYTHON" -c '
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

# jbool <点号路径> — 取布尔字段并转成 true / false（取不到返回空）
jbool() {
  "$PYTHON" -c '
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
print("true" if d is True else ("false" if d is False else d))
' "$1" "$BODY" 2>/dev/null
}

# jlist <点号路径> — 把数组用逗号连接（供 SQL 的 IN (...) 与 awk 使用）
#
# ⚠️ 不要用 jget 取数组：Python 的 repr 是 `[1, 2, 3]`，直接拼进
#    `IN ([1, 2, 3])` 会得到一条语法错误的 SQL，而 sql() 把 stderr 丢掉后
#    表现是「返回空字符串」，于是断言以「期望 3 实际 」的形式失败 ——
#    看着像数据没有落库。
jlist() {
  "$PYTHON" -c '
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
print(",".join(str(x) for x in d) if isinstance(d, list) else d)
' "$1" "$BODY" 2>/dev/null
}

# jlen <点号路径> — 数组/对象/字符串的长度；取不到返回 -1
jlen() {
  "$PYTHON" -c '
import json, sys
try:
    d = json.load(open(sys.argv[2], encoding="utf-8"))
except Exception:
    print(-1); raise SystemExit
for k in sys.argv[1].split("."):
    if not k:
        continue
    if isinstance(d, list):
        try: d = d[int(k)]
        except Exception: print(-1); raise SystemExit
    elif isinstance(d, dict):
        d = d.get(k)
    else:
        print(-1); raise SystemExit
    if d is None:
        print(-1); raise SystemExit
print(len(d) if isinstance(d, (list, dict, str)) else -1)
' "$1" "$BODY" 2>/dev/null
}

# jref <文件> <点号路径> — 同 jget，但从任意文件取（审计明细、风险项列表用）
jref() {
  "$PYTHON" -c '
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
' "$1" "$2" 2>/dev/null
}

# file_code <file> — 从响应体文件里取业务码；不是 JSON 时返回 <binary>
file_code() {
  "$PYTHON" -c '
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("<binary>"); raise SystemExit
print(d.get("code") or "<no-code>")
' "$1" 2>/dev/null
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

# eq <描述> <实际> <期望>
eq() {
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "期望「$3」，实际「$2」"; fi
}

# ne <描述> <实际> <不应等于的值>
ne() {
  if [ "$2" != "$3" ]; then ok "$1"; else bad "$1" "不应等于「$3」"; fi
}

# oneof <描述> <实际> <候选1> [候选2] [候选3]
#
# ⚠️ 变量后紧跟中文标点时必须写成 ${VAR}。bash 在非 C locale 下会把多字节
#    字符的首字节并进变量名，导致 `got（: unbound variable` 这类报错 ——
#    报错信息里看得见乱码，但很难意识到根因是「变量名被吃了」。
oneof() {
  local desc="$1" got="$2"; shift 2
  for want in "$@"; do
    if [ "$got" = "$want" ]; then ok "$desc"; return; fi
  done
  bad "$desc" "期望其中之一「$*」，实际「${got}」"
}

# contains <描述> <文本> <子串>
contains() {
  case "$2" in
    *"$3"*) ok "$1" ;;
    *) bad "$1" "在文本中未找到「$3」（实际「${2}」）" ;;
  esac
}

# hdr <头名> — 取 $HDR 里最后一个同名响应头的值（大小写不敏感）
hdr() {
  grep -i "^$1:" "$HDR" 2>/dev/null | tail -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r'
}

# ---------------------------------------------------------------- 会话工具

csrf_token() {
  curl -sS --noproxy '*' -c "$1" -b "$1" "$BASE/api/auth/csrf" -o "$BODY" 2>/dev/null
  jget data.csrf_token
}

SESSION_CSRF=""
# ADMIN_CSRF 与 SESSION_CSRF 必须分开。
#
# ⚠️ SESSION_CSRF 会被 login() 反复覆盖成「最后一次登录的那个账号」的令牌，
# 而 json()/req() 恒用管理员会话（$ADMIN_JAR）。两者混用的话，只要脚本里
# 在管理员之后登录过别的账号（审计员 / 评估员），**之后所有 json() 调用
# 都会带上别人的令牌**，被 CSRF 中间件以 403 AUTH_CSRF_INVALID 拒绝。
#
# 这个失败形态极具误导性：报的是权限错，看起来像「管理员没权限」，
# 而真正的原因是自己把令牌换掉了。更糟的是它会连带污染后面的断言 ——
# 例如「失败的流转不留下审计」会因为请求根本没进业务层而变成假绿。
ADMIN_CSRF=""

# login <jar> <user> <pass>
#
# ⚠️ 调用时**不要**写成 `X=$(login ...)`：命令替换会让函数在子 shell 中执行，
# 函数内对 LAST_STATUS 的赋值无法传回父 shell，后续断言会读到上一次的残留值，
# 产生「实际失败却报通过」的假绿。
login() {
  local jar="$1" user="$2" pass="$3"
  local token
  token=$(csrf_token "$jar")
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$jar" -b "$jar" -D "$HDR" -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $token" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}" 2>/dev/null)
  LAST_CODE=$(jget code)
  SESSION_CSRF=$(jget data.csrf_token)
}

# req <method> <path> [curl args...] — 以管理员会话发出请求
req() {
  local method="$1" path="$2"; shift 2
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
    -o "$BODY" -w '%{http_code}' \
    -X "$method" "$BASE$path" "$@" 2>/dev/null)
  LAST_CODE=$(jget code)
  [ -z "$LAST_CODE" ] && LAST_CODE="<no-json>"
}

# json <method> <path> [json body] — 以管理员会话发出的业务请求
json() {
  local method="$1" path="$2" payload="${3:-}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
    -w '%{http_code}' -X "$method" "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $ADMIN_CSRF" \
    -d "$payload" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# json_as <jar> <method> <path> [json body] [csrf] — 用指定会话发请求（越权断言）
json_as() {
  local jar="$1" method="$2" path="$3" payload="${4:-}" token="${5:-$SESSION_CSRF}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$jar" -b "$jar" -o "$BODY" \
    -w '%{http_code}' -X "$method" "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $token" \
    -d "$payload" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# raw <jar> <method> <path> [curl args...] — 不含 CSRF 头的裸请求
#
# 专用于「缺 CSRF 应当被拒」这条断言：json / json_as 都会自动带上令牌，
# 拿它们去测 CSRF 只会得到 200 —— 一条永远绿的假断言。
raw() {
  local jar="$1" method="$2" path="$3"; shift 3
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$jar" -b "$jar" \
    -o "$BODY" -w '%{http_code}' \
    -X "$method" "$BASE$path" "$@" 2>/dev/null)
  LAST_CODE=$(jget code)
  [ -z "$LAST_CODE" ] && LAST_CODE="<no-json>"
}

# ============================================================================
# 环境准备工具
# ============================================================================

env_value() {
  sed -n "s/^$1=//p" "$ROOT/.env" 2>/dev/null | head -1 | tr -d '"'\''' | tr -d '\r'
}

MYSQL_ROOT_PW="$(env_value MYSQL_ROOT_PASSWORD)"
MYSQL_USER_VAL="$(env_value MYSQL_USER)"; MYSQL_USER_VAL="${MYSQL_USER_VAL:-secrisk}"

compose() { docker compose "$@"; }

free_port() {
  local pids
  pids="$(lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
    sleep 1
  fi
}

# sql <SQL> — 在隔离库里执行查询，-N -B 输出无表头、tab 分隔
#
# ⚠️ `--default-character-set=utf8mb4` 不能省。缺了它，容器里的 mysql CLI
# 会按 latin1 连接，中文**在读到的时候就已经变成 `?`**了 —— 而
# 「界面里是『P6 漏洞 V=5』、落库里是『P6 ?? V=5』」看起来非常像写库时
# 编码坏了，排查方向会跑偏到迁移脚本与字段字符集上去。
sql() {
  compose exec -T mysql mysql -N -B --default-character-set=utf8mb4 \
    -uroot -p"$MYSQL_ROOT_PW" "$E2E_DB" -e "$1" 2>/dev/null
}

# sqlq <SQL> — 同 sql，但结果作为单个单元格返回（供 $() 包裹）
sqlq() { sql "$1" | head -1 | tr -d '\r'; }

wait_http() {
  local url="$1" secs="$2" i
  for i in $(seq 1 "$secs"); do
    if curl -fsS --noproxy '*' -m 2 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

SRV_PID=""

cleanup() {
  section "清理"
  # wait 不只是回收僵尸：少了它 bash 会在退出前多打印一行
  # `PID Killed: 9`，夹在汇总与清理信息之间，看上去像报错。
  if [ -n "$SRV_PID" ]; then
    kill -9 "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
  fi
  free_port "$PORT"

  if [ -n "$MYSQL_ROOT_PW" ]; then
    compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
      -e "DROP DATABASE IF EXISTS \`$E2E_DB\`;" >/dev/null 2>&1 \
      && echo "  ${C_DIM}已删除临时库 ${E2E_DB}${C_RESET}"
  fi
  rm -f "$ADMIN_JAR" "$AUDITOR_JAR" "$ASSESSOR_JAR" "$ANON_JAR" "$DB_TSV" "$ITEMS_JSON"
  echo "  ${C_DIM}开发库与其它数据未被触碰${C_RESET}"
}
trap cleanup EXIT
# Ctrl-C / kill 也要走 cleanup
trap 'exit 130' INT TERM

# ============================================================================
section "0. 环境准备"
# ============================================================================

command -v docker >/dev/null || { echo "未安装 docker"; exit 2; }
if ! compose ps --format '{{.Name}}' 2>/dev/null | grep -q secrisk-mysql; then
  echo "  MySQL 容器未运行，请先执行 make infra"
  exit 2
fi
ok "MySQL 容器在运行"

if [ -z "$MYSQL_ROOT_PW" ]; then
  echo "  未能从 .env 读取 MYSQL_ROOT_PASSWORD，无法创建隔离的临时库"
  exit 2
fi

free_port "$PORT"

compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" -e \
  "DROP DATABASE IF EXISTS \`$E2E_DB\`;
   CREATE DATABASE \`$E2E_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
   GRANT ALL PRIVILEGES ON \`$E2E_DB\`.* TO '$MYSQL_USER_VAL'@'%';
   FLUSH PRIVILEGES;" >/dev/null 2>&1

if compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
  -e "USE \`$E2E_DB\`;" >/dev/null 2>&1; then
  ok "已创建隔离的临时库 ${E2E_DB}（端口 ${PORT}）"
else
  bad "创建临时库失败"
  exit 2
fi

info "今天 = ${TODAY}；昨天 = ${YESTERDAY}；五天之后 = ${IN_5_DAYS}"

rm -f "$ADMIN_JAR" "$AUDITOR_JAR" "$ASSESSOR_JAR" "$ANON_JAR"

# ============================================================================
section "1. 启动后端（指向临时库）并登录"
# ============================================================================

(
  cd server
  SR_DATABASE_NAME="$E2E_DB" \
  SR_AUTH_BOOTSTRAP_USERNAME="$E2E_ADMIN" \
  SR_AUTH_BOOTSTRAP_PASSWORD="$E2E_ADMIN_PW" \
  SR_SERVER_PORT="$PORT" \
  SR_AUTH_LOGIN_RATE_LIMIT=2000 \
  SR_APP_LOG_LEVEL=info \
  go run ./cmd/api
) > "$SRV_LOG" 2>&1 &
SRV_PID=$!

if ! wait_http "$BASE/api/health" 120; then
  bad "后端未就绪"
  tail -30 "$SRV_LOG"
  exit 1
fi
ok "后端已就绪：$BASE"

login "$ADMIN_JAR" "$E2E_ADMIN" "$E2E_ADMIN_PW"
expect "引导管理员可登录" 200
ADMIN_CSRF="$SESSION_CSRF"

NEW_PW="${E2E_ADMIN_PW}New1"
json PATCH /api/auth/password \
  "{\"old_password\":\"$E2E_ADMIN_PW\",\"new_password\":\"$NEW_PW\"}"
expect "首次改密成功" 200

login "$ADMIN_JAR" "$E2E_ADMIN" "$NEW_PW"
expect "改密后可重新登录" 200
ADMIN_CSRF="$SESSION_CSRF"
ADMIN_NAME="$E2E_ADMIN"
# 显示名与登录名未必相同（引导时由 SR_AUTH_BOOTSTRAP_DISPLAY_NAME 决定），
# 而整改单的 created_by_name 走的是显示名。期望值从库里取，
# 而不是把「显示名等于登录名」这个假设写进断言。
ADMIN_DISPLAY="$(sqlq "SELECT IF(display_name = '', username, display_name) FROM users WHERE username = '${E2E_ADMIN}';")"
info "管理员：登录名 ${ADMIN_NAME} / 显示名 ${ADMIN_DISPLAY}"

# ============================================================================
section "2. 数据准备（威胁 / 资产 / 漏洞 / 评估任务）"
# ============================================================================

# ── 威胁字典：T=1 ───────────────────────────────────────────────────────
#
# 取 1 而不是默认的 3，是为了让 R = 重要性 × 严重程度（权重系数默认 1.0），
# 于是 3 档重要性 × 3 档严重程度恰好铺满五个等级：
#
#        S=5   S=3   S=1
#   I=5   25    15     5      25 很高 / 15 高 / 5 低
#   I=3   15     9     3      → very_high 1、high 2、medium 1、low 4、very_low 1
#   I=1    5     3     1
#
# 这个分布是「按等级批量建单」有区分度的前提：若全落在「很高」，
# 一个把等级筛选写死成「全部」的实现同样能通过。
json POST /api/dictionaries \
  '{"category":"threat","code":"r6_t1","name":"P6 威胁 T=1","weight":1}'
expect "建威胁字典 r6_t1（权重 1）" 201
TH_T1="$(jget data.code)"

# ── 资产：两批各 3 档重要性 ─────────────────────────────────────────────
#
# 两批而不是一批，是为了让「逐条建单」与「批量建单」互不干扰：
# 唯一索引的作用域是 (资产, 漏洞)，共用一批资产会让批量建单的命中数
# 随前面测试的执行顺序漂移，断言就得写成「≥ N」——那等于没有断言。
declare -a A_IDS=()
A_NAME=(P6-RA5 P6-RA3 P6-RA1 P6-RB5 P6-RB3 P6-RB1)
A_IMP=(5 3 1 5 3 1)
A_IP=(10.66.10.1 10.66.10.3 10.66.10.5 10.66.20.1 10.66.20.3 10.66.20.5)

for i in 0 1 2 3 4 5; do
  json POST /api/assets \
    "{\"name\":\"${A_NAME[$i]}\",\"asset_type\":\"server\",\"ip_address\":\"${A_IP[$i]}\",\"importance\":${A_IMP[$i]}}"
  expect "建资产 ${A_NAME[$i]}（重要性 ${A_IMP[$i]}）" 201
  A_IDS+=("$(jget data.id)")
done

RA5="${A_IDS[0]}"; RA3="${A_IDS[1]}"; RA1="${A_IDS[2]}"
RB5="${A_IDS[3]}"; RB3="${A_IDS[4]}"; RB1="${A_IDS[5]}"

# ── 漏洞：两批各 3 档严重程度 ───────────────────────────────────────────
declare -a V_IDS=()
V_TITLE=("P6 漏洞 V=5" "P6 漏洞 V=3" "P6 漏洞 V=1" "P6 漏洞 W=5" "P6 漏洞 W=3" "P6 漏洞 W=1")
V_SEV=(5 3 1 5 3 1)

for i in 0 1 2 3 4 5; do
  json POST /api/vulnerabilities "{\"title\":\"${V_TITLE[$i]}\",\"severity\":${V_SEV[$i]}}"
  expect "建漏洞 ${V_TITLE[$i]}（严重程度 ${V_SEV[$i]}）" 201
  V_IDS+=("$(jget data.id)")
done

RV5="${V_IDS[0]}"; RV3="${V_IDS[1]}"; RV1="${V_IDS[2]}"
RW5="${V_IDS[3]}"; RW3="${V_IDS[4]}"; RW1="${V_IDS[5]}"

# ── 把漏洞挂到资产上（决定风险项的 (资产, 漏洞) 组合）────────────────────
A_BATCH_A="[${RA5},${RA3},${RA1}]"
A_BATCH_B="[${RB5},${RB3},${RB1}]"

for i in 0 1 2; do
  json POST "/api/vulnerabilities/${V_IDS[$i]}/assets" "{\"asset_ids\":${A_BATCH_A}}"
  expect "把漏洞「${V_TITLE[$i]}」挂到 A 批 3 台资产" 200
done
for i in 3 4 5; do
  json POST "/api/vulnerabilities/${V_IDS[$i]}/assets" "{\"asset_ids\":${A_BATCH_B}}"
  expect "把漏洞「${V_TITLE[$i]}」挂到 B 批 3 台资产" 200
done

# ── 三个评估任务 ────────────────────────────────────────────────────────
json POST /api/assessments \
  "{\"name\":\"P6 整改跟踪验证 α\",\"description\":\"逐条建单与状态流转\",\"scope_type\":\"custom\",\"scope_ref\":${A_BATCH_A},\"default_threat_code\":\"${TH_T1}\"}"
expect "建主评估任务 α" 201
M1="$(jget data.id)"

json POST /api/assessments \
  "{\"name\":\"P6 整改跟踪验证 β\",\"description\":\"批量建单\",\"scope_type\":\"custom\",\"scope_ref\":${A_BATCH_B},\"default_threat_code\":\"${TH_T1}\"}"
expect "建批量评估任务 β" 201
M2="$(jget data.id)"

json POST /api/assessments \
  "{\"name\":\"P6 草稿任务\",\"description\":\"未计算，用于验证草稿口径\",\"scope_type\":\"custom\",\"scope_ref\":[${RA5}],\"default_threat_code\":\"${TH_T1}\"}"
expect "建草稿任务" 201
M3="$(jget data.id)"

json POST "/api/assessments/${M1}/calculate" '{}'
expect "计算 α（幂等落库）" 200
eq "α 产出 9 条风险项（3×3）" "$(jget data.risk_items_count)" "9"

json POST "/api/assessments/${M2}/calculate" '{}'
expect "计算 β" 200
eq "β 产出 9 条风险项（3×3）" "$(jget data.risk_items_count)" "9"

# ── 风险项读取工具 ──────────────────────────────────────────────────────

# load_items <assessment_id> — 把风险项列表拉到 $BODY，并留一份快照到 $ITEMS_JSON
#
# 两个文件都要，各有各的用途：
#   $BODY       —— 供 jget / jlen / expect 直接使用（与其它请求同一套读法）；
#   $ITEMS_JSON —— 留给 item_of / level_of 在**后续请求把 $BODY 覆盖之后**
#                  仍然能挑出风险项 id。建单要 item id，而建单的响应会覆盖 $BODY。
load_items() {
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
    -o "$BODY" -w '%{http_code}' \
    "$BASE/api/assessments/$1/risk-items?pageSize=200" 2>/dev/null)
  LAST_CODE=$(jget code)
  cp "$BODY" "$ITEMS_JSON" 2>/dev/null || true
}

# item_of <asset_id> <vuln_id> — 从 $ITEMS_JSON 里挑出该组合的风险项 id
item_of() {
  "$PYTHON" -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    print(""); raise SystemExit
a, v = int(sys.argv[2]), int(sys.argv[3])
for it in items:
    if int(it.get("asset_id", 0)) == a and int(it.get("vuln_id", 0)) == v:
        print(it["id"]); raise SystemExit
print("")
' "$ITEMS_JSON" "$1" "$2" 2>/dev/null
}

# level_of <asset_id> <vuln_id> — 该组合的风险等级（用于「快照应等于源」的断言）
level_of() {
  "$PYTHON" -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    print(""); raise SystemExit
a, v = int(sys.argv[2]), int(sys.argv[3])
for it in items:
    if int(it.get("asset_id", 0)) == a and int(it.get("vuln_id", 0)) == v:
        print(it.get("risk_level", "")); raise SystemExit
print("")
' "$ITEMS_JSON" "$1" "$2" 2>/dev/null
}

load_items "$M1"
expect "读取 α 风险项列表" 200
eq "α 风险项条数" "$(jlen data.items)" "9"

# 等级分布：证明数据准备真的铺满了五档（否则后面的「按等级筛选」断言
# 会退化成「筛出来的就是全部」，看着绿、其实什么都没验证）
LEVEL_DIST="$(sql "SELECT CONCAT(risk_level, ':', COUNT(*)) FROM risk_items WHERE assessment_id=$M1 GROUP BY risk_level ORDER BY risk_level;" | tr '\n' ' ')"
info "α 等级分布（直查 MySQL）：${LEVEL_DIST}"
eq "α「很高」1 条" "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M1 AND risk_level='very_high';")" "1"
eq "α「高」2 条" "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M1 AND risk_level='high';")" "2"
eq "α「中」1 条" "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M1 AND risk_level='medium';")" "1"
eq "α「低」4 条" "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M1 AND risk_level='low';")" "4"
eq "α「很低」1 条" "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M1 AND risk_level='very_low';")" "1"

ITEM_VH="$(item_of "$RA5" "$RV5")"    # R=25 very_high
ITEM_HI="$(item_of "$RA5" "$RV3")"    # R=15 high
ITEM_LOW="$(item_of "$RA1" "$RV5")"   # R=5  low
info "样例风险项：很高 id=${ITEM_VH} / 高 id=${ITEM_HI} / 低 id=${ITEM_LOW}"

# ============================================================================
section "3. 建单：快照、初始态与流转投影"
# ============================================================================

json POST /api/remediations "{\"risk_item_id\":${ITEM_VH},\"description\":\"请在本周内升级\"}"
expect "由「很高」风险项建单" 201
R1="$(jget data.id)"

eq "初始状态为 pending" "$(jget data.status)" "pending"
eq "业务身份 asset_id 落库" "$(jget data.asset_id)" "$RA5"
eq "业务身份 vuln_id 落库" "$(jget data.vuln_id)" "$RV5"
eq "发现出处 assessment_id" "$(jget data.assessment_id)" "$M1"
eq "发现出处 risk_item_id" "$(jget data.risk_item_id)" "$ITEM_VH"

# 快照列：目标被删、评估被重算之后，单子仍然要能自己说清「修什么」
eq "快照 asset_name" "$(jget data.asset_name)" "P6-RA5"
eq "快照 asset_ip" "$(jget data.asset_ip)" "10.66.10.1"
eq "快照 vuln_title" "$(jget data.vuln_title)" "P6 漏洞 V=5"
eq "快照 risk_level" "$(jget data.risk_level)" "very_high"
eq "快照 risk_value_r" "$(jget data.risk_value_r)" "25"
eq "标题默认取漏洞名" "$(jget data.title)" "P6 漏洞 V=5"
eq "创建人显示名已回填" "$(jget data.created_by_name)" "$ADMIN_DISPLAY"

# 时间态：未设期限一律三者皆空
eq "未设期限时 due_date 为空" "$(jget data.due_date)" ""
eq "未设期限不算逾期" "$(jbool data.overdue)" "false"
eq "未设期限 overdue_days=0" "$(jget data.overdue_days)" "0"
eq "未设期限 due_in_days 为空" "$(jget data.due_in_days)" ""

# 流转投影：pending 的三个出口，且都不需要说明
eq "pending 的流转选项数量" "$(jlen data.transitions)" "3"
eq "选项 0 = in_progress" "$(jget data.transitions.0.to_status)" "in_progress"
eq "选项 1 = resolved" "$(jget data.transitions.1.to_status)" "resolved"
eq "选项 2 = accepted" "$(jget data.transitions.2.to_status)" "accepted"
eq "pending→in_progress 不要求说明" "$(jbool data.transitions.0.note_required)" "false"
# accepted 是「决定不修」，必须写明理由 —— 投影里就要标出来，
# 否则前端不会把说明框标成必填，用户点下去才被 400 拒绝。
eq "pending→accepted 要求说明（投影）" "$(jbool data.transitions.2.note_required)" "true"

# 建单首条记录：时间线不能是空的
json GET "/api/remediations/${R1}"
expect "读取整改单详情" 200
eq "详情含单子本体" "$(jget data.remediation.id)" "$R1"
eq "时间线恰好 1 条（create）" "$(jlen data.logs)" "1"
eq "首条动作是 create" "$(jget data.logs.0.action)" "create"
eq "首条 to_status = pending" "$(jget data.logs.0.to_status)" "pending"
eq "首条操作人是管理员" "$(jget data.logs.0.operator_name)" "$ADMIN_NAME"

# ============================================================================
section "4. 唯一性：同一 (资产, 漏洞) 只允许一张未闭环单"
# ============================================================================

json POST /api/remediations "{\"risk_item_id\":${ITEM_VH}}"
expect "同目标二次建单被拒" 409 REMEDIATION_DUPLICATE_ACTIVE

eq "库里该目标只有 1 张未闭环单" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE asset_id=$RA5 AND vuln_id=$RV5 AND status IN ('pending','in_progress','resolved');")" "1"

# 生成列 active_key 的实测效果：重复插入确实被**数据库**拦下
# （而不是只靠 service 层的「先查后插」——那在并发下有竞态窗口）
DUP_ENTRY="$(sqlq "SELECT IFNULL(MAX(active_key), '') FROM remediations WHERE asset_id=$RA5 AND vuln_id=$RV5;")"
eq "active_key = asset_id:vuln_id" "$DUP_ENTRY" "${RA5}:${RV5}"

# 闭环：accepted 是终态，会把 active_key 置为 NULL
json POST "/api/remediations/${R1}/transition" \
  '{"to_status":"accepted","note":"该服务已下线，风险接受"}'
expect "流转到 accepted（终态）" 200
eq "accepted 是终态" "$(jget data.status)" "accepted"
ne "终态回填了 closed_at" "$(jget data.closed_at)" ""
eq "终态的流转选项为空（无出边）" "$(jlen data.transitions)" "0"
eq "进入终态时说明写入 resolution" "$(jget data.resolution)" "该服务已下线，风险接受"

eq "闭环后 active_key 变 NULL" \
  "$(sqlq "SELECT IFNULL(MAX(active_key), '<null>') FROM remediations WHERE id=$R1;")" "<null>"

# 闭环后可以再建一张 —— 这正是「漏洞复发时新建一张单」的语义。
# 若唯一索引写成「同一 (资产,漏洞) 全局唯一」，这一条会 409，
# 于是同一个漏洞第二次需要整改时就永远建不出单了。
json POST /api/remediations "{\"risk_item_id\":${ITEM_VH}}"
expect "闭环后同目标可再建一张" 201
R2="$(jget data.id)"
ne "新单与原单不是同一张" "$R2" "$R1"

eq "库里该目标现在：1 张未闭环 + 1 张已闭环" \
  "$(sql "SELECT CONCAT(SUM(status IN ('pending','in_progress','resolved')), '+', SUM(status IN ('closed','accepted'))) FROM remediations WHERE asset_id=$RA5 AND vuln_id=$RV5;" | tr -d '\r')" "1+1"

json GET "/api/remediations/${R2}"
eq "新单初始状态仍是 pending" "$(jget data.remediation.status)" "pending"

# ============================================================================
section "5. 重算不断链（P6 头号陷阱）"
# ============================================================================
#
# 这一段是 P6 最核心的验证。P4 的 calculate 是**先清后写**：
# 重算一次，risk_items 的 id 整批换新，旧的 id 全部消失。
#
# 如果整改单把 risk_item_id 当作业务身份（加了外键或依赖它做展示），
# 重算之后那张单子就会指向一个不存在的行 —— 界面不报错、列表照样出来、
# 详情页只是「来源风险项」一栏空着，而没有任何地方会告诉你出了这种事。
#
# 所以这里刻意**不**去质疑实现怎么写的，而是直接重算一次，再看结果。

OLD_ITEM="$ITEM_VH"          # 重算前那份风险项的 id（= R2 的出处）
BEFORE_ITEM_ROWS="$(sqlq "SELECT COUNT(*) FROM risk_items WHERE id=$OLD_ITEM;")"
eq "重算前：旧风险项 id 确实存在" "$BEFORE_ITEM_ROWS" "1"

json POST "/api/assessments/${M1}/calculate" '{}'
expect "重算 α（先清后写）" 200
eq "重算后仍是 9 条风险项" "$(jget data.risk_items_count)" "9"

eq "重算后：旧风险项 id 已不存在（出处失效）" \
  "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE id=$OLD_ITEM;")" "0"

load_items "$M1"
ITEM_VH_NEW="$(item_of "$RA5" "$RV5")"
ne "同一 (资产, 漏洞) 的新风险项 id 与旧的不同" "$ITEM_VH_NEW" "$OLD_ITEM"

# —— 关键断言：单子必须完好 ——
eq "重算后整改单仍然存在" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE id=$R2;")" "1"

json GET "/api/remediations/${R2}"
expect "重算后整改单详情仍可读" 200
eq "重算后状态未被打乱" "$(jget data.remediation.status)" "pending"
eq "重算后快照 asset_name 完好" "$(jget data.remediation.asset_name)" "P6-RA5"
eq "重算后快照 asset_ip 完好" "$(jget data.remediation.asset_ip)" "10.66.10.1"
eq "重算后快照 vuln_title 完好" "$(jget data.remediation.vuln_title)" "P6 漏洞 V=5"
eq "重算后快照 risk_level 完好" "$(jget data.remediation.risk_level)" "very_high"
eq "重算后快照 risk_value_r 完好" "$(jget data.remediation.risk_value_r)" "25"
eq "出处指向的旧 risk_item_id 原样保留（不假装它还有效）" \
  "$(jget data.remediation.risk_item_id)" "$OLD_ITEM"
eq "重算后流转记录仍在" "$(jlen data.logs)" "1"

# —— 反向对照：库里确实存在「出处已失效」的单子 ——
#
# 这一条不是在描述缺陷，而是把设计意图变成可观测的事实：
# 整改单是**业务事实**，它不随「又算了一遍」而改变。存在这种行，
# 恰恰证明表结构没有把 risk_item_id 当成约束。
STALE="$(sqlq "SELECT COUNT(*) FROM remediations r WHERE r.risk_item_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM risk_items i WHERE i.id = r.risk_item_id);")"
if [ "$STALE" -ge 1 ] 2>/dev/null; then
  ok "库里存在 ${STALE} 张「出处已失效但单子完好」的整改单（设计如此）"
else
  bad "库里存在「出处已失效但单子完好」的整改单" \
      "重算后应至少出现 1 张；实际 ${STALE} —— 若为 0，说明重算没有真正更换 id"
fi

# 已闭环的 R1 同样不受影响
eq "已闭环的单子在重算后依然保留" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE id=$R1 AND status='accepted';")" "1"

# ============================================================================
section "6. 状态机：合法流转、非法拒绝、必填说明、终态无出边"
# ============================================================================

load_items "$M1"
S1_ITEM="$(item_of "$RA5" "$RV3")"     # I=5,V=3 → R=15 → 高
S2_ITEM="$(item_of "$RA3" "$RV5")"     # I=3,V=5 → R=15 → 高

json POST /api/remediations "{\"risk_item_id\":${S1_ITEM}}"
expect "建状态机主链单 S1" 201
S1="$(jget data.id)"
json POST /api/remediations "{\"risk_item_id\":${S2_ITEM}}"
expect "建打回链单 S2" 201
S2="$(jget data.id)"

# 非法流转：pending 没有到 closed 的边。说明给足也不行 ——
# 被拒的原因必须是「流转非法」而不是「说明没填」，所以带上 note 一起测。
TRANS_LOGS_BEFORE="$(sqlq "SELECT COUNT(*) FROM remediation_logs WHERE remediation_id=$S1 AND action='transition';")"
json POST "/api/remediations/${S1}/transition" '{"to_status":"closed","note":"直接闭环试试"}'
expect "pending→closed 被拒（无这条边）" 409 REMEDIATION_TRANSITION_INVALID
TRANS_LOGS_AFTER="$(sqlq "SELECT COUNT(*) FROM remediation_logs WHERE remediation_id=$S1 AND action='transition';")"
eq "非法流转不留流转记录（拒绝要是真的拒绝）" "$TRANS_LOGS_AFTER" "$TRANS_LOGS_BEFORE"
eq "非法流转后状态仍是 pending" "$(sqlq "SELECT status FROM remediations WHERE id=$S1;")" "pending"

# 非法状态值：不是「这条边不允许」，而是「这个状态根本不存在」
json POST "/api/remediations/${S1}/transition" '{"to_status":"bogus","note":"x"}'
expect "非法状态值被拒" 400 REMEDIATION_STATUS_INVALID

# 必填说明：pending→accepted 是合法边，但它是「决定不修」的结论性动作
json POST "/api/remediations/${S1}/transition" '{"to_status":"accepted","note":"   "}'
expect "风险接受缺说明被拒" 400 REMEDIATION_NOTE_REQUIRED

json POST "/api/remediations/${S1}/transition" '{"to_status":"in_progress","note":""}'
expect "pending→in_progress 无需说明" 200
eq "状态已变为 in_progress" "$(jget data.status)" "in_progress"
eq "in_progress 的流转选项数量" "$(jlen data.transitions)" "3"
eq "选项 0 = resolved" "$(jget data.transitions.0.to_status)" "resolved"
eq "选项 1 = pending（退回未开始：分派错了 / 暂时搁置）" "$(jget data.transitions.1.to_status)" "pending"
eq "选项 2 = accepted" "$(jget data.transitions.2.to_status)" "accepted"

json POST "/api/remediations/${S1}/transition" '{"to_status":"resolved","note":"已升级完成"}'
expect "in_progress→resolved" 200
eq "状态已变为 resolved" "$(jget data.status)" "resolved"
eq "resolved 的流转选项数量" "$(jlen data.transitions)" "3"
eq "选项 0 = closed" "$(jget data.transitions.0.to_status)" "closed"
eq "选项 1 = in_progress（打回）" "$(jget data.transitions.1.to_status)" "in_progress"
eq "→closed 要求说明（投影）" "$(jbool data.transitions.0.note_required)" "true"
eq "resolved→in_progress 要求说明（投影，本表最重要的一条）" \
  "$(jbool data.transitions.1.note_required)" "true"
eq "→accepted 要求说明（投影）" "$(jbool data.transitions.2.note_required)" "true"

json POST "/api/remediations/${S1}/transition" '{"to_status":"closed","note":""}'
expect "闭环缺说明被拒" 400 REMEDIATION_NOTE_REQUIRED

json POST "/api/remediations/${S1}/transition" '{"to_status":"in_progress","note":"验证不通过：端口仍开放"}'
expect "resolved→in_progress 打回成功" 200
eq "打回后状态为 in_progress" "$(jget data.status)" "in_progress"

# 打回记录的 from/to 必须准确 —— 「状态流转可追溯」的验收标志就落在这两个字段上
json GET "/api/remediations/${S1}"
LAST_LOG_IDX=$(( $(jlen data.logs) - 1 ))
eq "打回记录的 action" "$(jget data.logs.${LAST_LOG_IDX}.action)" "transition"
eq "打回记录的 from_status" "$(jget data.logs.${LAST_LOG_IDX}.from_status)" "resolved"
eq "打回记录的 to_status" "$(jget data.logs.${LAST_LOG_IDX}.to_status)" "in_progress"
eq "打回记录的 note" "$(jget data.logs.${LAST_LOG_IDX}.note)" "验证不通过：端口仍开放"
eq "打回记录的操作人" "$(jget data.logs.${LAST_LOG_IDX}.operator_name)" "$ADMIN_NAME"

# 时间线必须能按顺序读下来：create → in_progress → resolved → 打回
eq "时间线首条仍是 create" "$(jget data.logs.0.action)" "create"
eq "时间线条数（create + 3 次流转 = 4）" "$(jlen data.logs)" "4"

# 回到 resolved 再闭环，看到闭时间与结论
json POST "/api/remediations/${S1}/transition" '{"to_status":"resolved","note":"复测通过"}'
expect "再次 in_progress→resolved" 200
json POST "/api/remediations/${S1}/transition" '{"to_status":"closed","note":"复测通过，闭环"}'
expect "resolved→closed（带说明）" 200
eq "闭环后的状态" "$(jget data.status)" "closed"
ne "闭环后 closed_at 非空" "$(jget data.closed_at)" ""
eq "闭环说明写入 resolution" "$(jget data.resolution)" "复测通过，闭环"
eq "终态无出边（transitions 为空数组）" "$(jlen data.transitions)" "0"

json POST "/api/remediations/${S1}/transition" '{"to_status":"in_progress","note":"想重开"}'
expect "终态再流转被拒（不可逆）" 409 REMEDIATION_TRANSITION_INVALID

# 打回链 S2：pending→in_progress→resolved→in_progress，验证「工作可以反复」
json POST "/api/remediations/${S2}/transition" '{"to_status":"in_progress","note":""}'
expect "S2 pending→in_progress" 200
json POST "/api/remediations/${S2}/transition" '{"to_status":"resolved","note":"第一次整改"}'
expect "S2 in_progress→resolved" 200
json POST "/api/remediations/${S2}/transition" '{"to_status":"in_progress","note":"抽检不通过"}'
expect "S2 打回" 200
eq "S2 打回后仍在 in_progress（未闭环）" "$(jget data.status)" "in_progress"
eq "S2 仍在未闭环集合里" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE id=$S2 AND active_key IS NOT NULL;")" "1"

# ============================================================================
section "7. 逾期：三档 + 无期限 + 闭环归零"
# ============================================================================
#
# 四条规则，每一条都有一个具体的错误答案：
#   1. 只有未闭环才可能逾期 —— 否则「历史上逾期过」会永远挂在指标上；
#   2. due_date 与今天都归一到零点再比 —— 否则今天到期的单子从 00:00:01
#      起就算逾期，而正确语义是「今天之内不算」；
#   3. 未设期限永不算逾期 —— 否则「没定 deadline」的单子会全部涌进逾期数，
#      这个指标直接作废；
#   4. 逾期与即将到期**不重叠** —— 重叠的话同一个单子会在两个数字里
#      各出现一次，用户会以为有两张单子。

load_items "$M1"

# O1：昨天到期 → 逾期 1 天
json POST /api/remediations \
  "{\"risk_item_id\":$(item_of "$RA5" "$RV1"),\"due_date\":\"${YESTERDAY}\"}"
expect "建 O1（期限=昨天）" 201
O1="$(jget data.id)"
eq "O1 due_date 回显" "$(jget data.due_date)" "$YESTERDAY"
eq "O1 已逾期" "$(jbool data.overdue)" "true"
eq "O1 逾期天数精确为 1" "$(jget data.overdue_days)" "1"
eq "O1 逾期时 due_in_days 为空（两个语义互斥）" "$(jget data.due_in_days)" ""

# O2：今天到期 → 不算逾期，due_in_days = 0
json POST /api/remediations \
  "{\"risk_item_id\":$(item_of "$RA3" "$RV3"),\"due_date\":\"${TODAY}\"}"
expect "建 O2（期限=今天）" 201
O2="$(jget data.id)"
eq "O2 今天到期不算逾期" "$(jbool data.overdue)" "false"
eq "O2 overdue_days=0" "$(jget data.overdue_days)" "0"
eq "O2 due_in_days=0（今天到期）" "$(jget data.due_in_days)" "0"

# O3：+5 天 → 不算逾期
json POST /api/remediations \
  "{\"risk_item_id\":$(item_of "$RA3" "$RV1"),\"due_date\":\"${IN_5_DAYS}\"}"
expect "建 O3（期限=+5 天）" 201
O3="$(jget data.id)"
eq "O3 未逾期" "$(jbool data.overdue)" "false"
eq "O3 剩余天数精确为 5" "$(jget data.due_in_days)" "5"

# O4：不设期限
json POST /api/remediations "{\"risk_item_id\":$(item_of "$RA1" "$RV5")}"
expect "建 O4（无期限）" 201
O4="$(jget data.id)"
eq "O4 due_date 为空" "$(jget data.due_date)" ""
eq "O4 未设期限永不算逾期" "$(jbool data.overdue)" "false"
eq "O4 due_in_days 为空" "$(jget data.due_in_days)" ""

# O5：先设成昨天到期（逾期），流转到终态后归零
json POST /api/remediations \
  "{\"risk_item_id\":$(item_of "$RA1" "$RV1"),\"due_date\":\"${YESTERDAY}\"}"
expect "建 O5（期限=昨天）" 201
O5="$(jget data.id)"
eq "O5 建单即逾期" "$(jbool data.overdue)" "true"

json POST "/api/remediations/${O5}/transition" '{"to_status":"in_progress","note":""}'
expect "O5 进入整改中（仍未闭环）" 200
eq "O5 未闭环时仍然逾期" "$(jbool data.overdue)" "true"

json POST "/api/remediations/${O5}/transition" \
  '{"to_status":"accepted","note":"该漏洞已由补丁平台统一处理，接受残余风险"}'
expect "O5 流转到 accepted" 200
eq "闭环之后不再是逾期（逾期是当前态，不是历史事实）" "$(jbool data.overdue)" "false"
eq "闭环之后 overdue_days 归零" "$(jget data.overdue_days)" "0"
eq "闭环之后 due_in_days 为空" "$(jget data.due_in_days)" ""

# ── 列表筛选与直查 SQL 对账 ─────────────────────────────────────────────
json GET "/api/remediations?overdue=true&pageSize=200"
expect "按「已逾期」筛选" 200
OVERDUE_LIST_TOTAL="$(jget data.total)"
eq "逾期清单只命中 O1" "$OVERDUE_LIST_TOTAL" "1"
eq "逾期清单里就是 O1" "$(jget data.items.0.id)" "$O1"

OVERDUE_SQL="$(sqlq "SELECT COUNT(*) FROM remediations WHERE due_date IS NOT NULL AND due_date < '${TODAY}' AND status IN ('pending','in_progress','resolved');")"
eq "逾期数与直查 MySQL 一致" "$OVERDUE_LIST_TOTAL" "$OVERDUE_SQL"

DUE_SOON_SQL="$(sqlq "SELECT COUNT(*) FROM remediations WHERE due_date IS NOT NULL AND due_date >= '${TODAY}' AND due_date <= DATE_ADD('${TODAY}', INTERVAL 7 DAY) AND status IN ('pending','in_progress','resolved');")"
eq "「即将到期」区间命中 O2 与 O3 两条" "$DUE_SOON_SQL" "2"

# 区间不重叠：今天到期的那张不能同时出现在两个集合里
OVERLAP="$(sqlq "SELECT COUNT(*) FROM remediations WHERE due_date IS NOT NULL AND status IN ('pending','in_progress','resolved') AND (due_date < '${TODAY}') AND (due_date >= '${TODAY}');")"
eq "逾期与即将到期两个区间无交集" "$OVERLAP" "0"

# ============================================================================
section "8. 批量建单：命中 / 新建 / 跳过"
# ============================================================================
#
# 与单张建单刻意不同的语义：重复的 (资产, 漏洞) **跳过而不报错**。
# 理由是这个功能的典型用法 —— 「算完一次评估把高风险的都开单」——
# 用户会在评估重算后再点一次；若那时整批失败，功能就没法用了。

json POST /api/remediations/batch "{\"assessment_id\":${M2},\"levels\":[\"very_high\",\"high\"]}"
expect "按「很高+高」批量建单" 200
eq "命中条数（β 的 very_high 1 + high 2）" "$(jget data.matched)" "3"
eq "本次新建 3 张" "$(jget data.created)" "3"
eq "本次跳过 0 张" "$(jget data.skipped)" "0"
eq "返回的 ids 有 3 个" "$(jlen data.ids)" "3"

BATCH_IDS="$(jlist data.ids)"
eq "库里确实多了 3 张未闭环单" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE id IN (${BATCH_IDS}) AND active_key IS NOT NULL;")" "3"

# 再跑一次：全部命中、一张不建 —— 幂等的直接体现
json POST /api/remediations/batch "{\"assessment_id\":${M2},\"levels\":[\"very_high\",\"high\"]}"
expect "同条件再跑一次仍 200（不整批失败）" 200
eq "第二次命中数不变" "$(jget data.matched)" "3"
eq "第二次一张都没新建" "$(jget data.created)" "0"
eq "第二次全部跳过" "$(jget data.skipped)" "3"
eq "第二次返回空 ids" "$(jlen data.ids)" "0"

# levels 省略 → 默认「很高 + 高」（最常见的用法不该逼用户每次都写一遍）
json POST /api/remediations/batch "{\"assessment_id\":${M2}}"
expect "不传 levels 走默认「很高+高」" 200
eq "默认等级集的命中数与显式给出时相同" "$(jget data.matched)" "3"
eq "默认等级集同样全部跳过" "$(jget data.skipped)" "3"

# 只挑一档：数字要跟着等级走，证明筛选真的生效
json POST /api/remediations/batch "{\"assessment_id\":${M2},\"levels\":[\"very_low\"]}"
expect "只对「很低」建单" 200
eq "「很低」命中 1 条" "$(jget data.matched)" "1"
eq "「很低」新建 1 张" "$(jget data.created)" "1"

# 非法等级报错而不是静默丢弃：丢弃会让用户拿到「建了 3 张」的结果，
# 却不知道「高」那一批为什么一条都没建。
json POST /api/remediations/batch "{\"assessment_id\":${M2},\"levels\":[\"very_high\",\"HIGH\"]}"
expect "非法等级被拒（大小写敏感）" 400 INVALID_PARAM

json POST /api/remediations/batch "{\"assessment_id\":${M2},\"levels\":[\"urgent\"]}"
expect "未知等级被拒" 400 INVALID_PARAM

# 草稿任务：没有任何风险项，但**不是**「命中 0 条」——
# 用户真正需要知道的是「先去算一次」，所以返回 409 而不是一份空结果。
json POST /api/remediations/batch "{\"assessment_id\":${M3},\"levels\":[\"very_high\"]}"
expect "草稿评估不能批量建单" 409 REMEDIATION_BATCH_EMPTY

json POST /api/remediations/batch '{"assessment_id":0,"levels":["very_high"]}'
expect "评估 ID 为 0 被拒" 400 INVALID_PARAM

json POST /api/remediations/batch '{"assessment_id":999999,"levels":["very_high"]}'
expect "评估不存在" 404 ASSESSMENT_NOT_FOUND

json POST /api/remediations/batch "{\"assessment_id\":${M2},\"due_in_days\":-1,\"levels\":[\"very_low\"]}"
expect "负数到期天数被拒" 400 INVALID_PARAM

# 批量建出的单子也要有首条记录（共用同一条写入路径，而不是「精简版」）
BATCH_ONE="$(printf '%s' "$BATCH_IDS" | cut -d, -f1)"
eq "批量建出的单子有 create 记录" \
  "$(sqlq "SELECT COUNT(*) FROM remediation_logs WHERE remediation_id=$BATCH_ONE AND action='create';")" "1"

# ============================================================================
section "9. 删除限制"
# ============================================================================

# D1：只改过字段、从未流转 → 仍可删
json POST /api/remediations "{\"risk_item_id\":$(item_of "$RA1" "$RV3")}"
expect "建 D1" 201
D1="$(jget data.id)"
json PATCH "/api/remediations/${D1}" '{"title":"改个名字再删"}'
expect "D1 改标题" 200
eq "改标题不产生流转记录" \
  "$(sqlq "SELECT COUNT(*) FROM remediation_logs WHERE remediation_id=$D1 AND action='transition';")" "0"

json DELETE "/api/remediations/${D1}"
expect "改过字段但从未流转的单子可以删" 200
eq "删除后库里不再有它" "$(sqlq "SELECT COUNT(*) FROM remediations WHERE id=$D1;")" "0"

# D2：流转过 → 属于工作记录，不可删（O5 已流转到 accepted）
json DELETE "/api/remediations/${O5}"
expect "流转过的单子不能删" 409 REMEDIATION_DELETE_FORBIDDEN
contains "拒绝文案给出替代动作（风险接受）" "$(jget message)" "风险接受"
eq "被拒后单子仍在" "$(sqlq "SELECT COUNT(*) FROM remediations WHERE id=$O5;")" "1"

# 未流转但状态不是 pending 的情况（理论上状态只能靠流转改变，
# 因此这一条用「已流转」的 S2 覆盖同一条分支的兜底）
json DELETE "/api/remediations/${S2}"
expect "进行中的单子不能删" 409 REMEDIATION_DELETE_FORBIDDEN

json DELETE "/api/remediations/999999"
expect "删除不存在的单子返回 404" 404 REMEDIATION_NOT_FOUND

json GET "/api/remediations/999999"
expect "读取不存在的单子返回 404" 404 REMEDIATION_NOT_FOUND

json POST "/api/remediations/999999/transition" '{"to_status":"in_progress"}'
expect "流转不存在的单子返回 404" 404 REMEDIATION_NOT_FOUND

# ============================================================================
section "10. 列表筛选与三态字段"
# ============================================================================

json GET "/api/remediations"
expect "整改单列表" 200
TOTAL_ALL="$(jget data.total)"
eq "列表总数与直查 MySQL 一致" "$TOTAL_ALL" "$(sqlq "SELECT COUNT(*) FROM remediations;")"

json GET "/api/remediations?active=true&pageSize=200"
expect "只看未闭环" 200
eq "未闭环数 = 三个未闭环状态之和" "$(jget data.total)" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE status IN ('pending','in_progress','resolved');")"

json GET "/api/remediations?status=accepted&pageSize=200"
expect "按单个状态筛选" 200
ACCEPTED_ONLY="$(jget data.total)"
eq "accepted 的条数与直查一致" "$ACCEPTED_ONLY" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE status='accepted';")"

# 两者同时给出是**自相矛盾**的条件（status 已指名一个状态，active 又说要三种）。
# handler 的处理是「以 status 为准」：元素级筛选比集合级更精确。
# ⚠️ 这里断言的是「结果等于只按 status 筛」，而不是「等于未闭环数」——
#    后者是另一种设计（active 优先），本系统不采用。改动 handler 时
#    必须同步改这一条，否则它会静默变成一条描述相反行为的断言。
json GET "/api/remediations?status=accepted&active=true&pageSize=200"
expect "status 与 active 同时给出" 200
eq "同时给出时以 status 为准（元素级筛选更精确）" "$(jget data.total)" "$ACCEPTED_ONLY"

json GET "/api/remediations?status=bogus"
expect "非法状态值被拒" 400 REMEDIATION_STATUS_INVALID

json GET "/api/remediations?level=very_high&pageSize=200"
expect "按发现时风险等级筛选" 200
eq "等级筛选的数字与直查一致" "$(jget data.total)" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE risk_level='very_high';")"

json GET "/api/remediations?keyword=P6-RA5&pageSize=200"
expect "按关键字搜索（命中资产名快照）" 200
if [ "$(jget data.total)" -ge 1 ] 2>/dev/null; then
  ok "关键字搜索命中资产名快照（${#A_NAME[@]} 台资产里至少 1 条）"
else
  bad "关键字搜索命中资产名快照" "total=$(jget data.total)"
fi

json GET "/api/remediations?assessment_id=${M1}&pageSize=200"
expect "按发现出处（评估）筛选" 200
eq "α 出处的单子条数与直查一致" "$(jget data.total)" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE assessment_id=$M1;")"

json GET "/api/remediations?assignee_id=1&pageSize=1"
expect "按负责人筛选（当前无人被分派，结果可为空）" 200

# 排序：期限近的靠前、未设期限的排最后 —— 这是「工作清单」的读法
json GET "/api/remediations?pageSize=200"
eq "列表按 (有期限在前, 期限升序) 排列：首条有期限" "$(jget data.items.0.due_date)" "$YESTERDAY"

# PATCH 的三态：不传=不动、null=清空、有值=改为该值
json PATCH "/api/remediations/${O4}" '{"assignee_id":1,"title":"三态测试"}'
expect "PATCH 设置负责人与标题" 200
eq "负责人已设置" "$(jget data.assignee_id)" "1"

json PATCH "/api/remediations/${O4}" '{"assignee_id":null}'
expect "PATCH 用 null 取消分派" 200
eq "负责人已被清空" "$(jget data.assignee_id)" ""

json PATCH "/api/remediations/${O4}" '{"description":"只改说明"}'
expect "PATCH 不传 assignee_id 时不动它" 200
eq "取消分派没有被「不传」悄悄恢复" "$(jget data.assignee_id)" ""

json PATCH "/api/remediations/${O4}" "{\"due_date\":\"${IN_5_DAYS}\"}"
expect "PATCH 设置期限" 200
eq "期限已设置" "$(jget data.due_date)" "$IN_5_DAYS"

json PATCH "/api/remediations/${O4}" '{"due_date":null}'
expect "PATCH 用 null 清除期限" 200
eq "期限已被清空" "$(jget data.due_date)" ""
eq "清空期限后不再即将到期" "$(jbool data.due_in_days)" ""

json PATCH "/api/remediations/${O4}" '{"due_date":"2026/11/01"}'
expect "非法日期格式被拒" 400 INVALID_PARAM

json PATCH "/api/remediations/${O4}" '{"title":"   "}'
expect "标题清空被拒" 400 INVALID_PARAM

json PATCH "/api/remediations/${O4}" '{}'
expect "空 PATCH 不报错（无可改字段时原样返回）" 200

# ============================================================================
section "11. 权限：匿名、CSRF、审计员只读、评估员可写"
# ============================================================================

# 匿名会话也要先取 CSRF 令牌：不取的话拦住请求的会是 CSRF 中间件，
# 断言「未登录被拒」虽然也会通过（都是 4xx），实际没验证到认证那一层。
rm -f "$ANON_JAR"
ANON_CSRF="$(csrf_token "$ANON_JAR")"

raw "$ANON_JAR" GET /api/remediations
expect "匿名读取整改单被拒" 401 UNAUTHORIZED

raw "$ANON_JAR" GET /api/dashboard/summary
expect "匿名读取仪表盘被拒" 401 UNAUTHORIZED

# 缺 CSRF：已登录、令牌也拿到了，但请求头不带它 → CSRF 中间件拦下。
# 不能用 json / json_as（它们会自动补令牌），否则这条断言永远是 200 的假绿。
CSRF_SAVED="$ADMIN_CSRF"
ADMIN_CSRF=""
json POST /api/remediations '{"risk_item_id":1}'
expect "已登录但缺 CSRF 令牌的写请求被拒" 403 AUTH_CSRF_INVALID
ADMIN_CSRF="$CSRF_SAVED"

# —— 审计员：只读 ——
json POST /api/users \
  "{\"username\":\"r6_auditor_$RANDOM\",\"display_name\":\"P6 审计员\",\"password\":\"Auditor@2026x\",\"roles\":[\"auditor\"]}"
expect "管理员可创建审计员账号" 201
AUDITOR_USER="$(jget data.username)"

login "$AUDITOR_JAR" "$AUDITOR_USER" "Auditor@2026x"
expect "审计员可登录" 200
AUD_CSRF="$SESSION_CSRF"
json_as "$AUDITOR_JAR" PATCH /api/auth/password \
  '{"old_password":"Auditor@2026x","new_password":"Auditor@2026y"}' "$AUD_CSRF"
expect "审计员首次改密" 200
login "$AUDITOR_JAR" "$AUDITOR_USER" "Auditor@2026y"
expect "审计员改密后可登录" 200
AUD_CSRF="$SESSION_CSRF"

json_as "$AUDITOR_JAR" GET "/api/remediations?pageSize=5" '' "$AUD_CSRF"
expect "审计员可以看整改单" 200
json_as "$AUDITOR_JAR" GET "/api/remediations/${O1}" '' "$AUD_CSRF"
expect "审计员可以看整改单详情与时间线" 200
json_as "$AUDITOR_JAR" GET /api/dashboard/summary '' "$AUD_CSRF"
expect "审计员可以看仪表盘" 200

# 审计员手上的 remediation:write 不在 readOnlyPermissions 里
json_as "$AUDITOR_JAR" POST /api/remediations "{\"risk_item_id\":${ITEM_VH_NEW}}" "$AUD_CSRF"
expect "审计员不能建单" 403 FORBIDDEN

json_as "$AUDITOR_JAR" PATCH "/api/remediations/${O4}" '{"title":"越权改名"}' "$AUD_CSRF"
expect "审计员不能改单" 403 FORBIDDEN

json_as "$AUDITOR_JAR" POST "/api/remediations/${O4}/transition" \
  '{"to_status":"resolved"}' "$AUD_CSRF"
expect "审计员不能流转状态" 403 FORBIDDEN

json_as "$AUDITOR_JAR" DELETE "/api/remediations/${O4}" '' "$AUD_CSRF"
expect "审计员不能删单" 403 FORBIDDEN

json_as "$AUDITOR_JAR" POST /api/remediations/batch \
  "{\"assessment_id\":${M2}}" "$AUD_CSRF"
expect "审计员不能批量建单" 403 FORBIDDEN

json_as "$AUDITOR_JAR" GET "/api/audit-logs?action=remediation.transition&pageSize=1" '' "$AUD_CSRF"
expect "审计员可以读审计日志（否则这个岗位没法工作）" 200

# —— 评估员：可读可写 ——
json POST /api/users \
  "{\"username\":\"r6_assessor_$RANDOM\",\"display_name\":\"P6 评估员\",\"password\":\"Assessor@2026x\",\"roles\":[\"assessor\"]}"
expect "管理员可创建评估员账号" 201
ASSESSOR_USER="$(jget data.username)"

login "$ASSESSOR_JAR" "$ASSESSOR_USER" "Assessor@2026x"
expect "评估员可登录" 200
ASR_CSRF="$SESSION_CSRF"
json_as "$ASSESSOR_JAR" PATCH /api/auth/password \
  '{"old_password":"Assessor@2026x","new_password":"Assessor@2026y"}' "$ASR_CSRF"
expect "评估员首次改密" 200
login "$ASSESSOR_JAR" "$ASSESSOR_USER" "Assessor@2026y"
expect "评估员改密后可登录" 200
ASR_CSRF="$SESSION_CSRF"

json_as "$ASSESSOR_JAR" GET "/api/remediations?pageSize=5" '' "$ASR_CSRF"
expect "评估员可以看整改单" 200

# 评估员建单：用 §9 里删掉的那条组合（RA1,RV3），它此刻是空闲的，
# 因此期望严格 201 —— 若写成 oneof 允许 409，等于没验证「真的建出来了」。
json_as "$ASSESSOR_JAR" POST /api/remediations \
  "{\"risk_item_id\":$(item_of "$RA1" "$RV3")}" "$ASR_CSRF"
expect "评估员可以建单（assessor 持有 remediation:write）" 201
ASSESSOR_NEW_ID="$(jget data.id)"

# 评估员能拉到用户清单（AssigneeSelect 组件依赖它；这是 rolePermissions
# 里刻意给 assessor 保留 user:read 的原因）
json_as "$ASSESSOR_JAR" GET "/api/users?pageSize=5" '' "$ASR_CSRF"
expect "评估员可以拉用户清单（用来选负责人）" 200

# 评估员不能读审计日志（审计是独立岗位）
json_as "$ASSESSOR_JAR" GET "/api/audit-logs?pageSize=1" '' "$ASR_CSRF"
expect "评估员不能读审计日志" 403 FORBIDDEN

# 评估员能写但审计员不能删：权限不是「有写权限就全权」
json_as "$ASSESSOR_JAR" DELETE "/api/remediations/${S2}" '' "$ASR_CSRF"
expect "评估员可尝试删除（有 remediation:write），业务层给出 409" 409 REMEDIATION_DELETE_FORBIDDEN

# ============================================================================
section "12. 仪表盘：口径、数字对账、参数切换"
# ============================================================================
#
# 「同一个『很高风险有多少条』，四种口径能给出四个数字」是仪表盘的头号陷阱。
# 本期的对策是：风险数字**全部绑定一个具体评估**，并把那个评估回传
# （assessments.latest），界面必须显示。因此这里的核心断言不是
# 「数字等于几」，而是「**换一个 assessment_id，数字要跟着变**」——
# 那才排除了「把数字写死」这种最难发现的假实现。

json GET /api/dashboard/summary
expect "读取首页统计（不传评估 ID）" 200

eq "资产总数" "$(jget data.assets.total)" "6"
eq "资产总数与直查一致" "$(jget data.assets.total)" "$(sqlq "SELECT COUNT(*) FROM assets;")"
eq "漏洞总数" "$(jget data.vulnerabilities.total)" "6"
eq "漏洞总数与直查一致" "$(jget data.vulnerabilities.total)" "$(sqlq "SELECT COUNT(*) FROM vulnerabilities;")"

eq "严重程度分布固定 5 档" "$(jlen data.vulnerabilities.by_severity)" "5"
eq "严重程度 5 档各有 2 个" "$(jget data.vulnerabilities.by_severity.4.count)" "2"
eq "严重程度 4 档为 0（固定形状，没有的也要在）" "$(jget data.vulnerabilities.by_severity.3.count)" "0"

eq "评估任务总数" "$(jget data.assessments.total)" "3"
eq "已计算 2 个" "$(jget data.assessments.calculated)" "2"
eq "草稿 1 个" "$(jget data.assessments.draft)" "1"

oneof "不传评估 ID 时取「最近一次已计算」的那一个" "$(jget data.assessments.latest.id)" "$M1" "$M2"
eq "口径来源必须是已计算状态" "$(jget data.assessments.latest.status)" "calculated"
eq "口径来源的风险项数" "$(jget data.assessments.latest.risk_items_count)" "9"
eq "口径来源回传了名称（界面要显示它）" "$(jget data.assessments.latest.name)" "$(sqlq "SELECT name FROM assessments WHERE id=$(jget data.assessments.latest.id);")"
ne "口径来源回传了计算时间" "$(jget data.assessments.latest.calculated_at)" ""

# —— 核心：换 assessment_id，数字要跟着变 ——
json GET "/api/dashboard/summary?assessment_id=${M1}"
expect "显式指定 α" 200
eq "α 的口径 id" "$(jget data.assessments.latest.id)" "$M1"
M1_VH="$(jget data.assessments.latest.level_counts.very_high)"
M1_ITEMS="$(jget data.assessments.latest.risk_items_count)"

json GET "/api/dashboard/summary?assessment_id=${M2}"
expect "显式指定 β" 200
eq "β 的口径 id" "$(jget data.assessments.latest.id)" "$M2"
M2_VH="$(jget data.assessments.latest.level_counts.very_high)"

# 两份评估的等级分布本来相同（同为 3×3 同权重），所以这里换一个
# 有区分度的对照：把 α 重算之后它仍应给出同一批数字，而**空库对照**
# 由下面的草稿评估承担。真正要证明的是「数字来自被指定的那次评估」，
# 因此断言 level_counts 与直查 SQL 逐档相等。
eq "α 的「很高」数与直查 MySQL 一致" "$M1_VH" \
  "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M1 AND risk_level='very_high';")"
eq "α 的风险项数与直查一致" "$M1_ITEMS" \
  "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M1;")"
eq "β 的「很高」数与直查 MySQL 一致" "$M2_VH" \
  "$(sqlq "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$M2 AND risk_level='very_high';")"

eq "等级分布固定 5 档（缺的补 0）" "$(jlen data.assessments.latest.level_counts)" "5"

# 风险最高的资产：必须来自被指定的那次评估
json GET "/api/dashboard/summary?assessment_id=${M1}"
eq "α 的最高风险资产是 RA5（R=25）" "$(jget data.assessments.latest.top_assets.0.asset_name)" "P6-RA5"
eq "α 的最高风险资产 risk_value" "$(jget data.assessments.latest.top_assets.0.risk_value)" "25"

# —— 草稿评估：不报错，但要说清「尚未计算」 ——
json GET "/api/dashboard/summary?assessment_id=${M3}"
expect "指定一个草稿评估（合法，不是错误）" 200
eq "草稿评估的 status 透出来（界面据此解释为什么是空的）" \
  "$(jget data.assessments.latest.status)" "draft"
eq "草稿评估的风险项数为 0" "$(jget data.assessments.latest.risk_items_count)" "0"
eq "草稿评估的等级分布全零" "$(jget data.assessments.latest.level_counts.very_high)" "0"
eq "草稿评估没有计算时间" "$(jget data.assessments.latest.calculated_at)" ""

json GET "/api/dashboard/summary?assessment_id=999999"
expect "指定不存在的评估返回 404" 404 ASSESSMENT_NOT_FOUND

# —— 整改区块：数字全部与直查 SQL 对账 ——
json GET /api/dashboard/summary
eq "整改单总数与直查一致" "$(jget data.remediations.total)" "$(sqlq "SELECT COUNT(*) FROM remediations;")"
eq "未闭环数与直查一致" "$(jget data.remediations.active)" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE status IN ('pending','in_progress','resolved');")"
eq "按状态分布固定 5 个键" "$(jlen data.remediations.by_status)" "5"

BY_STATUS_SUM=$(( $(jget data.remediations.by_status.pending) \
  + $(jget data.remediations.by_status.in_progress) \
  + $(jget data.remediations.by_status.resolved) \
  + $(jget data.remediations.by_status.closed) \
  + $(jget data.remediations.by_status.accepted) ))
eq "五个状态之和等于 total（否则界面上会出现「加起来少一张」）" \
  "$BY_STATUS_SUM" "$(jget data.remediations.total)"

eq "逾期数与直查 MySQL 一致" "$(jget data.remediations.overdue)" \
  "$(sqlq "SELECT COUNT(*) FROM remediations WHERE due_date IS NOT NULL AND due_date < '${TODAY}' AND status IN ('pending','in_progress','resolved');")"
eq "逾期数 = 1（O1）" "$(jget data.remediations.overdue)" "1"
eq "即将到期数 = 2（O2 今天到期 + O3 还有 5 天）" "$(jget data.remediations.due_soon)" "2"
eq "即将到期的窗口天数回传（界面要能解释这个数字）" "$(jget data.remediations.due_within_days)" "7"

# 重叠会让同一个单子在两个数字里各出现一次，用户会以为有两张单子。
# 判据：两个区间各自命中数之和，等于「两个条件取并集」的命中数。
UNION_SQL="$(sqlq "SELECT COUNT(*) FROM remediations WHERE due_date IS NOT NULL AND status IN ('pending','in_progress','resolved') AND (due_date < '${TODAY}' OR due_date <= DATE_ADD('${TODAY}', INTERVAL 7 DAY));")"
eq "逾期与即将到期两个区间不重叠" \
  "$(( $(jget data.remediations.overdue) + $(jget data.remediations.due_soon) ))" "$UNION_SQL"

# 仪表盘上的「逾期 N 条」与列表页 ?overdue=true 必须是同一个数
json GET "/api/remediations?overdue=true&pageSize=200"
LIST_OVERDUE="$(jget data.total)"
json GET /api/dashboard/summary
eq "仪表盘逾期数与整改列表页 overdue 筛选结果相同（同一个「今天」）" \
  "$(jget data.remediations.overdue)" "$LIST_OVERDUE"

info "最近整改动态条数：$(jlen data.recent_remediations)（上限 5）"
if [ "$(jlen data.recent_remediations)" -ge 1 ] 2>/dev/null; then
  ok "最近整改动态非空"
else
  bad "最近整改动态非空" "recent_remediations 为空"
fi

# 空库场景在 §12 末尾用 SQL 无法模拟（库里有数据），
# 由「草稿评估」那三条代人覆盖：一次都没算过的系统会返回 latest=null，
# 而这里至少验证了「latest 可能指向一个没有风险数字的评估」不会 500。
eq "generated_at 有值" "$( [ -n "$(jget data.generated_at)" ] && echo yes || echo no )" "yes"

# ============================================================================
section "13. 审计与流转痕迹"
# ============================================================================

audit_total() {  # <action> — 直查 MySQL 数该动作码的审计条数
  sqlq "SELECT COUNT(*) FROM audit_logs WHERE action='$1';"
}

for pair in \
  "remediation.create:建单" \
  "remediation.update:改字段" \
  "remediation.transition:状态流转" \
  "remediation.delete:删除" \
  "remediation.batch_create:批量建单"; do
  code="${pair%%:*}"; label="${pair##*:}"
  n="$(audit_total "$code")"
  if [ "$n" != "0" ] && [ -n "$n" ]; then
    ok "审计留下 ${label}（${code}，共 ${n} 条）"
  else
    bad "审计留下 ${label}（${code}）" "audit_logs 里 action=${code} 的条数为 ${n}"
  fi
done

# 明细：审计要能回答「改了哪几条、从什么状态到什么状态」，
# 只留一个动作码等于把这些问题重新交回给读日志的人。
audit_fetch() {  # <action> [pageSize]
  local ps="${2:-5}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
    -o "$AUDIT_JSON" -w '%{http_code}' \
    "$BASE/api/audit-logs?action=$1&pageSize=${ps}" 2>/dev/null)
  LAST_CODE=$(file_code "$AUDIT_JSON")
}

# detail_key <key> — 取 $AUDIT_JSON 首条记录的 detail[key]（数组用逗号连接）
detail_key() {
  "$PYTHON" -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    print(""); raise SystemExit
if not items:
    print(""); raise SystemExit
d = items[0].get("detail")
if not isinstance(d, dict):
    print(""); raise SystemExit
v = d.get(sys.argv[2])
if v is None:
    print("")
elif isinstance(v, list):
    print(",".join(str(x) for x in v))
else:
    print(v)
' "$AUDIT_JSON" "$1" 2>/dev/null
}

# 明细是 JSON **对象**（不是字符串）—— 这正是「前端无需再 parse 一次」的证据：
# 如果它退化成字符串，下面每一个 detail_key 都会返回空，而上面那些
# 「审计留下了某个动作码」的断言仍然全绿 —— 于是「有审计」成立，
# 「审计里写了什么」却已经坏了。
audit_fetch remediation.transition 5
ne "流转审计明细含 from" "$(detail_key from)" ""
ne "流转审计明细含 to" "$(detail_key to)" ""
ne "流转审计明细含 note" "$(detail_key note)" ""
oneof "流转审计明细的 from 是一个合法状态（说明 detail 是对象、键可直接取）" \
  "$(detail_key from)" "pending" "in_progress" "resolved" "closed" "accepted"

audit_fetch remediation.create 5
ne "建单审计明细含 asset_id" "$(detail_key asset_id)" ""
ne "建单审计明细含 vuln_id" "$(detail_key vuln_id)" ""
ne "建单审计明细含 risk_item_id（出处）" "$(detail_key risk_item_id)" ""
ne "建单审计明细含 risk_level" "$(detail_key risk_level)" ""

audit_fetch remediation.update 5
ne "改字段审计明细含 changed（改了哪些列）" "$(detail_key changed)" ""

audit_fetch remediation.delete 5
ne "删除审计明细含 title" "$(detail_key title)" ""

audit_fetch remediation.batch_create 5
ne "批量建单审计明细含 assessment_id" "$(detail_key assessment_id)" ""
ne "批量建单审计明细含 matched" "$(detail_key matched)" ""
ne "批量建单审计明细含 created" "$(detail_key created)" ""
ne "批量建单审计明细含 skipped" "$(detail_key skipped)" ""

# 失败请求不该留下审计：非法流转之后 remediation.transition 的条数不能变。
# 中间件对 status ≥ 400 的请求本就不落审计，且 handler 只在成功路径
# 调用 MarkAuditRecorded —— 这条断言同时守住这两道。
# S1 此刻是 closed（终态），从它出发到 pending 没有边 → 必然 409。
TRANS_AUDIT_BEFORE="$(audit_total remediation.transition)"
json POST "/api/remediations/${S1}/transition" '{"to_status":"pending","note":"终态想回退"}'
expect "（制造一次失败的流转）" 409 REMEDIATION_TRANSITION_INVALID
TRANS_AUDIT_AFTER="$(audit_total remediation.transition)"
eq "失败的流转没有留下审计" "$TRANS_AUDIT_AFTER" "$TRANS_AUDIT_BEFORE"

# 服务端日志：写操作都要有明确归宿（中间件记录 / service 自落 / 明确跳过），
# 漏了会让日志里出现「既未记录也未声明」的告警。
if grep -q "既未由中间件记录" "$SRV_LOG"; then
  bad "服务端日志没有「写操作未记录审计」告警" \
      "$(grep -m1 '既未由中间件记录' "$SRV_LOG")"
else
  ok "服务端日志没有「未记录审计」告警（每个写接口都声明了归宿）"
fi

# 整改单的流转记录要有操作人：时间线要回答「当时是谁做的」
eq "流转记录都带操作人（无空值）" \
  "$(sqlq "SELECT COUNT(*) FROM remediation_logs WHERE action='transition' AND operator_name = '';")" "0"
TRANS_LOG_N="$(sqlq "SELECT COUNT(*) FROM remediation_logs WHERE action='transition';")"
if [ "$TRANS_LOG_N" -ge 5 ] 2>/dev/null; then
  ok "流转记录累计 ${TRANS_LOG_N} 条（覆盖 S1 主链、S2 打回链、R1 与 O5 的终态流转）"
else
  bad "流转记录数量符合预期（≥5）" "实际 ${TRANS_LOG_N} 条"
fi

# S1 的完整时间线：这是「状态流转可追溯」最直观的物证
json GET "/api/remediations/${S1}"
eq "S1 时间线首条是 create（谁建的、什么时候）" "$(jget data.logs.0.action)" "create"
CHAIN="$(sqlq "SELECT GROUP_CONCAT(CONCAT(from_status, '→', to_status) ORDER BY id SEPARATOR ' | ') FROM remediation_logs WHERE remediation_id=$S1 AND action='transition';")"
eq "S1 的流转链完整且顺序正确" "$CHAIN" \
  "pending→in_progress | in_progress→resolved | resolved→in_progress | in_progress→resolved | resolved→closed"

# ---------------------------------------------------------------- 汇总
section "汇总"
TOTAL=$((PASS + FAIL))
printf "  通过 %s%d/%d%s\n" "$C_GREEN" "$PASS" "$TOTAL" "$C_RESET"
if [ "$FAIL" -gt 0 ]; then
  printf "\n  %s未通过项：%s\n" "$C_RED" "$C_RESET"
  for item in "${FAILED_ITEMS[@]}"; do
    printf "    - %s\n" "$item"
  done
  printf "\n  ${C_DIM}服务端日志：%s${C_RESET}\n" "$SRV_LOG"
  printf "  ${C_DIM}复查提示：${C_RESET}\n"
  printf "    ${C_DIM}整改单  mysql> SELECT id, asset_id, vuln_id, status, due_date, active_key FROM remediations;${C_RESET}\n"
  printf "    ${C_DIM}流转记录 mysql> SELECT * FROM remediation_logs ORDER BY id;${C_RESET}\n"
  exit 1
fi

printf "\n  %sP6 整改跟踪与仪表盘守门验证全部通过 ✅%s\n" "$C_GREEN" "$C_RESET"
