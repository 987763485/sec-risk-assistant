#!/usr/bin/env bash
# ============================================================================
# P7 扩展模块预留 守门验证
#
# 验收标志（docs/01 §6 原文）：**配置后能拉取一条 CVE 信息**
# 执行纪律原文：严格只做「接口预留 + 骨架」，不实现具体情报源，防止范围蔓延
#
# ────────────────────────────────────────────────────────────────────────────
# ▍两个贯穿全脚本的设计决定
# ────────────────────────────────────────────────────────────────────────────
#
# ① **验收标志由 `local` 离线驱动证明，而不是真连 NVD。**
#
#    「真连一次 NVD」看起来更真，但那条路径依赖外网可达性、上游限流、
#    （可选的）API Key 是否有效 —— 任何一项变了守门就变红，而**一个会
#    随机变红的守门比没有守门更糟**：它训练人忽略红色。
#
#    `local` 驱动走的是**同一条** service 编排、同一张表、同一套审计、
#    同一套运行态回写，只有「取数」这一步不落网。验收标志要断的是
#    「配置 → 拉取 → 落库 → 可读」这条链路，不是公网本身。
#    公网路径的正确性由两处各自负责，都不需要真连外网：
#      · `pkg/intelfeed` 单测覆盖 NVD 响应解析与全部错误分支；
#      · 本脚本第 6 节的出站拦截矩阵覆盖「地址不被允许」。
#
# ② **SSRF 矩阵必须带正例对照。**
#
#    只断言「内网地址被拒」的脚本，在有人把校验误改成「一律拒绝」时会
#    **全绿** —— 而那会让整个功能不可用。因此每条拒绝断言旁边都有一条
#    「公网地址被接受」的对照，并且真的把一条配置存进库里再读回来。
#
# ────────────────────────────────────────────────────────────────────────────
# ▍覆盖的 11 节
#
#   0. 环境准备：隔离库 sec_risk_integration_e2e + 端口 18088
#   1. 启动后端、登录、改引导密码（并预置一个 `SR_INTEL_` 环境变量）
#   2. 权限面：`integration:read` / `integration:write` / `system:write`
#      三者的分工（三档角色逐个验证）
#   3. 配置 CRUD 与校验：建 / 读 / 改三态 / 停用 / 无 DELETE / 唯一名 /
#      未知类型 / 凭据变量名前缀
#   4. SSRF 拦截矩阵（保存时）+ 公网正例
#   5. **验收标志**：local 驱动端到端拉取一条 CVE，字段逐个核对 + 幂等
#   6. 拉取的十二条拒绝路径（含「有人直接改库把地址换掉」后的复核）
#   7. 运行态回写：全成功 / 部分失败 / updated_at 的含义
#   8. 情报与漏洞：详情内嵌 + 外键 CASCADE（与扫描文件的 RESTRICT 对照）
#   9. 审计：两个动作码 + 明细里只有变量名、没有凭据值
#  10. MCP Server：stdio 端到端 + 写开关默认关闭 + 错误凭据拿不到数据
#
# ────────────────────────────────────────────────────────────────────────────
# ▍环境隔离
#
# 不复用开发库，临时建 `sec_risk_integration_e2e`；端口 18088
# （18080–18087 已被 asset / auth / web / style / file / assess / report /
#   remediate 占用）。不依赖 docgen 与 gotenberg —— P7 不渲染任何文件。
# 只有第 10 节需要 Node；缺 Node 时该节标为跳过并计入失败，
# 而不是静默跳过（静默跳过等于把一节断言悄悄删掉）。
#
# 用法： bash scripts/verify-integration.sh
# 退出码：0 = 全部通过；1 = 存在失败项；2 = 前置条件不满足
#
# 前置条件：MySQL 已启动（make infra）；mcp/node_modules 已安装
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT=18088
BASE="http://127.0.0.1:${PORT}"
E2E_DB="sec_risk_integration_e2e"
E2E_ADMIN="admin"
# 临时库的临时口令：随进程生成，不写入任何文件，用完即随库删除
E2E_ADMIN_PW="Rq8!$(date +%s)$RANDOM"
NEW_PW="${E2E_ADMIN_PW}New1"

# 预置给集成用的凭据环境变量。
#
# 它的**值**是一个刻意好认的串，用途是反向断言：
# 「这个值不得出现在任何响应体、任何审计明细里」。
# 没有这样一个已知值，「不含凭据」这条断言就只能写成「不含 password 字样」，
# 而那与真的没泄漏是两回事。
INTEL_SECRET="s3cr3t-$(date +%s)-$RANDOM"
INTEL_ENV_NAME="SR_INTEL_E2E_KEY"

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 \
  || PYTHON="/Users/chunle/.workbuddy/binaries/python/versions/3.13.12/bin/python3"

NODE_BIN="${NODE_BIN:-}"
if [ -z "$NODE_BIN" ]; then
  if command -v node >/dev/null 2>&1; then
    NODE_BIN="$(command -v node)"
  elif [ -x "/Users/chunle/.workbuddy/binaries/node/versions/22.22.2-6/bin/node" ]; then
    NODE_BIN="/Users/chunle/.workbuddy/binaries/node/versions/22.22.2-6/bin/node"
  fi
fi

SRV_LOG="/tmp/sr-integration-verify-srv.log"
MCP_LOG="/tmp/sr-integration-mcp.log"
MCP_BAD_LOG="/tmp/sr-integration-mcp-bad.log"
BODY="/tmp/.sr-integration-body"
HDR="/tmp/.sr-integration-hdr"

ADMIN_JAR="/tmp/sr-integration-admin.jar"
AUDITOR_JAR="/tmp/sr-integration-auditor.jar"
ASSESSOR_JAR="/tmp/sr-integration-assessor.jar"
ANON_JAR="/tmp/sr-integration-anon.jar"

R7="r7_$RANDOM"

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
# HTTP / JSON 工具（与 verify-remediate.sh 同源）
#
# ⚠️ 这里刻意不抽公共库。这些函数的每一次改动都只影响一个脚本，
#    而抽成共享文件之后，「改一处影响六份守门」会在无人察觉时发生。
#    重复在这里是刻意的成本。
# ============================================================================

LAST_STATUS=0
LAST_CODE=""

# jget <点号路径> — 从 $BODY 中取值
#
# ⚠️ 数据文件路径通过参数传入，而不是用 stdin 重定向：两个 stdin 重定向
#    会互相覆盖，python 会把数据文件当脚本读，函数永远返回空值 —— 静默失效。
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

# jbool <点号路径> — 取布尔字段并转成 true / false；取不到返回空
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

# jlen <点号路径> — 数组/对象/字符串长度；取不到返回 -1
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

# jref <文件> <点号路径> — 同 jget，但源文件可指定
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

# file_has <文件> <子串> — 在文件里找子串（用于「响应体不得出现凭据」这类反向断言）
file_has() { [ -f "$1" ] && "$PYTHON" -c '
import sys
data = open(sys.argv[1], encoding="utf-8", errors="replace").read()
print("yes" if sys.argv[2] in data else "no")
' "$1" "$2" 2>/dev/null || echo "no"; }

expect() {
  local desc="$1" want_status="$2" want_code="${3:-}"
  if [ "$LAST_STATUS" = "$want_status" ] && { [ -z "$want_code" ] || [ "$LAST_CODE" = "$want_code" ]; }; then
    ok "$desc"
  else
    bad "$desc" "期望 HTTP $want_status${want_code:+ / $want_code}，实际 HTTP $LAST_STATUS / $LAST_CODE"
  fi
}

eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "期望「$3」，实际「$2」"; fi; }
ne() { if [ "$2" != "$3" ]; then ok "$1"; else bad "$1" "不应等于「$3」"; fi; }

# contains <描述> <文本> <子串>
contains() {
  case "$2" in
    *"$3"*) ok "$1" ;;
    *) bad "$1" "未找到「$3」（实际「${2}」）" ;;
  esac
}

# not_contains <描述> <文本> <子串> — 反向断言（凭据泄漏、假绿）
not_contains() {
  case "$2" in
    *"$3"*) bad "$1" "不该出现却出现了「$3」" ;;
    *) ok "$1" ;;
  esac
}

# ge <描述> <实际> <下限>
ge() {
  if [ "$2" -ge "$3" ] 2>/dev/null; then ok "$1"; else bad "$1" "期望 ≥ $3，实际「$2」"; fi
}

# oneof <描述> <实际> <候选1> [候选2] ...
#
# ⚠️ 变量后紧跟中文标点时必须写成 ${VAR}：bash 在非 C locale 下会把多字节
#    字符的首字节并进变量名，报 `got（: unbound variable` 这类看不懂的错。
oneof() {
  local desc="$1" got="$2"; shift 2
  for want in "$@"; do
    if [ "$got" = "$want" ]; then ok "$desc"; return; fi
  done
  bad "$desc" "期望其中之一「$*」，实际「${got}」"
}

csrf_token() {
  curl -sS --noproxy '*' -c "$1" -b "$1" "$BASE/api/auth/csrf" -o "$BODY" 2>/dev/null
  jget data.csrf_token
}

SESSION_CSRF=""
# ⚠️ ADMIN_CSRF 与 SESSION_CSRF 必须分开：SESSION_CSRF 会被 login() 反复覆盖成
#    「最后一次登录的那个账号」的令牌，而 json() 恒用管理员会话。两者混用会让
#    管理员之后的请求带上别人的令牌 → 403 AUTH_CSRF_INVALID，看起来像权限问题。
ADMIN_CSRF=""

# login <jar> <user> <pass>
#
# ⚠️ 调用时不要写成 `X=$(login ...)`：命令替换让函数在子 shell 里跑，
#    对 LAST_STATUS 的赋值传不回父 shell，后续断言会读到残留值 → 假绿。
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

# json_as <jar> <method> <path> [body] [csrf] — 用指定会话发请求（越权断言）
json_as() {
  local jar="$1" method="$2" path="$3" payload="${4:-}" token="${5:-$SESSION_CSRF}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$jar" -b "$jar" -o "$BODY" \
    -w '%{http_code}' -X "$method" "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $token" \
    -d "$payload" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# json_to <outfile> ... — 同 json，但响应落到指定文件（要保留上一份响应时用）
json_to() {
  local out="$1" method="$2" path="$3" payload="${4:-}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$out" \
    -w '%{http_code}' -X "$method" "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $ADMIN_CSRF" \
    -d "$payload" 2>/dev/null)
  LAST_CODE=$(jref "$out" code)
}

# sql_indexcols <表> <索引名> — 按顺序取出索引包含的列名
#
# 「唯一键必须含 cve_id」是 P7 的一条硬约束（少了它，一条漏洞上的多条 CVE
# 会互相覆盖）。这条约束只体现在 DDL 里，用接口层的行为**测不出来** ——
# 于是直接问 information_schema。
sql_indexcols() {
  sqlq "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX)
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA='${E2E_DB}' AND TABLE_NAME='$1' AND INDEX_NAME='$2';"
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

# sql <SQL> — 在隔离库里执行查询
#
# ⚠️ `--default-character-set=utf8mb4` 不能省：缺了它，容器里的 mysql CLI 会按
#    latin1 连接，中文**在读到的时候就已经变成 `?`** —— 看起来非常像写库时
#    编码坏了，排查方向会跑偏到迁移脚本上。
sql() {
  compose exec -T mysql mysql -N -B --default-character-set=utf8mb4 \
    -uroot -p"$MYSQL_ROOT_PW" "$E2E_DB" -e "$1" 2>/dev/null
}

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
  if [ -n "$SRV_PID" ]; then
    kill -9 "$SRV_PID" 2>/dev/null
    # wait 不只是回收僵尸：少了它 bash 会多打印一行 `PID Killed: 9`，
    # 夹在汇总与清理信息之间看上去像报错
    wait "$SRV_PID" 2>/dev/null
  fi
  free_port "$PORT"

  if [ -n "$MYSQL_ROOT_PW" ]; then
    compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
      -e "DROP DATABASE IF EXISTS \`$E2E_DB\`;" >/dev/null 2>&1 \
      && echo "  ${C_DIM}已删除临时库 ${E2E_DB}${C_RESET}"
  fi
  rm -f "$ADMIN_JAR" "$AUDITOR_JAR" "$ASSESSOR_JAR" "$ANON_JAR"
  echo "  ${C_DIM}开发库与其它数据未被触碰${C_RESET}"
}
trap cleanup EXIT
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

TBL_COUNT="$(sqlq "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${E2E_DB}';" 2>/dev/null || echo 0)"
info "临时库当前表数 = ${TBL_COUNT}（迁移尚未执行，预期 0）"

if [ -n "$NODE_BIN" ]; then
  info "Node = ${NODE_BIN}"
else
  info "未找到 node —— 第 10 节将失败"
fi

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
  env "$INTEL_ENV_NAME=$INTEL_SECRET" go run ./cmd/api
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

json PATCH /api/auth/password \
  "{\"old_password\":\"$E2E_ADMIN_PW\",\"new_password\":\"$NEW_PW\"}"
expect "首次改密成功" 200

login "$ADMIN_JAR" "$E2E_ADMIN" "$NEW_PW"
expect "改密后可重新登录" 200
ADMIN_CSRF="$SESSION_CSRF"

# 迁移台账：000008 是 P7 新增的
MIG_8="$(sqlq "SELECT COUNT(*) FROM schema_migrations WHERE version = 8;")"
eq "迁移版本 000008 已应用" "$MIG_8" "1"

T_INTEG="$(sqlq "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${E2E_DB}' AND TABLE_NAME='integrations';")"
T_INTEL="$(sqlq "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${E2E_DB}' AND TABLE_NAME='vuln_intel';")"
eq "integrations 表已建立" "$T_INTEG" "1"
eq "vuln_intel 表已建立" "$T_INTEL" "1"

# 外键规则：情报是**派生数据**，跟着漏洞走（CASCADE）；
# 这与 vulnerabilities.source_file_id 的 RESTRICT 是刻意形成对照的两条立场。
CASCADE_RULE="$(sqlq "SELECT DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA='${E2E_DB}' AND CONSTRAINT_NAME='fk_vuln_intel_vuln';")"
eq "vuln_intel → vulnerabilities 是 ON DELETE CASCADE" "$CASCADE_RULE" "CASCADE"

# 集成配置的 updated_at 语义：它是运行态与配置同表的直接后果，
# 这里只断言列存在且可空，语义在第 7 节用一次真实拉取来证明
HAS_LAST_RUN="$(sqlq "SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='${E2E_DB}' AND TABLE_NAME='integrations' AND COLUMN_NAME='last_run_at';")"
eq "integrations.last_run_at 列存在（运行态与配置同表）" "$HAS_LAST_RUN" "1"

# ============================================================================
section "2. 权限面：三种权限码的分工"
# ============================================================================

# —— 匿名 ——
rm -f "$ANON_JAR"
LAST_STATUS=$(curl -sS --noproxy '*' -o "$BODY" -w '%{http_code}' \
  "$BASE/api/integrations" 2>/dev/null)
LAST_CODE=$(jget code)
expect "匿名读集成列表被拒" 401

# —— 缺 CSRF 的写请求 ——
#
# ⚠️ 不能用 json()/json_as()：它们会自动补令牌，这条断言就永远是 200 的假绿。
CSRF_SAVED="$ADMIN_CSRF"
ADMIN_CSRF=""
json POST /api/integrations '{"name":"no-csrf","type":"local"}'
expect "已登录但缺 CSRF 的写请求被拒" 403 AUTH_CSRF_INVALID
ADMIN_CSRF="$CSRF_SAVED"

# —— 审计员：有 integration:read，没有 integration:write / system:write ——
json POST /api/users \
  "{\"username\":\"${R7}_auditor_$RANDOM\",\"display_name\":\"P7 审计员\",\"password\":\"Auditor@2026x\",\"roles\":[\"auditor\"]}"
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

json_as "$AUDITOR_JAR" GET /api/integrations '' "$AUD_CSRF"
expect "审计员**可以**读集成列表（integration:read 由只读派生自动跟上）" 200
eq "列表里下发了 supported_types（前端据此渲染下拉框）" \
  "$(jlen data.supported_types)" "2"
contains "supported_types 里含 local" "$(jget data.supported_types.0.type)$(jget data.supported_types.1.type)" "local"
eq "列表里下发了凭据变量名前缀" "$(jget data.credential_env_prefix)" "SR_INTEL_"

json_as "$AUDITOR_JAR" POST /api/integrations '{"name":"aud-denied","type":"local"}' "$AUD_CSRF"
expect "审计员不能建集成配置（无 system:write）" 403 FORBIDDEN

json_as "$AUDITOR_JAR" POST /api/integrations/1/fetch '{"vuln_id":1}' "$AUD_CSRF"
expect "审计员不能触发拉取（无 integration:write）" 403 FORBIDDEN

# —— 评估员：有 integration:read + integration:write，没有 system:write ——
json POST /api/users \
  "{\"username\":\"${R7}_assessor_$RANDOM\",\"display_name\":\"P7 评估员\",\"password\":\"Assessor@2026x\",\"roles\":[\"assessor\"]}"
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

json_as "$ASSESSOR_JAR" GET /api/integrations '' "$ASR_CSRF"
expect "评估员可以读集成列表" 200

json_as "$ASSESSOR_JAR" POST /api/integrations '{"name":"asr-denied","type":"local"}' "$ASR_CSRF"
expect "评估员不能建集成配置（这正是 system:write 与 integration:write 的分界）" 403 FORBIDDEN

# 评估员能拉取 —— 但要等第 5 节把集成与漏洞建出来之后再验，
# 这里先确认「权限本身在」（用不存在的集成验证：403 与 404 能区分出来）
json_as "$ASSESSOR_JAR" POST /api/integrations/999999/fetch '{"vuln_id":1}' "$ASR_CSRF"
expect "评估员**通过**了权限闸门（拿到 404 而不是 403，说明 integration:write 生效）" \
  404 INTEGRATION_NOT_FOUND

# ============================================================================
section "3. 配置 CRUD 与校验"
# ============================================================================

# ── 建：local 驱动（离线，不需要地址与凭据）──
json POST /api/integrations \
  "{\"name\":\"${R7} 本地离线驱动\",\"type\":\"local\"}"
expect "建 local 类型集成（不填地址与凭据）" 201
INT_LOCAL="$(jget data.id)"
eq "类型中文名由后端下发" "$(jget data.type_label)" "本地离线驱动（不访问网络）"
eq "未填地址时 base_url 为空串" "$(jget data.base_url)" ""
eq "未填凭据时 credential_env 为空串" "$(jget data.credential_env)" ""
eq "未拉取过时 last_status 为空串（不是 false，也不是 failed）" "$(jget data.last_status)" ""
eq "未拉取过时 credential_present 为 false" "$(jbool data.credential_present)" "false"
eq "默认超时 10000ms" "$(jget data.timeout_ms)" "10000"
eq "默认启用" "$(jbool data.enabled)" "true"

# ── 建：NVD（带凭据变量名，指向公网地址）──
json POST /api/integrations \
  "{\"name\":\"${R7} NVD 带凭据\",\"type\":\"nvd\",\"base_url\":\"https://1.1.1.1\",\"credential_env\":\"${INTEL_ENV_NAME}\",\"timeout_ms\":5000}"
expect "建 nvd 类型集成（公网 IP 字面量 + 预置的凭据变量名）" 201
INT_NVD="$(jget data.id)"
eq "地址被原样保存（末尾无斜杠）" "$(jget data.base_url)" "https://1.1.1.1"
eq "只存变量名，不存凭据本身" "$(jget data.credential_env)" "$INTEL_ENV_NAME"
eq "credential_present 回答「变量已设置」" "$(jbool data.credential_present)" "true"
eq "越界超时被收敛而不是报错" "$(jget data.timeout_ms)" "5000"

# 建 local 类型但不填地址 → 应取默认地址（local 没有默认地址，故为空）
json POST /api/integrations \
  "{\"name\":\"${R7} 超时收敛\",\"type\":\"local\",\"timeout_ms\":999999}"
expect "建一个超时越界的集成" 201
INT_CLAMP="$(jget data.id)"
eq "超时上限被收敛到 30000ms" "$(jget data.timeout_ms)" "30000"

json POST /api/integrations \
  "{\"name\":\"${R7} 超时下限\",\"type\":\"local\",\"timeout_ms\":1}"
expect "建一个超时过小的集成" 201
INT_CLAMP2="$(jget data.id)"
eq "超时下限被收敛到 1000ms" "$(jget data.timeout_ms)" "1000"

# ── 校验失败路径 ──
json POST /api/integrations \
  "{\"name\":\"${R7} 本地离线驱动\",\"type\":\"local\"}"
expect "重名被拒" 409 INTEGRATION_NAME_TAKEN

json POST /api/integrations '{"name":"r7-bad-type","type":"virustotal"}'
expect "未知适配器类型被拒（骨架期只有 nvd / local）" 400 INTEGRATION_TYPE_UNKNOWN

json POST /api/integrations '{"name":"","type":"local"}'
expect "空名称被拒" 400 INVALID_PARAM

json POST /api/integrations \
  "{\"name\":\"${R7} 凭据前缀\",\"type\":\"nvd\",\"credential_env\":\"SR_AUTH_JWT_SECRET\"}"
expect "凭据变量名不带 SR_INTEL_ 前缀时被拒（否则等于开放「读取任意环境变量」）" \
  400 INTEGRATION_CREDENTIAL_INVALID

json POST /api/integrations \
  "{\"name\":\"${R7} 凭据格式\",\"type\":\"nvd\",\"credential_env\":\"SR_INTEL_bad-name\"}"
expect "凭据变量名含非法字符时被拒" 400 INTEGRATION_CREDENTIAL_INVALID

json POST /api/integrations "{\"name\":\"${R7} 不存在类型库\",\"type\":\"nvd\",\"base_url\":\"http://127.0.0.1:9/\"}"
expect "保存时即拒绝内网地址（第一层 SSRF 防护）" 400 INTEGRATION_ENDPOINT_BLOCKED

# ── 读 ──
json GET /api/integrations
expect "读集成列表" 200
LIST_HAS="$(jget data.items.0.id)"
ne "列表非空" "$LIST_HAS" ""

json GET "/api/integrations/${INT_LOCAL}"
expect "读单个集成" 200
eq "单条读数与列表一致" "$(jget data.id)" "$INT_LOCAL"

json GET /api/integrations/999999
expect "读不存在的集成返回 404" 404 INTEGRATION_NOT_FOUND

# ── 改：三态与「按合并后的最终值整体校验」──
json PATCH "/api/integrations/${INT_LOCAL}" "{\"name\":\"${R7} 本地离线驱动（改名）\"}"
expect "改名" 200
eq "改名生效" "$(jget data.name)" "${R7} 本地离线驱动（改名）"

json PATCH "/api/integrations/${INT_LOCAL}" '{}'
expect "空 PATCH 被拒（没有需要更新的配置项）" 400 INVALID_PARAM

# 三态：显式 null = 清空凭据
json PATCH "/api/integrations/${INT_NVD}" '{"credential_env":null}'
expect "credential_env 传 null 表示清空" 200
eq "凭据变量名已清空" "$(jget data.credential_env)" ""
eq "清空后 credential_present 变回 false" "$(jbool data.credential_present)" "false"

json PATCH "/api/integrations/${INT_NVD}" "{\"credential_env\":\"${INTEL_ENV_NAME}\"}"
expect "再填回凭据变量名" 200
eq "凭据变量名已恢复" "$(jget data.credential_env)" "$INTEL_ENV_NAME"

# ⚠️ 这条是本节的要害：只把类型从 local 改成 nvd 时，
#    **地址也要重新过一遍校验**。若实现只校验「本次传入的字段」，
#    这个请求就会通过，于是库里留下一个 local（无需地址）→ nvd（需要地址）
#    却带着被改坏地址的配置。
json PATCH "/api/integrations/${INT_CLAMP}" '{"type":"nvd"}'
expect "把 local 改成 nvd 时，合并后的地址仍被整体校验（空地址合法，故通过）" 200
eq "类型已改为 nvd" "$(jget data.type)" "nvd"
eq "地址仍是空串（默认地址在拉取时才生效，不在保存时填充）" "$(jget data.base_url)" ""
info "「按合并后的最终值校验」的实证在下面两条：把库里的地址改坏，再只改名字"

# 反向：把一个合法配置直接改库改成内网地址，再经接口改**别的**字段，
#       应当在校验时被拦下（证明校验读的是合并后的最终值，而不是请求体）
sql "UPDATE integrations SET base_url='http://10.99.99.99/' WHERE id=${INT_CLAMP};" >/dev/null 2>&1
json PATCH "/api/integrations/${INT_CLAMP}" "{\"name\":\"${R7} 合并校验\"}"
expect "库里地址被改坏后，只改名字的 PATCH 也会被拦下" 400 INTEGRATION_ENDPOINT_BLOCKED
json GET "/api/integrations/${INT_CLAMP}"
eq "被拦下的 PATCH 没有写入任何字段（名字未变）" "$(jget data.name)" "${R7} 超时收敛"
json PATCH "/api/integrations/${INT_CLAMP}" '{"base_url":"https://1.1.1.1"}'
expect "把地址改回公网后 PATCH 通过" 200

# ── 停用 / 启用 ──
json PATCH "/api/integrations/${INT_CLAMP2}" '{"enabled":false}'
expect "停用一个集成" 200
eq "停用已生效" "$(jbool data.enabled)" "false"

# ── 无 DELETE ──
req DELETE "/api/integrations/${INT_LOCAL}"
expect "DELETE /api/integrations/:id 不存在（集成是审计记录指向的对象，不许删）" 404

# ── 列表不分页 ──
#
# 条数不用写死的数字断，而是与库里的行数对齐：写死「≥5」时，
# 前面某一节少建一个集成就会让这一条红，而红的原因与「分不分页」毫无关系 ——
# 一条会因无关改动变红的断言，作用只是训练人忽略它。
json GET /api/integrations
DB_INT_ALL="$(sqlq "SELECT COUNT(*) FROM integrations;")"
eq "列表一次返回全部集成（不分页：条数等于库里行数，且 > 1）" "$(jlen data.items)" "$DB_INT_ALL"
ge "确实不止一条（否则「不分页」是废话）" "$DB_INT_ALL" "2"
eq "列表响应里没有分页字段（与业务列表的立场不同）" "$(jget data.total)" ""

# ============================================================================
section "4. SSRF 拦截矩阵（保存时）+ 公网正例"
# ============================================================================

# ── 拒绝矩阵 ──
#
# 每条都走一遍真实的 POST /api/integrations，而不是调 Go 单测：
# 单测证明的是 CheckEndpoint 的实现，这里要证明的是**它真的挂在保存路径上**。
#
# 覆盖三类绕过手法：
#   ① 字面量形式（点分十进制、十六进制、整数、IPv6、IPv4-mapped）
#   ② 特殊网段（回环、私有、链路本地、云元数据、CGNAT）
#   ③ 非 http(s) 协议与内嵌凭据
declare -a SSRF_CASES=(
  "http://127.0.0.1:8080/|回环 IPv4 字面量"
  "http://localhost:8080/|localhost（解析到回环）"
  "http://[::1]:8080/|IPv6 回环字面量"
  "http://[::ffff:127.0.0.1]/|IPv4-mapped IPv6 形式的回环"
  "http://0x7f000001/|十六进制整数形式的回环（字符串黑名单必漏）"
  "http://2130706433/|十进制整数形式的回环（字符串黑名单必漏）"
  "http://0x7f.1/|混合进制的回环"
  "http://169.254.169.254/latest/meta-data/|云元数据地址"
  "http://10.1.2.3/api|私有段 10/8"
  "http://172.16.5.5/api|私有段 172.16/12"
  "http://192.168.1.1/api|私有段 192.168/16"
  "http://100.64.0.1/api|CGNAT 段 100.64/10"
  "http://[fd00::1]/api|IPv6 ULA 段"
  "http://[fe80::1]/api|IPv6 链路本地段"
  "http://[2002:7f00:1::]/api|6to4 隧道地址（内嵌回环）"
  "http://[::]/api|未指定地址"
  "http://0.0.0.0/api|未指定地址（点分形式）"
  "file:///etc/passwd|非 http(s) 协议 file"
  "gopher://127.0.0.1:6379/_INFO|非 http(s) 协议 gopher"
  "https://user:pass@example.com/|URL 内嵌凭据"
)

# 名字里带序号是必要的：多个 URL 截断后可能落到同一个 slug，
# 而集成名称是唯一的 —— 撞名会拿到 409 而不是 400，
# 于是「拒绝」这条断言会以「期望 400 实际 409」的形式失败，
# 看起来像 SSRF 校验失效了。
ssrf_idx=0
for entry in "${SSRF_CASES[@]}"; do
  url="${entry%%|*}"
  label="${entry##*|}"
  ssrf_idx=$((ssrf_idx + 1))
  json POST /api/integrations \
    "{\"name\":\"${R7} ssrf${ssrf_idx} $(echo "$url" | tr -c 'a-zA-Z0-9' '_' | cut -c1-20)\",\"type\":\"nvd\",\"base_url\":\"$url\"}"
  expect "拒绝 ${label}" 400 INTEGRATION_ENDPOINT_BLOCKED
done

# 拒绝之后**库里不能留下痕迹**：被拒的配置不该出现在列表里。
#
# ⚠️ 这条断言是「先落库再校验」这类实现的唯一照妖镜 ——
#    那种实现下接口会返回 400，但配置已经写进去了，
#    而列表接口不会报错，只会多出一条谁也没建过的记录。
BAD_ROWS="$(sqlq "SELECT COUNT(*) FROM integrations WHERE name LIKE '${R7} ssrf%';")"
eq "被拒绝的地址一条都没有落库" "$BAD_ROWS" "0"

# ── 正例对照 ──
#
# 没有这一段，把校验误改成「一律拒绝」的实现在上面的矩阵里会全绿，
# 而整个功能会变成不可用 —— 这正是 SSRF 校验最容易出的那种「过紧」故障。
json POST /api/integrations \
  "{\"name\":\"${R7} 公网正例\",\"type\":\"nvd\",\"base_url\":\"https://1.1.1.1\"}"
expect "公网地址被接受（正例对照：防「一律拒绝」假绿）" 201
INT_PUBLIC="$(jget data.id)"
eq "公网地址原样保存" "$(jget data.base_url)" "https://1.1.1.1"

json POST /api/integrations \
  "{\"name\":\"${R7} 公网主机名\",\"type\":\"nvd\",\"base_url\":\"https://services.nvd.nist.gov\"}"
LAST_STATUS_SAVED="$LAST_STATUS"
# 域名解析结果取决于运行环境：企业内网 DNS / 沙箱代理可能把公网域名
# 指到保留网段，那时被拒是**正确**行为。因此这条做成「要么 201，要么
# 400 且原因是解析结果被拦」，而不是硬性 201。
if [ "$LAST_STATUS" = "201" ]; then
  ok "公网域名被接受（本机 DNS 解析到公网地址）"
elif [ "$LAST_STATUS" = "400" ] && [ "$LAST_CODE" = "INTEGRATION_ENDPOINT_BLOCKED" ]; then
  ok "公网域名被拒，但原因是本机 DNS 把它解析到了非公网段（环境相关，非缺陷）"
  info "本机 DNS 下 services.nvd.nist.gov 解析结果不在公网段"
else
  bad "公网域名的处理结果不合预期" "HTTP $LAST_STATUS / $LAST_CODE"
fi

# ============================================================================
section "5. 【验收标志】配置后能拉取一条 CVE 信息"
# ============================================================================

# 目标漏洞：登记一条 local 驱动里真实存在的 CVE
json POST /api/vulnerabilities \
  "{\"title\":\"${R7} 验收漏洞\",\"severity\":5,\"cve_ids\":[\"CVE-2021-44228\"]}"
expect "建对照漏洞（登记 CVE-2021-44228）" 201
V_MAIN="$(jget data.id)"
contains "漏洞的 cve_ids 已规范化保存" "$(jget data.cve_ids)" "CVE-2021-44228"

# 用 local 驱动拉取 —— 离线、确定、不依赖外网
json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "【验收标志】配置后的集成成功拉取（HTTP 200）" 200

eq "本次请求的 CVE 列表" "$(jget data.requested.0)" "CVE-2021-44228"
eq "成功 1 条" "$(jget data.succeeded)" "1"
eq "失败 0 条" "$(jget data.failed)" "0"
eq "新增 1 条" "$(jget data.inserted)" "1"
eq "更新 0 条" "$(jget data.updated)" "0"
eq "集成标识回显" "$(jget data.integration_id)" "$INT_LOCAL"
eq "漏洞标识回显" "$(jget data.vuln_id)" "$V_MAIN"
ge "耗时已回填" "$(jget data.latency_ms)" "0"

# 拉到的快照字段逐个核对
eq "快照条数 1" "$(jlen data.items)" "1"
eq "快照 CVE 编号" "$(jget data.items.0.cve_id)" "CVE-2021-44228"
eq "快照来源是适配器类型（不是集成 id）" "$(jget data.items.0.source)" "local"
eq "快照来源中文名" "$(jget data.items.0.source_label)" "本地离线驱动（不访问网络）"
eq "严重度取上游给的档位" "$(jget data.items.0.severity)" "critical"
# ⚠️ 用 oneof 而不是 eq "10.0"：Go 的 encoding/json 把 float64(10.0) 写成 `10`，
#    于是 Python 解析成正整数并打印 `10`。写死 "10.0" 会得到一条
#    「期望 10.0 实际 10」的假失败 —— 而它看起来像少了小数位。
oneof "CVSS 分数为 10" "$(jget data.items.0.cvss_score)" "10" "10.0"
ne "display_title 非空（NVD 无标题时的回退逻辑）" "$(jget data.items.0.display_title)" ""
ne "描述非空" "$(jget data.items.0.description)" ""
ge "参考链接 ≥ 1 条" "$(jlen data.items.0.references)" "1"
ne "fetched_at 已回填" "$(jget data.items.0.fetched_at)" ""
ne "published_at 已回填（与 fetched_at 是两个不同的事实）" "$(jget data.items.0.published_at)" ""
ne "快照有自增 id（响应读自库中，不是拼出来的）" "$(jget data.items.0.id)" ""

INTEL_ID_1="$(jget data.items.0.id)"

# 落库交叉核对：接口说的与库里存的必须一致
DB_INTEL_CNT="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "库里确有 1 条快照" "$DB_INTEL_CNT" "1"
DB_SEV="$(sqlq "SELECT severity FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "库里的严重度与接口一致" "$DB_SEV" "critical"
DB_CVE="$(sqlq "SELECT cve_id FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "库里的 CVE 编号与接口一致" "$DB_CVE" "CVE-2021-44228"
DB_SRC="$(sqlq "SELECT source FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "库里存的是适配器类型" "$DB_SRC" "local"

# 漏洞详情内嵌情报 —— 这是前端展示所依赖的接口
json GET "/api/vulnerabilities/${V_MAIN}"
expect "读漏洞详情" 200
eq "详情内嵌 1 条情报" "$(jlen data.intel)" "1"
eq "详情内嵌的 CVE 编号一致" "$(jget data.intel.0.cve_id)" "CVE-2021-44228"
eq "详情内嵌的严重度一致" "$(jget data.intel.0.severity)" "critical"

# ── 幂等 ──
#
# 同一 (漏洞, 来源, CVE) 重复拉取必须是**更新**而不是新增：
# 否则每点一次「拉取」库里就多一条，而展示层会看到同一 CVE 出现多次。
json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "重复拉取（幂等）" 200
eq "第二次是更新而不是新增：inserted=0" "$(jget data.inserted)" "0"
eq "第二次是更新而不是新增：updated=1" "$(jget data.updated)" "1"
eq "第二次仍然成功 1 条" "$(jget data.succeeded)" "1"

DB_INTEL_CNT2="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "重复拉取后库里仍然是 1 条" "$DB_INTEL_CNT2" "1"
INTEL_ID_2="$(jget data.items.0.id)"
eq "重复拉取复用的是同一行（id 未变）" "$INTEL_ID_2" "$INTEL_ID_1"

# ── 多 CVE 批量 ──
json POST /api/vulnerabilities \
  "{\"title\":\"${R7} 多 CVE 漏洞\",\"severity\":4,\"cve_ids\":[\"CVE-2017-5638\",\"CVE-2018-15473\"]}"
expect "建一个挂 2 条 CVE 的漏洞" 201
V_MULTI="$(jget data.id)"

json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MULTI}}"
expect "一次拉取多条 CVE" 200
eq "请求了 2 条" "$(jlen data.requested)" "2"
eq "成功 2 条" "$(jget data.succeeded)" "2"
eq "新增 2 条" "$(jget data.inserted)" "2"

DB_MULTI="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_MULTI};")"
eq "库里 2 条" "$DB_MULTI" "2"

# 唯一键必须含 cve_id：少了它，第二条会覆盖第一条。
#
# ⚠️ 这条用「库里有 2 行」而不是「接口返回 2 条」来断言是刻意的：
#    接口返回的 items 是重新读库拼的，但它也可以被实现成「把本次拉到的
#    记录原样回显」。只有行数能证明唯一键真的没把它们压成一条。
DB_DISTINCT="$(sqlq "SELECT COUNT(DISTINCT cve_id) FROM vuln_intel WHERE vuln_id=${V_MULTI};")"
eq "两行的 cve_id 不同（唯一键含 cve_id）" "$DB_DISTINCT" "2"

# 指定 cve_id 只拉一条
json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MULTI},\"cve_id\":\"cve-2018-15473\"}"
expect "指定 cve_id 拉取（小写形态也接受）" 200
eq "只请求了 1 条" "$(jlen data.requested)" "1"
eq "requested 已被归一化为大写" "$(jget data.requested.0)" "CVE-2018-15473"

# 评估员用同一个集成拉取 —— 证明 integration:write 真的挂在拉取上
json_as "$ASSESSOR_JAR" POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MULTI}}" "$ASR_CSRF"
expect "评估员可以触发拉取（integration:write 生效）" 200

# ============================================================================
section "6. 拉取的十二条拒绝路径"
# ============================================================================

# ① 上游未收录该 CVE → 接口**仍然 200**，成败在 failed / errors 里
json POST /api/vulnerabilities \
  "{\"title\":\"${R7} 未收录漏洞\",\"severity\":3,\"cve_ids\":[\"CVE-1999-0001\"]}"
expect "建一个 local 驱动未收录的 CVE 漏洞" 201
V_UNKNOWN="$(jget data.id)"

json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_UNKNOWN}}"
expect "上游未收录时接口仍然 200（结果对象里区分成败）" 200
eq "成功 0 条" "$(jget data.succeeded)" "0"
eq "失败 1 条" "$(jget data.failed)" "1"
eq "没有落库" "$(jget data.inserted)" "0"
eq "errors 里带上了 CVE 编号" "$(jget data.errors.0.cve_id)" "CVE-1999-0001"
contains "errors 里给出了人话原因" "$(jget data.errors.0.message)" "未收录"
eq "items 为空（本次什么也没拉到）" "$(jlen data.items)" "0"

DB_UNK="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_UNKNOWN};")"
eq "未收录的 CVE 一条也没落库" "$DB_UNK" "0"

# ② 拉一条不属于该漏洞的 CVE → 400
json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MAIN},\"cve_id\":\"CVE-2018-15473\"}"
expect "不能对该漏洞拉取它没登记的 CVE" 400 INVALID_PARAM
contains "拒绝原因指明「该漏洞的 CVE 列表里没有这条编号」" "$(jget message)" "没有这条编号"

# ③ 漏洞没有登记任何 CVE → 400
json POST /api/vulnerabilities "{\"title\":\"${R7} 无 CVE 漏洞\",\"severity\":2}"
expect "建一个没有 CVE 的漏洞" 201
V_NOCVE="$(jget data.id)"

json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_NOCVE}}"
expect "漏洞没有 CVE 时无法拉取（并给出下一步建议）" 400 INVALID_PARAM
contains "拒绝原因提示了补救方式" "$(jget message)" "补上 CVE 编号"

# ④ CVE 格式不合法 → 400
json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MAIN},\"cve_id\":\"CVE-21-1\"}"
expect "CVE 编号格式不合法被拒" 400 INVALID_PARAM

# ⑤ 单次超过 5 条上限 → 400
json POST /api/vulnerabilities \
  "{\"title\":\"${R7} 六条 CVE 漏洞\",\"severity\":3,\"cve_ids\":[\"CVE-2001-0001\",\"CVE-2001-0002\",\"CVE-2001-0003\",\"CVE-2001-0004\",\"CVE-2001-0005\",\"CVE-2001-0006\"]}"
expect "建一个挂 6 条 CVE 的漏洞" 201
V_SIX="$(jget data.id)"

json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_SIX}}"
expect "挂 6 条 CVE 时拒绝整批（上限 5）" 400 INVALID_PARAM
contains "拒绝原因给出上限与补救方式" "$(jget message)" "指定要拉取的 cve_id"

# ⑥ 停用的集成 → 409
json POST "/api/integrations/${INT_CLAMP2}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "停用的集成不能被拉取" 409 INTEGRATION_DISABLED

# ⑦ 凭据变量名已登记但环境里没有 → 409（且**在校验阶段拦下，不出网**）
#
# ⚠️ 这条同时证明了编排顺序：先校验、再取凭据、最后才发请求。
#    若顺序反了，这里会先向 base_url 发起一次真实请求才报错 ——
#    而那正是 SSRF 防护要避免的事。
json POST /api/integrations \
  "{\"name\":\"${R7} 缺凭据\",\"type\":\"nvd\",\"base_url\":\"https://1.1.1.1\",\"credential_env\":\"SR_INTEL_NOT_SET_E2E\"}"
expect "建一个凭据变量名存在但环境里没有的集成" 201
INT_NOKEY="$(jget data.id)"
eq "credential_present 如实回答「没设置」" "$(jbool data.credential_present)" "false"

json POST "/api/integrations/${INT_NOKEY}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "凭据缺失时拒绝拉取（这是部署问题，不是重试能解决的）" 409 INTEGRATION_CREDENTIAL_MISSING
contains "拒绝原因点名了那个环境变量" "$(jget message)" "SR_INTEL_NOT_SET_E2E"

# ⑧ 有人**直接改库**把地址换成内网 → 拉取前复核仍然拦得住
#
# ⚠️ 这一条证明的是**第一层在拉取路径上的第二次调用**，不是第二层防护。
#    真正防 DNS rebinding 的 `net.Dialer.Control` 在这条路径上不参与
#    （地址在内网，`CheckEndpoint` 就先拒了，根本走不到 connect）。
#    把这条断言标成「第二层」会让第二层从此没人再测 —— 而它恰恰是
#    「预检通过之后 DNS 变脸」的唯一防线。
#    第二层由 `pkg/intelfeed` 的单测 `TestGuardedClientBlocksAtDialTime`
#    覆盖（直接让客户端连受限字面量地址，断言拒绝来自 Control 而不是
#    「端口没人监听」的 connection refused）。
sql "UPDATE integrations SET base_url='http://127.0.0.1:9/' WHERE id=${INT_PUBLIC};" >/dev/null 2>&1
json POST "/api/integrations/${INT_PUBLIC}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "库里地址被改成内网后，拉取前的复核仍然拦得住（第一层在拉取路径上重跑）" \
  400 INTEGRATION_ENDPOINT_BLOCKED
sql "UPDATE integrations SET base_url='https://1.1.1.1' WHERE id=${INT_PUBLIC};" >/dev/null 2>&1

# ⑨ 库里的类型不被支持（适配器已移除）→ 400 而不是 500
sql "UPDATE integrations SET type='legacy_threatbook' WHERE id=${INT_CLAMP};" >/dev/null 2>&1
json POST "/api/integrations/${INT_CLAMP}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "库里的适配器类型已不受支持时给出 400（用户的下一步是改类型，不是重试）" \
  400 INTEGRATION_TYPE_UNKNOWN
sql "UPDATE integrations SET type='nvd' WHERE id=${INT_CLAMP};" >/dev/null 2>&1

# ⑩ 目标漏洞不存在 → 404
json POST "/api/integrations/${INT_LOCAL}/fetch" '{"vuln_id":999999999}'
expect "目标漏洞不存在" 404 VULN_NOT_FOUND

# ⑪ vuln_id 缺失 → 400（handler 层拦下）
json POST "/api/integrations/${INT_LOCAL}/fetch" '{}'
expect "缺少 vuln_id 被拒" 400 INVALID_PARAM

# ⑫ 集成不存在 → 404
json POST "/api/integrations/999999/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "集成不存在" 404 INTEGRATION_NOT_FOUND

# ============================================================================
section "7. 运行态回写"
# ============================================================================

# ── 运行态记的是「最后一次执行」，不是历史累计 ──
#
# 上面第 6 节在 INT_LOCAL 上留下的运行态是**失败**（上游未收录该 CVE）。
# 因此这里必须自己先跑一次全成功的拉取 —— 否则断言的其实是
# 「第 6 节最后一次拉取的结果」，而那条断言的描述（「全成功时 …」）
# 与它测的东西是两回事。
json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "让这个集成跑一次全部成功的拉取" 200
eq "本次确实全成功" "$(jget data.succeeded)" "1"
eq "本次失败 0 条" "$(jget data.failed)" "0"

json GET "/api/integrations/${INT_LOCAL}"
expect "读回集成运行态" 200
eq "全成功时 last_status = success" "$(jget data.last_status)" "success"
eq "last_error 为空" "$(jget data.last_error)" ""
ne "last_run_at 已回填" "$(jget data.last_run_at)" ""
ge "last_latency_ms 已回填" "$(jget data.last_latency_ms)" "0"

# ── 部分失败也记 failed ──
#
# 判据是「本次是否**全部**成功」：这一列要回答的是「这个集成现在能不能
# 正常用」，而「三条里有一条拉不到」显然不属于「能正常用」。
json POST /api/vulnerabilities \
  "{\"title\":\"${R7} 半成功漏洞\",\"severity\":3,\"cve_ids\":[\"CVE-2021-44228\",\"CVE-1999-0002\"]}"
expect "建一个「一条能拉到、一条拉不到」的漏洞" 201
V_HALF="$(jget data.id)"

json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_HALF}}"
expect "部分成功的拉取仍然返回 200" 200
eq "成功 1 条" "$(jget data.succeeded)" "1"
eq "失败 1 条" "$(jget data.failed)" "1"
eq "succeeded + failed == len(requested)" \
  "$(( $(jget data.succeeded) + $(jget data.failed) ))" "$(jlen data.requested)"
eq "有失败时仍然落库了成功的那条" "$(jget data.inserted)" "1"

json GET "/api/integrations/${INT_LOCAL}"
eq "部分失败记为 failed（判据是「全部成功」）" "$(jget data.last_status)" "failed"
contains "last_error 概括了失败比例" "$(jget data.last_error)" "1/2 条失败"

# ── updated_at 的语义 ──
#
# 集成配置的运行态与配置同表，因此一次拉取会刷新 updated_at。
# 界面若把这一列标成「最后修改时间」，用户会看到「我没改配置，时间怎么变了」。
# 这里用一次「纯拉取、不改配置」来证明这一点。
updated_before="$(sqlq "SELECT updated_at FROM integrations WHERE id=${INT_LOCAL};")"
# ⚠️ 睡 2 秒而不是 1 秒：updated_at 是**秒级** DATETIME，差一秒时两次读数
#    有可能落在同一秒里，于是这条断言会以「期望不同实际相同」的形式
#    偶发失败 —— 而它看起来像「运行态没写回」。宁可慢一点，不要偶发红。
sleep 2
json POST "/api/integrations/${INT_LOCAL}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "只拉取、不改配置" 200
updated_after="$(sqlq "SELECT updated_at FROM integrations WHERE id=${INT_LOCAL};")"
ne "一次拉取会刷新 updated_at（所以它不是「配置最后修改时间」）" "$updated_after" "$updated_before"

# 但配置字段本身没变 —— 这是「按合并后的最终值校验」之外的另一半：
# 拉取不该顺手把配置列写回去（那正是「拉取失败却把 base_url 改回默认值」
# 这类事故的起点）。
json GET "/api/integrations/${INT_LOCAL}"
eq "配置字段没有被拉取动作改动" "$(jget data.name)" "${R7} 本地离线驱动（改名）"
eq "启用状态没有被拉取动作改动" "$(jbool data.enabled)" "true"
eq "类型没有被拉取动作改动" "$(jget data.type)" "local"

# ============================================================================
section "8. 情报与漏洞的关系"
# ============================================================================

# ── 唯一键的组成（直接问 DDL）──
#
# 「唯一键必须含 cve_id」是 P7 最容易被写错、也最难被发现的一处：
# 一条漏洞挂 2 条 CVE 时，唯一键少了 cve_id 会让后一条**覆盖**前一条，
# 接口照样返回 2 条（因为它读的是本次拉到的记录），只有行数会露出破绽。
# 这类约束只体现在 DDL 里，因此直接查 information_schema 比用行为推断可靠。
UK_COLS="$(sql_indexcols vuln_intel uk_vuln_intel_identity)"
eq "vuln_intel 的唯一键是 (vuln_id, source, cve_id) 三列有序" \
  "$UK_COLS" "vuln_id,source,cve_id"

# ── `source` 存的是适配器类型，不是集成的 id ──
#
# 这一点用「两个不同的集成拉同一个漏洞，落库后 source 只有一个取值」来证明：
# 若实现存的是 integrations.id，这里会出现两个不同的 source。
json POST /api/integrations \
  "{\"name\":\"${R7} 第二来源\",\"type\":\"local\"}"
expect "再建一个 local 集成（模拟第二个情报源实例）" 201
INT_LOCAL2="$(jget data.id)"
ne "两个集成确实是不同的 id" "$INT_LOCAL" "$INT_LOCAL2"

DB_SRC_BEFORE="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
json POST "/api/integrations/${INT_LOCAL2}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "同一漏洞用另一个集成实例拉取" 200
eq "同类型 → 同 source → 是更新而不是新增" "$(jget data.inserted)" "0"
eq "同类型 → 同 source → updated=1" "$(jget data.updated)" "1"

DB_SRC_AFTER="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "行数没有因为换了个集成而增加" "$DB_SRC_AFTER" "$DB_SRC_BEFORE"
DB_SRC_DISTINCT="$(sqlq "SELECT COUNT(DISTINCT source) FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "source 只有一个取值（存的是类型而不是集成 id）" "$DB_SRC_DISTINCT" "1"
DB_SRC_VALUE="$(sqlq "SELECT source FROM vuln_intel WHERE vuln_id=${V_MAIN} LIMIT 1;")"
eq "source 的取值就是适配器类型" "$DB_SRC_VALUE" "local"

# ⚠️ 换一个「不同 source」的场景在这里造不出来：骨架期只有 nvd / local
#    两个适配器，而 nvd 会真的出网。因此「不同来源各自成条」这条
#    由上面的唯一键断言（三列有序）来保证，而不是靠一个假的 nvd 集成。

json GET "/api/vulnerabilities/${V_MAIN}"
eq "漏洞详情内嵌 1 条情报" "$(jlen data.intel)" "1"

# ── 级联删除 ──
#
# 情报是**派生数据**：漏洞没了，挂在它上面的情报也就失去了指代对象。
# 这与 vulnerabilities.source_file_id 的 RESTRICT（扫描文件被引用时不许删）
# 是两条刻意相反的立场，理由见迁移文件头部的设计约束。
DB_BEFORE_DEL="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_HALF};")"
ge "待删除的漏洞上确有条情报" "$DB_BEFORE_DEL" "1"

json DELETE "/api/vulnerabilities/${V_HALF}"
expect "删除漏洞" 200

DB_AFTER_DEL="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_HALF};")"
eq "漏洞删除后情报被级联清理（CASCADE）" "$DB_AFTER_DEL" "0"

# 反向对照：别的漏洞的情报不受影响
DB_OTHERS="$(sqlq "SELECT COUNT(*) FROM vuln_intel WHERE vuln_id=${V_MAIN};")"
eq "其它漏洞的情报不受影响" "$DB_OTHERS" "1"

# ── 空情报时详情返回空数组而不是 null ──
#
# `null` 会让前端的 `v-for` 直接抛错，而这类错误只在「这个漏洞恰好
# 没有情报」时才出现 —— 也就是最不容易被测到的那条路径。
json GET "/api/vulnerabilities/${V_NOCVE}"
expect "读一个没有情报的漏洞详情" 200
eq "intel 是空数组而不是 null" "$(jlen data.intel)" "0"

# ============================================================================
section "9. 审计"
# ============================================================================

# ── integration.update（建 / 改共用）──
json GET "/api/audit-logs?action=integration.update&pageSize=1"
expect "可以按 action=integration.update 查询" 200
ge "有 integration.update 记录" "$(jget data.total)" "1"
eq "资源类型为 integration" "$(jget data.items.0.resource)" "integration"
ne "资源标识为集成 id" "$(jget data.items.0.resource_id)" ""
eq "操作人是管理员" "$(jget data.items.0.username)" "$E2E_ADMIN"

ADMIN_ACTION_CNT="$(sqlq "SELECT COUNT(*) FROM audit_logs WHERE action='integration.update';")"
ge "库里确有 integration.update（而不是接口层拼出来的）" "$ADMIN_ACTION_CNT" "10"

# ── integration.fetch（主干动作）──
json GET "/api/audit-logs?action=integration.fetch&pageSize=5"
expect "可以按 action=integration.fetch 查询" 200
ge "有 integration.fetch 记录" "$(jget data.total)" "1"

FETCH_CNT="$(sqlq "SELECT COUNT(*) FROM audit_logs WHERE action='integration.fetch';")"
ge "库里确有 integration.fetch" "$FETCH_CNT" "5"

# 失败路径也留痕：审计要回答的是「谁让服务器去连过哪个地址」，
# 而失败的尝试恰恰是最需要留痕的那种。
FAILED_AUDIT="$(sqlq "SELECT COUNT(*) FROM audit_logs WHERE action='integration.fetch'
  AND JSON_EXTRACT(detail,'\$.failed') > 0;")"
ge "失败的拉取也写了审计（failed > 0 的记录存在）" "$FAILED_AUDIT" "1"

# ── 明细字段 ──
#
# 取最新一条 fetch 明细，逐字段核对「该记的都记了」。
json GET "/api/audit-logs?action=integration.fetch&pageSize=1"
DET="$(jget data.items.0.detail)"
contains "明细里有 integration_id" "$DET" "integration_id"
contains "明细里有 integration_name" "$DET" "integration_name"
contains "明细里有 base_url（回答「服务器实际去向哪里发起了请求」）" "$DET" "base_url"
contains "明细里有 vuln_id" "$DET" "vuln_id"
contains "明细里有 cve_ids" "$DET" "cve_ids"
contains "明细里有 succeeded / failed" "$DET" "succeeded"
contains "明细里有 latency_ms" "$DET" "latency_ms"

# ── **明细里不得出现凭据值** ──
#
# 这一段是整节的重点，也是「凭据永不入库」这条设计承诺的直接断言。
#
# 构造方式：让一个**带凭据变量**的集成真的走一次拉取（local 驱动不看凭据，
# 但 resolveCredential 会把它取出来），然后检查三处出口：
#   ① 拉取响应体、② 审计明细、③ 集成列表响应
json POST /api/integrations \
  "{\"name\":\"${R7} 带密钥的本地源\",\"type\":\"local\",\"credential_env\":\"${INTEL_ENV_NAME}\"}"
expect "建一个带凭据变量的 local 集成" 201
INT_WITHKEY="$(jget data.id)"
eq "credential_present = true（变量确实在服务进程里）" "$(jbool data.credential_present)" "true"

json POST "/api/integrations/${INT_WITHKEY}/fetch" "{\"vuln_id\":${V_MAIN}}"
expect "带凭据的集成拉取成功" 200

SECRET_IN_RESP="$(file_has "$BODY" "$INTEL_SECRET")"
eq "① 拉取响应体里没有凭据值" "$SECRET_IN_RESP" "no"

json GET "/api/integrations"
SECRET_IN_LIST="$(file_has "$BODY" "$INTEL_SECRET")"
eq "② 集成列表响应里没有凭据值（只有变量名）" "$SECRET_IN_LIST" "no"
contains "列表里如实给出了变量名" "$(cat "$BODY")" "$INTEL_ENV_NAME"

json GET "/api/audit-logs?action=integration.fetch&pageSize=5"
SECRET_IN_AUDIT="$(file_has "$BODY" "$INTEL_SECRET")"
eq "③ 拉取审计明细里没有凭据值" "$SECRET_IN_AUDIT" "no"
AUDIT_HAS_VAR="$(file_has "$BODY" "$INTEL_ENV_NAME")"
eq "审计明细里记的是变量**名**" "$AUDIT_HAS_VAR" "yes"

# 整张审计表都不该出现这个值（防止某条记录以别的方式带进去）
SECRET_IN_DB="$(sqlq "SELECT COUNT(*) FROM audit_logs WHERE detail LIKE '%${INTEL_SECRET}%';")"
eq "④ 审计表里任何一条明细都不含凭据值" "$SECRET_IN_DB" "0"

# 集成表里也只有变量名
DB_SECRET="$(sqlq "SELECT COUNT(*) FROM integrations WHERE credential_env LIKE '%${INTEL_SECRET}%';")"
eq "⑤ integrations 表里没有凭据值" "$DB_SECRET" "0"

# ── 失败请求不留审计 ──
#
# 一条不合法（400）的拉取请求不该留下 integration.fetch 记录：
# 它没让服务器去连任何地方，记下来只会稀释「谁连过哪里」这个信号。
BEFORE_BAD="$(sqlq "SELECT COUNT(*) FROM audit_logs WHERE action='integration.fetch';")"
json POST "/api/integrations/${INT_LOCAL}/fetch" '{}'
expect "缺 vuln_id 的拉取被拒" 400 INVALID_PARAM
AFTER_BAD="$(sqlq "SELECT COUNT(*) FROM audit_logs WHERE action='integration.fetch';")"
eq "被拒的拉取没有留下审计记录" "$AFTER_BAD" "$BEFORE_BAD"

# ── 审计里没有「未记录审计」告警 ──
#
# 双路径审计（中间件 + service 自落库）若声明错了，会出现「同一个请求
# 记了两条」或「一条都没记」。前者的表现是 action 计数翻倍，
# 后者是请求能成功但审计缺失 —— 两者都不会报错。
NO_DOUBLE="$(sqlq "SELECT COUNT(*) FROM (
  SELECT request_id, action, COUNT(*) c FROM audit_logs
  WHERE action IN ('integration.update','integration.fetch') AND request_id <> ''
  GROUP BY request_id, action HAVING c > 1) t;")"
eq "没有重复记录的审计（request_id + action 唯一）" "$NO_DOUBLE" "0"

NO_WARN="$(file_has "$SRV_LOG" "既未由中间件记录")"
eq "后端日志里没有「写操作未留审计」的告警" "$NO_WARN" "no"
NO_AUDIT_ERR="$(file_has "$SRV_LOG" "审计日志写入失败")"
eq "后端日志里没有「审计日志写入失败」" "$NO_AUDIT_ERR" "no"

# ============================================================================
section "10. MCP Server（stdio）"
# ============================================================================

if [ -z "$NODE_BIN" ]; then
  bad "未找到 node，MCP 一节无法验证（这一节不可静默跳过：静默跳过等于删掉断言）"
else
  if [ ! -d "$ROOT/mcp/node_modules" ]; then
    bad "mcp/node_modules 不存在，请先在 mcp/ 下执行 npm install"
  else
    SR_MCP_API_BASE="$BASE" \
    SR_MCP_USERNAME="$E2E_ADMIN" \
    SR_MCP_PASSWORD="$NEW_PW" \
    SR_MCP_LIVE=1 \
      "$NODE_BIN" "$ROOT/mcp/test/mcp-smoke.mjs" > "$MCP_LOG" 2>&1
    MCP_RC=$?
    if [ "$MCP_RC" = "0" ]; then
      ok "MCP 冒烟全通过（含真登录 + 真调用）"
    else
      bad "MCP 冒烟失败（退出码 ${MCP_RC}）" "$(tail -20 "$MCP_LOG" | tr '\n' ' ')"
    fi

    # ⚠️ 不能只看退出码：一个「什么都没测」的空脚本同样会返回 0。
    #    这里逐节核对它真的跑了内容，把「冒烟本身失效」变成一条可见的失败。
    # ⚠️ 断言的子串必须与冒烟脚本实际输出的字面量一致。冒烟的文案里
    #    带 Markdown 强调（`默认**不**暴露写工具 fetch_vuln_intel`），
    #    写「默认不暴露写工具」会**永远匹配不到** —— 而它失败的样子
    #    与「冒烟真的没跑到这一节」一模一样，排查方向会跑偏。
    contains "MCP 冒烟跑到了工具清单断言" "$(cat "$MCP_LOG")" "工具清单由写开关决定"
    contains "MCP 冒烟验证了默认不暴露写工具" "$(cat "$MCP_LOG")" "默认**不**暴露写工具 fetch_vuln_intel"
    contains "MCP 冒烟跑到了调用层" "$(cat "$MCP_LOG")" "get_dashboard_summary 调用成功"
    contains "MCP 冒烟验证了错误以工具级错误返回" "$(cat "$MCP_LOG")" "工具级错误"

    # ── 反向对照：错误凭据拿不到任何数据 ──
    #
    # 这一条是 MCP 一节的关键：它证明「MCP 不是绕过认证的后门」。
    # 若 MCP 里有任何一处缓存、降级或本地兜底，这里就会拿到数据并返回 0。
    SR_MCP_API_BASE="$BASE" \
    SR_MCP_USERNAME="$E2E_ADMIN" \
    SR_MCP_PASSWORD="${NEW_PW}-wrong" \
    SR_MCP_LIVE=1 \
      "$NODE_BIN" "$ROOT/mcp/test/mcp-smoke.mjs" > "$MCP_BAD_LOG" 2>&1
    BAD_RC=$?
    if [ "$BAD_RC" != "0" ]; then
      ok "凭据错误时 MCP 拿不到数据（退出码 ${BAD_RC}，反向对照）"
    else
      bad "凭据错误时 MCP 竟然拿到了数据 —— 存在绕过认证的路径"
    fi
    contains "失败原因指向认证而不是别的" "$(cat "$MCP_BAD_LOG")" "401"

    # ── MCP 用的就是后端账号，因此权限也照旧生效 ──
    #
    # 上面那次拉取与这里的所有写操作都记在服务账号名下；
    # 第 9 节已经断言审计里有这些记录，责任人可查。
    MCP_AUDIT="$(sqlq "SELECT COUNT(*) FROM audit_logs
      WHERE action='integration.fetch' AND username='${E2E_ADMIN}';")"
    ge "MCP 触发的调用同样留下了审计记录（责任人 = 服务账号）" "$MCP_AUDIT" "1"

    # 后端日志里没有因为 MCP 而产生的 500
    has_500="$(file_has "$SRV_LOG" '"level":"ERROR"')"
    if [ "$has_500" = "yes" ]; then
      info "后端日志里存在 ERROR 行，逐条核对是否与本阶段相关："
      "$PYTHON" -c '
import sys, json
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        rec = json.loads(line)
    except Exception:
        continue
    if rec.get("level") == "ERROR":
        print("     ", rec.get("msg"), rec.get("err", ""))
' "$SRV_LOG" | head -10
      # 本脚本刻意制造了若干 4xx；400/404/409 不该写 ERROR。
      # 真的出现 ERROR 时把它记成失败，避免「日志里有错但没人看」。
      bad "后端日志出现 ERROR 行（4xx 是业务结果，不该记成 ERROR）"
    else
      ok "后端日志里没有 ERROR 行（被拒的请求都是业务结果，不是异常）"
    fi
  fi
fi

# ============================================================================
section "汇总"
# ============================================================================

printf "  通过 ${C_GREEN}%d${C_RESET} 项" "$PASS"
if [ "$FAIL" -gt 0 ]; then
  printf "，失败 ${C_RED}%d${C_RESET} 项\n" "$FAIL"
  printf "\n${C_RED}失败明细：${C_RESET}\n"
  for item in "${FAILED_ITEMS[@]}"; do printf "  · %s\n" "$item"; done
  exit 1
fi
printf "，失败 0 项\n"
printf "\n${C_GREEN}P7 守门验证全部通过 ✅${C_RESET}\n"
exit 0
