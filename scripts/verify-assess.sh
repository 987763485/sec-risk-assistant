#!/usr/bin/env bash
# ============================================================================
# P4 风险评估引擎 守门验证
#
# 验证什么（对应 docs/01-实现计划.md 里 P4 的验收标志
# 「手工核算与系统结果一致；界面值 = 落库值 = 报告值三者完全一致」）：
#
#   ▍本脚本最重要的一个设计决定：**独立算术**
#
#   预期值**不复用后端任何代码**，而是直接在本脚本里用 bash 整数运算重算
#   R 与档位。这并不是多余：
#
#     R = A × T × V，后端内部把每个量放大 1000 倍走 int64，写成
#         ((A_milli * T_milli) / 1000 * V_milli) / 1000
#     两次整数除法都是**截断**，且左结合。用「浮点乘一遍再四舍五入」去
#     核对，在绝大多数数据上会得到相同答案，于是测试是绿的——但那是巧合，
#     不是等价。真正等价的是把这个截断序列照抄一遍（见下面的 rmilli）。
#     如果本脚本改成调后端自己的算法来「验证」后端，那就成了自己证明
#     自己：算法改错了，两边一起错，脚本依然是绿的。
#
#   覆盖的 15 节：
#
#    0. 环境准备：隔离库 sec_risk_assess_e2e + 端口 18085。
#    1. 登录并改掉引导密码。
#    2. 台账准备：5 档重要性的资产、5 档严重程度的漏洞、5 档权重的威胁，
#       以及一条独立的"边界专用"资产/漏洞（只挂 1 条，便于精确构造边界值）。
#    3. 试算的只读语义：可反复调、结果稳定、不落库、不产生审计、不改状态。
#    4. 引擎穷举 125 组：5 个威胁档 × 25 条 (重要性 × 严重程度) 组合，
#       逐条用独立算术复核 A / T / V / R 与档位。
#    5. 阈值边界：19.999/20、11.999/12、5.999/6、1.999/2 —— 验证判定是
#       闭区间（R ≥ 阈值）且两侧确实分属相邻档位。用 asset_weight 覆盖
#       精确构造 .999（见下方注释：为什么不用造 0.999 的威胁）。
#    6. 配置快照：改系统权重后，**老评估的快照与落库值一字不改**。
#    7. 落库：条数、四列自洽（A×T×V=R）、risk_level 与 R 一致。
#    8. 三处一致：界面（risk-items 接口）= 落库（直接查 MySQL）= 报告
#       （export-data），逐条比对四个数值与档位。
#    9. 矩阵：恒为 25 格；每格计数与 risk_items 按 (importance, severity)
#       分组的条数一致；total 与 risk_items_count 一致。
#   10. 下钻：按 (importance, severity) 过滤的集合恰好等于矩阵该格。
#   11. 权重改 1.5 后 A 与 R 的传导（新评估用新配置）。
#   12. 重算幂等 + 逐项覆盖的威胁在重算后保留。
#   13. 审计员只读：能看结果，不能建 / 改 / 算 / 删。
#   14. 审计落库与日志：6 个 P4 动作各自留下记录；preview 不留；
#       服务端日志无 ERROR、无「写操作未记录审计」告警。
#
# ── 环境隔离 ───────────────────────────────────────────────────────────────
# 本脚本**不复用开发库**，临时建 sec_risk_assess_e2e（理由与 verify-asset.sh /
# verify-file.sh 相同：本脚本会建 6 台资产、6 条漏洞、5 个威胁字典与 4 个评估
# 任务，跑在开发库上会污染本地数据）。
#
# 端口用 18085：验证脚本不该顺手杀掉用户正在用的 dev server。
#
# 用法： bash scripts/verify-assess.sh
# 退出码：0 = 全部通过；1 = 存在失败项
#
# 前置条件：MySQL 已启动（make infra）。
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT=18085
BASE="http://127.0.0.1:${PORT}"
E2E_DB="sec_risk_assess_e2e"
E2E_ADMIN="admin"
# 临时库的临时口令：随进程生成，不写入任何文件，用完即随库删除
E2E_ADMIN_PW="Rk7!$(date +%s)$RANDOM"

SRV_LOG="/tmp/sr-assess-verify-srv.log"
BODY="/tmp/.sr-assess-body"
HDR="/tmp/.sr-assess-hdr"
DB_TSV="/tmp/.sr-assess-db.tsv"
ADMIN_JAR="/tmp/sr-assess-admin.jar"
READONLY_JAR="/tmp/sr-assess-readonly.jar"

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

# ============================================================================
# 独立算术：这一节是整个脚本的立身之本，**不要**改成调用后端接口取期望值。
# ============================================================================

# rmilli <importance> <w_milli> <t_milli> <severity> — 重算 R 的定点整数值
#
# 与 riskengine.Compute 逐位对应（含两次截断与左结合）：
#
#   aWeighted := importance * AssetWeight        // AssetWeight 本身已是 milli
#   rMilli    := aWeighted * tMilli / Scale * vMilli / Scale
#
# 注意 bash 的 / 对正数与 Go 一样是向零截断，所以这里可以照抄。
rmilli() {
  local imp="$1" wm="$2" tm="$3" sev="$4"
  local am=$(( imp * wm ))
  local vm=$(( sev * 1000 ))
  echo $(( am * tm / 1000 * vm / 1000 ))
}

# level_milli <r_milli> <very_high> <high> <medium> <low> — 档位判定
#
# 顺序从高到低**不能反**：反了以后 R=25 会先撞上低档位直接返回 low。
# 阈值参数是整数（后端 ParseConfig 的签名就是 int）。
level_milli() {
  local r="$1"
  local vh=$(( $2 * 1000 )) hi=$(( $3 * 1000 )) md=$(( $4 * 1000 )) lo=$(( $5 * 1000 ))
  if   [ "$r" -ge "$vh" ]; then echo very_high
  elif [ "$r" -ge "$hi" ]; then echo high
  elif [ "$r" -ge "$md" ]; then echo medium
  elif [ "$r" -ge "$lo" ]; then echo low
  else echo very_low
  fi
}

# m2f <milli> — 把定点整数格式化成人读的样子（19.999 / 0.001 / -2.500）
m2f() {
  local m="$1" sign=""
  if [ "$m" -lt 0 ]; then sign="-"; m=$(( -m )); fi
  printf "%s%d.%03d" "$sign" $(( m / 1000 )) $(( m % 1000 ))
}

# ============================================================================
# HTTP 工具（与 verify-file.sh 保持同源，改动请两边同步）
# ============================================================================

LAST_STATUS=0
LAST_CODE=""

# jget <点号路径> — 从 $BODY 中取值
#
# ⚠️ 数据文件路径通过参数传入，而不是用 stdin 重定向。
# 若写成 `python3 - <<'PY' < "$BODY"`，两个 stdin 重定向会互相覆盖，
# python 会把数据文件当脚本读取，函数永远返回空值 —— 静默失效，极难排查。
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

# jlen <点号路径> — 数组/对象/字符串的长度；取不到返回 -1
jlen() {
  python3 -c '
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

# jmilli <点号路径> — 取一个数值字段并换算成定点整数（截断精度的统一入口）
#
# 后端出参是 float64（JSON 里形如 19.999），直接用字符串比会在 "20" vs "20.0"
# 这类表示差异上误判。统一转成 milli 整数再比，比较的是数值本身。
jmilli() {
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
try:
    print(int(round(float(d) * 1000)))
except Exception:
    print("")
' "$1" "$BODY" 2>/dev/null
}

# dump_risk_items — 把 $BODY 里 data.items 逐条输出为 TSV：
#   importance  severity  a_milli  t_milli  v_milli  r_milli  risk_level
#
# 供 while-read 做逐条比对。用进程替换 `< <(...)` 喂给 while，
# **不要**用管道：管道会让 while 跑在子 shell 里，ok/bad 里的计数
# 传不回父 shell，最后汇总会显示 0 项、脚本假绿退出。
dump_risk_items() {
  python3 -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    raise SystemExit
def m(v):
    try: return int(round(float(v) * 1000))
    except Exception: return -1
for it in items:
    print("\t".join([
        str(it.get("importance", -1)),
        str(it.get("severity", -1)),
        str(m(it.get("asset_value_a"))),
        str(m(it.get("threat_weight_t"))),
        str(m(it.get("vuln_weight_v"))),
        str(m(it.get("risk_value_r"))),
        str(it.get("risk_level", "")),
    ]))
' "$BODY" 2>/dev/null
}

# top_sorted — 检查 $BODY 里 data.top_items 是否按 R 非递增排列
#
# 这是一条回归护栏。P4 守门时抓到过：契约与 Preview 的注释都写着
# 「风险值最高的风险项」，但 build 只排序了资产汇总、没排风险项，
# 于是执行页所谓的"最该先看的 20 条"其实是数据库返回顺序的前 20 条。
# 这类 bug 不报错、结果也不"错"，只是展示的是别的东西 —— 只能靠断言守。
top_sorted() {
  python3 -c '
import json, sys
try:
    items = (json.load(open(sys.argv[1], encoding="utf-8")).get("data") or {}).get("top_items") or []
except Exception:
    print("读取失败"); raise SystemExit
vals = []
for it in items:
    try: vals.append((float(it.get("risk_value_r")), it.get("asset_name", "")))
    except Exception: pass
if not vals:
    print("空列表"); raise SystemExit
for (a, an), (b, bn) in zip(vals, vals[1:]):
    if a < b:
        print("逆序：%s(%s) 之后是 %s(%s)" % (a, an, b, bn)); raise SystemExit
print("OK")
' "$BODY" 2>/dev/null
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
    *) bad "$1" "在「$2」中未找到「$3」" ;;
  esac
}

# ---------------------------------------------------------------- 会话工具

csrf_token() {
  curl -sS --noproxy '*' -c "$1" -b "$1" "$BASE/api/auth/csrf" -o "$BODY" 2>/dev/null
  jget data.csrf_token
}

SESSION_CSRF=""

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

# json <method> <path> [json body] — 带会话 CSRF 的业务请求
json() {
  local method="$1" path="$2" payload="${3:-}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
    -w '%{http_code}' -X "$method" "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $SESSION_CSRF" \
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

# ---------------------------------------------------------------- 环境准备

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

# sql <SQL> — 在隔离库里执行只读查询，-N -B 输出无表头、tab 分隔
sql() {
  compose exec -T mysql mysql -N -B -uroot -p"$MYSQL_ROOT_PW" "$E2E_DB" -e "$1" 2>/dev/null
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
  rm -f "$ADMIN_JAR" "$READONLY_JAR" "$DB_TSV"
  rm -f /tmp/.sr-assess-ui.json /tmp/.sr-assess-export.json /tmp/.sr-assess-matrix.json
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
  ok "已创建隔离的临时库 $E2E_DB"
else
  bad "创建临时库失败"
  exit 2
fi

rm -f "$ADMIN_JAR" "$READONLY_JAR"

section "1. 启动后端（指向临时库）并登录"

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

for _ in $(seq 1 120); do
  if curl -sS --noproxy '*' -o /dev/null -m 2 "$BASE/api/health" 2>/dev/null; then break; fi
  sleep 1
done
if ! curl -sS --noproxy '*' -o /dev/null -m 2 "$BASE/api/health" 2>/dev/null; then
  bad "后端未就绪"
  tail -30 "$SRV_LOG"
  exit 1
fi
ok "后端已就绪：$BASE"

login "$ADMIN_JAR" "$E2E_ADMIN" "$E2E_ADMIN_PW"
expect "引导管理员可登录" 200

NEW_PW="${E2E_ADMIN_PW}New1"
json PATCH /api/auth/password \
  "{\"old_password\":\"$E2E_ADMIN_PW\",\"new_password\":\"$NEW_PW\"}"
expect "首次改密成功" 200

login "$ADMIN_JAR" "$E2E_ADMIN" "$NEW_PW"
expect "改密后可重新登录" 200

# ============================================================================
section "2. 台账准备（威胁字典 / 资产 / 漏洞 / 关联）"
# ============================================================================

# ── 威胁字典：5 档权重 1–5 ────────────────────────────────────────────────
#
# 穷举需要 T 能取到 5 个不同值，而 T 来自字典的 weight（风险项本身不存
# 自由数值的 T，只存威胁码）。所以这里建 5 条。
TH_CODES=()
for t in 1 2 3 4 5; do
  json POST /api/dictionaries \
    "{\"category\":\"threat\",\"code\":\"e2e_t${t}\",\"name\":\"E2E 威胁 T=${t}\",\"weight\":${t}}"
  expect "建威胁字典 e2e_t${t}（权重 ${t}）" 201
  TH_CODES+=("$(jget data.code)")
done

TH1_CODE="${TH_CODES[0]}"
TH3_CODE="${TH_CODES[2]}"

# ── 资产：5 档重要性 ─────────────────────────────────────────────────────
#
# importance 是矩阵横轴与 A 的档位来源，5 台正好铺满 1–5。
ASSET_IDS=()
for i in 1 2 3 4 5; do
  json POST /api/assets \
    "{\"name\":\"E2E-ASSET-${i}\",\"asset_type\":\"server\",\"ip_address\":\"192.168.9.${i}\",\"importance\":${i}}"
  expect "建资产 E2E-ASSET-${i}（重要性 ${i}）" 201
  ASSET_IDS+=("$(jget data.id)")
done

# ── 漏洞：5 档严重程度 ───────────────────────────────────────────────────
#
# 注意 severity 与 D3 决策的关系：V 取 vulnerabilities.severity（扫描器定级），
# 不受字典权重影响。这里手工录入时直接给 1–5。
VULN_IDS=()
for s in 1 2 3 4 5; do
  json POST /api/vulnerabilities \
    "{\"title\":\"E2E 漏洞 S=${s}\",\"severity\":${s}}"
  expect "建漏洞 E2E 漏洞 S=${s}（严重程度 ${s}）" 201
  VULN_IDS+=("$(jget data.id)")
done

# ── 关联：5 台资产 × 5 条漏洞 = 25 个风险项 ───────────────────────────────
#
# 25 = importance(5) × severity(5)，再乘 5 个威胁档就是 125 组穷举。
ALL_VULN_JSON="$(printf '%s,' "${VULN_IDS[@]}")"
ALL_VULN_JSON="[${ALL_VULN_JSON%,}]"

for idx in 0 1 2 3 4; do
  json POST "/api/vulnerabilities/${VULN_IDS[$idx]}/assets" "{\"asset_ids\":${ALL_VULN_JSON}}"
  expect "把漏洞 S=$((idx + 1)) 挂到 5 台资产上" 200
done

# ── 边界专用：1 台重要性 1 的资产 + 1 条严重程度 1 的漏洞 ────────────────
#
# 第 5 节要精确构造 R = 19.999 这种值。若评估范围里有 25 条风险项，
# 返回的 top_items 会被截断（上限 20 条），而"最后一条恰好是被截掉的那条"
# 是最难排查的失败模式。所以单独起一个范围只含 1 台资产、1 条漏洞的评估：
#   此时 R = 1 × w × T × 1，把 w 设成目标值即可精确命中。
json POST /api/assets \
  '{"name":"E2E-BOUNDARY","asset_type":"server","ip_address":"192.168.9.99","importance":1}'
expect "建边界专用资产（重要性 1）" 201
BOUND_ASSET_ID="$(jget data.id)"

json POST /api/vulnerabilities '{"title":"E2E 边界漏洞 S=1","severity":1}'
expect "建边界专用漏洞（严重程度 1）" 201
BOUND_VULN_ID="$(jget data.id)"

json POST "/api/vulnerabilities/$BOUND_VULN_ID/assets" "{\"asset_ids\":[$BOUND_ASSET_ID]}"
expect "边界漏洞只挂到边界资产上" 200

# ── 范围校验的负路径 ─────────────────────────────────────────────────────
json POST /api/assessments \
  "{\"name\":\"E2E-BAD-SCOPE\",\"scope_type\":\"custom\",\"scope_ref\":[]}"
expect "custom 范围为空被拒" 400

json POST /api/assessments \
  "{\"name\":\"E2E-BAD-SCOPE2\",\"scope_type\":\"custom\",\"scope_ref\":[99999999]}"
expect "custom 范围含不存在的资产被拒" 400

json POST /api/assessments \
  '{"name":"E2E-BAD-THREAT","scope_type":"all","default_threat_code":"no_such_threat"}'
expect "不存在的威胁码被拒" 400 THREAT_NOT_FOUND

# ── 建三个评估任务 ───────────────────────────────────────────────────────
ASSET_JSON="$(printf '%s,' "${ASSET_IDS[@]}")"
ASSET_JSON="[${ASSET_JSON%,}]"

json POST /api/assessments \
  "{\"name\":\"E2E 主评估\",\"description\":\"125 组穷举与三处一致\",\"scope_type\":\"custom\",\"scope_ref\":${ASSET_JSON},\"default_threat_code\":\"${TH3_CODE}\"}"
expect "建主评估任务（25 条风险项）" 201
E1="$(jget data.id)"
eq "新建任务初始状态为 draft" "$(jget data.status)" "draft"
eq "新建任务 risk_items_count 为 0" "$(jget data.risk_items_count)" "0"
eq "新建任务 max_risk 为 null（不是 0）" "$(jget data.max_risk)" ""

json POST /api/assessments \
  "{\"name\":\"E2E 边界评估\",\"scope_type\":\"custom\",\"scope_ref\":[$BOUND_ASSET_ID],\"default_threat_code\":\"${TH1_CODE}\"}"
expect "建边界评估任务（1 条风险项）" 201
E2="$(jget data.id)"

json POST /api/assessments \
  "{\"name\":\"E2E 落库评估\",\"scope_type\":\"custom\",\"scope_ref\":${ASSET_JSON},\"default_threat_code\":\"${TH3_CODE}\"}"
expect "建落库评估任务" 201
E3="$(jget data.id)"

# ============================================================================
section "3. 试算的只读语义（可反复调 / 不落库 / 不留审计）"
# ============================================================================

req GET "/api/audit-logs?action=assessment.calculate&pageSize=1"
CALC_AUDIT_BEFORE="$(jget data.total)"

json POST /api/assessments/preview "{\"assessment_id\":$E1}"
expect "试算返回 200" 200
eq "试算的资产数为 5" "$(jget data.assets_count)" "5"
eq "试算的风险项为 25" "$(jget data.risk_items_count)" "25"
eq "试算的无漏洞资产为 0" "$(jget data.unmatched_assets)" "0"
eq "试算结果含五个等级键" "$(jlen data.level_counts)" "5"
eq "试算的 top_items 按 R 从高到低排列" "$(top_sorted)" "OK"

PREVIEW_FIRST="$(dump_risk_items | sort)"

json POST /api/assessments/preview "{\"assessment_id\":$E1}"
expect "再次试算仍返回 200" 200
PREVIEW_SECOND="$(dump_risk_items | sort)"
eq "两次试算逐条结果完全一致" "$PREVIEW_SECOND" "$PREVIEW_FIRST"

json GET "/api/assessments/$E1"
expect "试算后仍能读取任务" 200
eq "试算不改变任务状态（仍 draft）" "$(jget data.status)" "draft"
eq "试算不落库（risk_items_count 仍 0）" "$(jget data.risk_items_count)" "0"
eq "试算不写 max_risk" "$(jget data.max_risk)" ""
eq "试算不写配置快照" "$(jget data.config_snapshot)" ""

req GET "/api/audit-logs?action=assessment.calculate&pageSize=1"
eq "试算不产生 assessment.calculate 审计" "$(jget data.total)" "$CALC_AUDIT_BEFORE"

# 覆盖阈值的试算不应该影响后续不带覆盖的试算（参数是每请求独立的）
json POST /api/assessments/preview \
  "{\"assessment_id\":$E1,\"asset_weight\":1.5,\"thresholds\":{\"very_high\":20,\"high\":12,\"medium\":6,\"low\":2}}"
expect "带临时覆盖的试算返回 200" 200
json POST /api/assessments/preview "{\"assessment_id\":$E1}"
PREVIEW_THIRD="$(dump_risk_items | sort)"
eq "临时覆盖不外溢到下一次试算" "$PREVIEW_THIRD" "$PREVIEW_FIRST"

# ============================================================================
section "4. 引擎穷举 125 组（独立算术复核 A / T / V / R 与档位）"
# ============================================================================

# 后端此时用默认配置：w = 1.000，阈值 20 / 12 / 6 / 2。
# 每轮改任务级默认威胁 → 计算 → 把 25 条全量取回逐条复核。
EXHAUST_CHECKS=0
EXHAUST_MISMATCH=0
MISMATCH_SAMPLE=""

for idx in 0 1 2 3 4; do
  TVAL=$(( idx + 1 ))
  TCODE="${TH_CODES[$idx]}"

  json PATCH "/api/assessments/$E1" "{\"default_threat_code\":\"${TCODE}\"}"
  expect "把默认威胁改为 T=${TVAL}" 200

  json POST "/api/assessments/$E1/calculate"
  expect "计算（T=${TVAL}）" 200

  req GET "/api/assessments/$E1/risk-items?pageSize=200"
  eq "（T=${TVAL}）风险项条数为 25" "$(jget data.total)" "25"

  ROUND_BAD=0
  while IFS=$'\t' read -r imp sev am tm vm rm lvl; do
    [ -z "${imp:-}" ] && continue
    EXHAUST_CHECKS=$(( EXHAUST_CHECKS + 1 ))
    exp_rm=$(rmilli "$imp" 1000 $(( TVAL * 1000 )) "$sev")
    exp_level=$(level_milli "$exp_rm" 20 12 6 2)
    if [ "$rm" != "$exp_rm" ] || [ "$am" != "$(( imp * 1000 ))" ] \
       || [ "$tm" != "$(( TVAL * 1000 ))" ] || [ "$vm" != "$(( sev * 1000 ))" ] \
       || [ "$lvl" != "$exp_level" ]; then
      ROUND_BAD=$(( ROUND_BAD + 1 ))
      EXHAUST_MISMATCH=$(( EXHAUST_MISMATCH + 1 ))
      if [ -z "$MISMATCH_SAMPLE" ]; then
        MISMATCH_SAMPLE="i=${imp} s=${sev} T=${TVAL} 后端(A=$(m2f "$am") T=$(m2f "$tm") V=$(m2f "$vm") R=$(m2f "$rm") ${lvl}) 独立(A=$(( imp * 1000 / 1000 )) T=${TVAL} V=${sev} R=$(m2f "$exp_rm") ${exp_level})"
      fi
    fi
  done < <(dump_risk_items)

  eq "（T=${TVAL}）25 条 A/T/V/R 与档位逐条与独立算术一致" "$ROUND_BAD" "0"
done

eq "穷举共复核 125 组（5 威胁档 × 25 组合）" "$EXHAUST_CHECKS" "125"
eq "穷举零不一致" "$EXHAUST_MISMATCH" "0"
[ "$EXHAUST_MISMATCH" -gt 0 ] && printf "     ${C_DIM}首个不一致：%s${C_RESET}\n" "$MISMATCH_SAMPLE"

# 等级分布也由独立算术推出，而不是把 13 / 7 / 4 / 1 / 0 抄进脚本：
# 抄来的常数在阈值或权重调整后会静默过期，算出来的不会。
# count_levels <t_milli> — 统计 25 组合落在 5 个档位各几条
# 输出：very_high high medium low very_low（空格分隔）
count_levels() {
  local tm="$1" i s lv
  local vh=0 hi=0 md=0 lo=0 vl=0
  for i in 1 2 3 4 5; do
    for s in 1 2 3 4 5; do
      lv=$(level_milli "$(rmilli "$i" 1000 "$tm" "$s")" 20 12 6 2)
      case "$lv" in
        very_high) vh=$(( vh + 1 )) ;;
        high)      hi=$(( hi + 1 )) ;;
        medium)    md=$(( md + 1 )) ;;
        low)       lo=$(( lo + 1 )) ;;
        very_low)  vl=$(( vl + 1 )) ;;
      esac
    done
  done
  echo "$vh $hi $md $lo $vl"
}

# T=3（落库评估 E3 用的档）与 T=5（穷举最后一轮）
read -r EXP_VH EXP_HI EXP_MD EXP_LO EXP_VL <<< "$(count_levels 3000)"
read -r EXP5_VH EXP5_HI EXP5_MD EXP5_LO EXP5_VL <<< "$(count_levels 5000)"

# 穷举的最后一轮把默认威胁设成了 T=5，所以此刻 E1 的汇总按 T=5 核。
json GET "/api/assessments/$E1"
eq "等级分布 very_high（T=5）与独立算术一致" "$(jget data.level_counts.very_high)" "$EXP5_VH"
eq "等级分布 high（T=5）与独立算术一致"      "$(jget data.level_counts.high)" "$EXP5_HI"
eq "等级分布 medium（T=5）与独立算术一致"    "$(jget data.level_counts.medium)" "$EXP5_MD"
eq "等级分布 low（T=5）与独立算术一致"       "$(jget data.level_counts.low)" "$EXP5_LO"
eq "等级分布 very_low（T=5）与独立算术一致"  "$(jget data.level_counts.very_low)" "$EXP5_VL"
eq "等级分布计数之和为 25" \
   "$(( EXP5_VH + EXP5_HI + EXP5_MD + EXP5_LO + EXP5_VL ))" "25"

# ============================================================================
section "5. 阈值边界（19.999/20、11.999/12、5.999/6、1.999/2）"
# ============================================================================

# 构造手法：边界评估 E2 只有 1 条风险项，且它的 importance=1、severity=1、
# 默认威胁 T=1。于是
#
#     R = 1 × w × 1 × 1 = w
#
# 把 asset_weight 覆盖成目标值，R 就精确等于它。
#
# 为什么不给阈值也传小数：后端 ParseConfig 的四个阈值参数是 **int**，
# 阈值本身只能是整数（与 system_configs 的 DECIMAL(6,3) 不冲突——阈值是
# "20 分"这种整数分界，权重才需要小数）。所以边界一律"动权重、不动阈值"。
#
# 为什么用 .999 而不是 .001 去测上侧：R 与阈值相等时属于哪一档，取决于
# 判定是闭区间还是开区间。测 19.999 落在"高"，19.999 与 20 只差一个
# 定点单位（0.001），任何浮点误差都会让它翻档——这正是定点实现要挡住的
# 那类 bug。
#
# boundary <权重字面量> <权重milli> <期望R milli> <期望档位> — 单条边界用例
boundary() {
  local wtext="$1" wm="$2" exp_rm="$3" exp_level="$4"
  local desc="R=$(m2f "$exp_rm") 判为 ${exp_level}（权重 ${wtext}）"
  json POST /api/assessments/preview \
    "{\"assessment_id\":$E2,\"asset_weight\":${wtext},\"thresholds\":{\"very_high\":20,\"high\":12,\"medium\":6,\"low\":2}}"
  local got_rm got_level
  got_rm="$(jmilli data.top_items.0.risk_value_r)"
  got_level="$(jget data.top_items.0.risk_level)"
  if [ "$LAST_STATUS" = "200" ] && [ "$got_rm" = "$exp_rm" ] && [ "$got_level" = "$exp_level" ]; then
    ok "$desc"
  else
    bad "$desc" "期望 R=$(m2f "$exp_rm") / ${exp_level}，实际 HTTP $LAST_STATUS / R=$(m2f "${got_rm:-0}") / ${got_level:-空}"
  fi
  # A 也该等于权重本身（importance=1）
  eq "  ↳ 同一条的 A = ${wtext}" "$(jmilli data.top_items.0.asset_value_a)" "$wm"
}

json POST /api/assessments/preview "{\"assessment_id\":$E2}"
eq "边界评估只有 1 条风险项（后续边界用例的前提）" "$(jget data.risk_items_count)" "1"
eq "边界评估的资产数为 1" "$(jget data.assets_count)" "1"
eq "边界评估返回的 top_items 恰有 1 条（不会被 20 条上限截断）" "$(jlen data.top_items)" "1"

# 独立算术核对：R = 1 × w_milli × T_milli(=1000) × 1
eq "独立算术核对 R(w=19.999)" "$(rmilli 1 19999 1000 1)" "19999"
eq "独立算术核对 R(w=19.999) 的档位" "$(level_milli 19999 20 12 6 2)" "high"

boundary "19.999" 19999 19999 "high"
boundary "20"     20000 20000 "very_high"
boundary "11.999" 11999 11999 "medium"
boundary "12"     12000 12000 "high"
boundary "5.999"  5999  5999  "low"
boundary "6"      6000  6000  "medium"
boundary "1.999"  1999  1999  "very_low"
boundary "2"      2000  2000  "low"

# 阈值本身也需要自洽校验：不严格递减 / 低档位小于 1 应当被拒
json POST /api/assessments/preview \
  "{\"assessment_id\":$E2,\"thresholds\":{\"very_high\":12,\"high\":12,\"medium\":6,\"low\":2}}"
expect "阈值不严格递减被拒" 400

json POST /api/assessments/preview \
  "{\"assessment_id\":$E2,\"thresholds\":{\"very_high\":20,\"high\":12,\"medium\":6,\"low\":0}}"
expect "低档位下界为 0 被拒" 400

json POST /api/assessments/preview "{\"assessment_id\":$E2,\"asset_weight\":0}"
expect "权重为 0 被拒" 400

# ============================================================================
section "6. 配置快照：改系统配置不追溯历史评估"
# ============================================================================

# 记下 E1 当下的快照与落库指纹
json GET "/api/assessments/$E1"
eq "E1 快照的资产权重为 1"      "$(jget data.config_snapshot.asset_weight)" "1"
eq "E1 快照的很高阈值为 20"     "$(jget data.config_snapshot.thresholds.very_high)" "20"
eq "E1 快照的模型标识正确"      "$(jget data.config_snapshot.model)" "gb_t_20984_multiplication"
E1_MAX_BEFORE="$(jmilli data.max_risk)"
E1_SNAP_BEFORE="$(jget data.config_snapshot)"

req GET "/api/assessments/$E1/risk-items?pageSize=200&importance=5&severity=5"
E1_55_BEFORE="$(jmilli data.items.0.risk_value_r)"
E1_55_A_BEFORE="$(jmilli data.items.0.asset_value_a)"

# 改系统配置：权重 1 → 1.5
json PATCH /api/system/configs '{"asset_weight":1.5}'
expect "改系统配置（权重 1 → 1.5）" 200
eq "  ↳ 接口回读权重为 1.5" "$(jget data.asset_weight)" "1.5"

# 老评估必须一字不改
json GET "/api/assessments/$E1"
eq "改配置后 E1 快照仍为权重 1"      "$(jget data.config_snapshot.asset_weight)" "1"
eq "改配置后 E1 快照整体不变"        "$(jget data.config_snapshot)" "$E1_SNAP_BEFORE"
eq "改配置后 E1 的 max_risk 不变"    "$(jmilli data.max_risk)" "$E1_MAX_BEFORE"

req GET "/api/assessments/$E1/risk-items?pageSize=200&importance=5&severity=5"
eq "改配置后 E1 落库的 A 不变（仍按快照 w=1）" "$(jmilli data.items.0.asset_value_a)" "$E1_55_A_BEFORE"
eq "改配置后 E1 落库的 R 不变"                 "$(jmilli data.items.0.risk_value_r)" "$E1_55_BEFORE"

# 落库层面再确认一次（不只信接口）
DB_SNAP="$(sql "SELECT JSON_EXTRACT(config_snapshot,'\$.asset_weight') FROM assessments WHERE id=$E1;")"
eq "直查库里 E1 快照权重仍是 1" "$(printf '%s' "$DB_SNAP" | tr -d ' ')" "1"

# 而「新的计算」必须用新配置：试算读的就是当前配置（不是快照）
json POST /api/assessments/preview "{\"assessment_id\":$E1}"
expect "改配置后的试算返回 200" 200
eq "独立算术：w=1.5 下 importance=1 的 A = 1.5" "$(( 1 * 1500 ))" "1500"
# top_items 按 R 从高到低（顺序在 build 源头定死，不只是"看起来像排过"），
# 所以首位必然是 i=5、s=5 的那条。注意 E1 的默认威胁此刻是穷举最后一轮
# 设下的 T=5，于是 R = (5×1.5) × 5 × 5 = 187.5。
eq "试算首位的 A = 7.5（用的是当前配置 1.5）" "$(jmilli data.top_items.0.asset_value_a)" "7500"
eq "  ↳ 首位的 i / s 确为 5 / 5" \
   "$(jget data.top_items.0.importance)/$(jget data.top_items.0.severity)" "5/5"
eq "  ↳ 首位的 T = 5（沿用穷举最后一轮的默认威胁）" \
   "$(jmilli data.top_items.0.threat_weight_t)" "5000"
eq "  ↳ 独立算术：R = 7.5 × 5 × 5 = 187.5" "$(rmilli 5 1500 5000 5)" "187500"
eq "  ↳ 试算首位的 R = 187.5" "$(jmilli data.top_items.0.risk_value_r)" "187500"

# 改回 1，便于后面各节用干净的整数基线
json PATCH /api/system/configs '{"asset_weight":1}'
expect "把系统权重改回 1" 200

# ============================================================================
section "7. 落库：条数 / 四列自洽 / 档位一致"
# ============================================================================

json POST "/api/assessments/$E3/calculate"
expect "落库评估计算成功" 200
eq "落库后状态为 calculated" "$(jget data.status)" "calculated"
eq "资产数为 5" "$(jget data.assets_count)" "5"
eq "风险项为 25" "$(jget data.risk_items_count)" "25"
ne "max_risk 不再是 null" "$(jget data.max_risk)" ""

# max_risk 的期望值：w=1、T=3、i=5、s=5 → R = 5 × 3 × 5 = 75
eq "独立算术：最大 R = 75" "$(rmilli 5 1000 3000 5)" "75000"
eq "max_risk 等于 75" "$(jmilli data.max_risk)" "75000"
eq "max_risk 的档位为 very_high" \
   "$(level_milli "$(rmilli 5 1000 3000 5)" 20 12 6 2)" "very_high"

req GET "/api/assessments/$E3/risk-items?pageSize=200"
eq "落库的 25 条能全量取回" "$(jget data.total)" "25"

SELF_BAD=0
SELF_SAMPLE=""
while IFS=$'\t' read -r imp sev am tm vm rm lvl; do
  [ -z "${imp:-}" ] && continue
  exp_rm=$(rmilli "$imp" 1000 3000 "$sev")
  exp_level=$(level_milli "$exp_rm" 20 12 6 2)
  # 四列自洽：A × T × V 在本脚本的定点序列下必须等于 R
  if [ "$rm" != "$exp_rm" ] || [ "$lvl" != "$exp_level" ] \
     || [ "$am" != "$(( imp * 1000 ))" ] || [ "$tm" != "3000" ] || [ "$vm" != "$(( sev * 1000 ))" ]; then
    SELF_BAD=$(( SELF_BAD + 1 ))
    if [ -z "$SELF_SAMPLE" ]; then
      SELF_SAMPLE="i=${imp} s=${sev} A=$(m2f "$am") T=$(m2f "$tm") V=$(m2f "$vm") R=$(m2f "$rm") ${lvl}"
    fi
  fi
done < <(dump_risk_items)

eq "落库的 25 条四列自洽且档位一致" "$SELF_BAD" "0"
[ "$SELF_BAD" -gt 0 ] && printf "     ${C_DIM}首个不一致：%s${C_RESET}\n" "$SELF_SAMPLE"

# 每条都必须满足 A×T×V=R 这个等式（用整数的乘除复算，容差为 0）
PURE_BAD=0
while IFS=$'\t' read -r imp sev am tm vm rm lvl; do
  [ -z "${imp:-}" ] && continue
  recomputed=$(( am * tm / 1000 * vm / 1000 ))
  [ "$recomputed" != "$rm" ] && PURE_BAD=$(( PURE_BAD + 1 ))
done < <(dump_risk_items)
eq "逐条 A×T×V 复算等于落库的 R" "$PURE_BAD" "0"

# 资产级汇总：每台资产的风险 = 其下最大 R（不是平均）
req GET "/api/assessments/$E3/risk-items?pageSize=200&importance=5"
eq "importance=5 的资产下有 5 条风险项" "$(jget data.total)" "5"
json GET "/api/assessments/$E3/matrix"
eq "矩阵格子数恒为 25" "$(jlen data.cells)" "25"
eq "矩阵 total 等于 risk_items_count" "$(jget data.total)" "25"
eq "矩阵 grid_size 为 5" "$(jget data.grid_size)" "5"
eq "矩阵 max_grade 为 5" "$(jget data.max_grade)" "5"

# ============================================================================
section "8. 三处一致：界面值 = 落库值 = 报告值（逐条）"
# ============================================================================

# ① 界面：走正常接口拿 25 条
req GET "/api/assessments/$E3/risk-items?pageSize=200"
cp "$BODY" /tmp/.sr-assess-ui.json

# ② 落库：直接查 MySQL，绕开所有业务代码
sql "SELECT asset_id, vuln_id, importance, severity, asset_value_a, threat_weight_t, vuln_weight_v, risk_value_r, risk_level
     FROM risk_items WHERE assessment_id=$E3 ORDER BY asset_id, vuln_id;" > "$DB_TSV"
DB_ROWS="$(wc -l < "$DB_TSV" | tr -d ' ')"
eq "库里 risk_items 有 25 行" "$DB_ROWS" "25"

# ③ 报告：export-data
req GET "/api/assessments/$E3/export-data"
cp "$BODY" /tmp/.sr-assess-export.json
eq "报告里含 25 条风险项" "$(jlen data.items)" "25"
eq "报告头部带配置快照" "$(jget data.config.asset_weight)" "1"

# 报告里也应按 R 从高到低（"最严重的排前面"），与 top_items 同源同序
EXPORT_SORT="$(python3 -c '
import json, sys
try:
    items = (json.load(open(sys.argv[1], encoding="utf-8")).get("data") or {}).get("items") or []
except Exception:
    print("读取失败"); raise SystemExit
vals = [float(i["risk_value_r"]) for i in items if i.get("risk_value_r") is not None]
if not vals:
    print("空列表"); raise SystemExit
for a, b in zip(vals, vals[1:]):
    if a < b:
        print("逆序 %s -> %s" % (a, b)); raise SystemExit
print("OK")
' /tmp/.sr-assess-export.json 2>/dev/null)"
eq "报告的风险项按 R 从高到低排列" "$EXPORT_SORT" "OK"
eq "报告首条即全局最大 R（75）" "$(jmilli data.items.0.risk_value_r)" "75000"

# 逐条比对三方。用 python 只做"读三个来源并相减"，不做任何数值换算，
# 换算在 dump/jmilli 里已经统一成 milli，这里纯比整数。
TRIPLE_OUT="$(python3 - /tmp/.sr-assess-ui.json /tmp/.sr-assess-export.json "$DB_TSV" <<'PY'
import json, sys, csv

ui_path, exp_path, db_path = sys.argv[1], sys.argv[2], sys.argv[3]

def load_items(path):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        return {}
    items = (data.get("data") or {}).get("items") or []
    out = {}
    for it in items:
        key = (int(it["asset_id"]), int(it["vuln_id"]))
        out[key] = {
            "a": int(round(float(it["asset_value_a"]) * 1000)),
            "t": int(round(float(it["threat_weight_t"]) * 1000)),
            "v": int(round(float(it["vuln_weight_v"]) * 1000)),
            "r": int(round(float(it["risk_value_r"]) * 1000)),
            "level": it["risk_level"],
        }
    return out

ui = load_items(ui_path)
rep = load_items(exp_path)

db = {}
with open(db_path, encoding="utf-8") as fh:
    for row in csv.reader(fh, delimiter="\t"):
        if len(row) < 9:
            continue
        key = (int(row[0]), int(row[1]))
        db[key] = {
            "a": int(round(float(row[4]) * 1000)),
            "t": int(round(float(row[5]) * 1000)),
            "v": int(round(float(row[6]) * 1000)),
            "r": int(round(float(row[7]) * 1000)),
            "level": row[8],
        }

problems = []
if len(ui) != 25:
    problems.append("界面条数=%d" % len(ui))
if len(rep) != 25:
    problems.append("报告条数=%d" % len(rep))
if len(db) != 25:
    problems.append("落库条数=%d" % len(db))

for key in sorted(set(ui) | set(rep) | set(db)):
    u, r, d = ui.get(key), rep.get(key), db.get(key)
    if u is None or r is None or d is None:
        problems.append("键 %s 三方不齐 (界面=%s 报告=%s 落库=%s)" % (
            key, u is not None, r is not None, d is not None))
        continue
    if u != r:
        problems.append("界面≠报告 %s: %s vs %s" % (key, u, r))
    if u != d:
        problems.append("界面≠落库 %s: %s vs %s" % (key, u, d))

print("\n".join(problems) if problems else "OK")
PY
)"

if [ "$TRIPLE_OUT" = "OK" ]; then
  ok "三个来源（界面 / 落库 / 报告）25 条逐条一致"
else
  bad "三个来源存在不一致" "$(printf '%s' "$TRIPLE_OUT" | head -3 | tr '\n' '; ')"
fi

# 报告头部的汇总值也要与任务一致
req GET "/api/assessments/$E3/export-data"
eq "报告 max_risk 与任务一致" "$(jmilli data.max_risk)" "75000"
eq "报告 level_counts 之和为 25" \
   "$(( $(jget data.level_counts.very_high) + $(jget data.level_counts.high) + $(jget data.level_counts.medium) + $(jget data.level_counts.low) + $(jget data.level_counts.very_low) ))" \
   "25"
eq "报告含 5 个资产" "$(jlen data.assets)" "5"

# ============================================================================
section "9. 矩阵：格子计数与 risk_items 分组一致"
# ============================================================================

json GET "/api/assessments/$E3/matrix"
cp "$BODY" /tmp/.sr-assess-matrix.json

MATRIX_OUT="$(python3 - /tmp/.sr-assess-matrix.json "$DB_TSV" <<'PY'
import json, sys, csv

cells = ((json.load(open(sys.argv[1], encoding="utf-8")).get("data") or {})).get("cells") or []

# 矩阵必须固定 25 格（含空格的 0）——"昨天这块是红的"依赖位置稳定
if len(cells) != 25:
    print("格子数=%d（应为 25）" % len(cells)); raise SystemExit

seen = set()
for c in cells:
    seen.add((int(c["importance"]), int(c["severity"])))
if len(seen) != 25:
    print("格子坐标有重复或缺失，去重后=%d" % len(seen)); raise SystemExit

by_cell = {}
with open(sys.argv[2], encoding="utf-8") as fh:
    for row in csv.reader(fh, delimiter="\t"):
        if len(row) < 9:
            continue
        key = (int(row[2]), int(row[3]))          # importance, severity
        by_cell.setdefault(key, []).append(int(round(float(row[7]) * 1000)))

problems = []
for c in cells:
    key = (int(c["importance"]), int(c["severity"]))
    want = len(by_cell.get(key, []))
    if int(c["count"]) != want:
        problems.append("格 %s 计数 %s ≠ 落库分组 %d" % (key, c["count"], want))
    maxr = max(by_cell.get(key, [0]))
    if int(round(float(c["max_risk"]) * 1000)) != maxr:
        problems.append("格 %s max_risk 不符" % (key,))

total = sum(int(c["count"]) for c in cells)
if total != 25:
    problems.append("格子计数之和=%d（应为 25）" % total)

print("\n".join(problems) if problems else "OK")
PY
)"

if [ "$MATRIX_OUT" = "OK" ]; then
  ok "25 格计数与 max_risk 逐格与落库分组一致"
else
  bad "矩阵与落库分组不一致" "$(printf '%s' "$MATRIX_OUT" | head -3 | tr '\n' '; ')"
fi

# ============================================================================
section "10. 下钻：按 (重要性, 严重程度) 过滤 = 矩阵该格"
# ============================================================================

# 逐格核对：对矩阵里的每个格子，按 (importance, severity) 过滤接口
# 返回的条数必须等于格子的 count —— 下钻不该多一条也不该少一条。
DRILL_BAD=0
DRILL_TOTAL=0
for i in 1 2 3 4 5; do
  for s in 1 2 3 4 5; do
    req GET "/api/assessments/$E3/risk-items?pageSize=200&importance=${i}&severity=${s}"
    got="$(jget data.total)"
    exp="$(sql "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$E3 AND importance=$i AND severity=$s;")"
    DRILL_TOTAL=$(( DRILL_TOTAL + 1 ))
    if [ "$got" != "$exp" ]; then
      DRILL_BAD=$(( DRILL_BAD + 1 ))
      printf "     ${C_DIM}格 (${i},${s})：接口 %s ≠ 落库 %s${C_RESET}\n" "$got" "$exp"
    fi
  done
done
eq "25 个格子的下钻集合与落库分组完全对应" "$DRILL_BAD" "0"
eq "核对过的格子数为 25" "$DRILL_TOTAL" "25"

# 下钻回来的条目本身也要真的属于该格
req GET "/api/assessments/$E3/risk-items?pageSize=200&importance=5&severity=5"
eq "格 (5,5) 的下钻条数" "$(jget data.total)" "1"
eq "格 (5,5) 的条目 importance=5" "$(jget data.items.0.importance)" "5"
eq "格 (5,5) 的条目 severity=5" "$(jget data.items.0.severity)" "5"
eq "格 (5,5) 的 R = 75" "$(jmilli data.items.0.risk_value_r)" "75000"

# 等级过滤与关键词过滤也顺带验一下（下钻列表的两个附加维度）
req GET "/api/assessments/$E3/risk-items?pageSize=200&level=very_high"
LEVEL_VH_API="$(jget data.total)"
LEVEL_VH_DB="$(sql "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$E3 AND risk_level='very_high';")"
eq "按等级过滤的条数与落库一致" "$LEVEL_VH_API" "$LEVEL_VH_DB"
eq "等级过滤的条数与独立算术的 very_high 计数一致" "$LEVEL_VH_API" "$EXP_VH"

# ============================================================================
section "11. 权重改 1.5 后 A 与 R 的传导（新评估用新配置）"
# ============================================================================

json PATCH /api/system/configs '{"asset_weight":1.5}'
expect "把系统权重改为 1.5" 200

json POST /api/assessments \
  "{\"name\":\"E2E 权重 1.5\",\"scope_type\":\"custom\",\"scope_ref\":${ASSET_JSON},\"default_threat_code\":\"${TH3_CODE}\"}"
expect "新建评估（将在权重 1.5 下计算）" 201
E4="$(jget data.id)"

json POST "/api/assessments/$E4/calculate"
expect "在权重 1.5 下计算" 200
eq "新评估的快照权重为 1.5" "$(jget data.config_snapshot.asset_weight)" "1.5"

req GET "/api/assessments/$E4/risk-items?pageSize=200"
eq "新评估仍是 25 条" "$(jget data.total)" "25"

TRANS_BAD=0
TRANS_SAMPLE=""
while IFS=$'\t' read -r imp sev am tm vm rm lvl; do
  [ -z "${imp:-}" ] && continue
  # A = importance × 1.5；R 走与后端逐位对应的定点序列
  exp_a=$(( imp * 1500 ))
  exp_rm=$(rmilli "$imp" 1500 3000 "$sev")
  exp_level=$(level_milli "$exp_rm" 20 12 6 2)
  if [ "$am" != "$exp_a" ] || [ "$rm" != "$exp_rm" ] || [ "$lvl" != "$exp_level" ]; then
    TRANS_BAD=$(( TRANS_BAD + 1 ))
    if [ -z "$TRANS_SAMPLE" ]; then
      TRANS_SAMPLE="i=${imp} s=${sev} 期望 A=$(m2f "$exp_a") R=$(m2f "$exp_rm") ${exp_level}，实际 A=$(m2f "$am") R=$(m2f "$rm") ${lvl}"
    fi
  fi
  # 与旧评估同一 (i,s) 对比：A 与 R 应各放大 1.5 倍
  old_am=$(( imp * 1000 ))
  if [ "$am" != "$(( old_am * 1500 / 1000 ))" ]; then
    TRANS_BAD=$(( TRANS_BAD + 1 ))
  fi
done < <(dump_risk_items)
eq "权重 1.5 下 25 条的 A 与 R 按独立算术传导正确" "$TRANS_BAD" "0"
[ "$TRANS_BAD" -gt 0 ] && printf "     ${C_DIM}首个不一致：%s${C_RESET}\n" "$TRANS_SAMPLE"

# 具体值抽查：i=5, s=5, T=3, w=1.5 → A=7.5，R=7.5×3×5=112.5
eq "独立算术：A=7500" "$(rmilli 5 1500 1000 1)" "7500"
eq "独立算术：R=112500" "$(rmilli 5 1500 3000 5)" "112500"
json GET "/api/assessments/$E4"
eq "新评估 max_risk = 112.5" "$(jmilli data.max_risk)" "112500"

# E1 上一轮是 T=5：R = i×1×5×s，最大 5×5×5=125。改配置不许追溯它。
json GET "/api/assessments/$E1"
eq "旧评估 E1 快照权重仍为 1（改配置不追溯）" "$(jget data.config_snapshot.asset_weight)" "1"
eq "E1（T=5, w=1）的 max_risk 仍是 125" "$(jmilli data.max_risk)" "125000"

json PATCH /api/system/configs '{"asset_weight":1}'
expect "把系统权重改回 1" 200

# ============================================================================
section "12. 重算幂等 + 逐项覆盖威胁在重算后保留"
# ============================================================================

req GET "/api/assessments/$E3/risk-items?pageSize=200"
FINGER_BEFORE="$(dump_risk_items | sort)"
E3_MAX_BEFORE="$(sql "SELECT max_risk FROM assessments WHERE id=$E3;")"

json POST "/api/assessments/$E3/calculate"
expect "再次计算（同配置）" 200
req GET "/api/assessments/$E3/risk-items?pageSize=200"
FINGER_AFTER="$(dump_risk_items | sort)"
eq "重算后 25 条逐条指纹不变" "$FINGER_AFTER" "$FINGER_BEFORE"
eq "重算后条数不翻倍" "$(jget data.total)" "25"
eq "重算后 max_risk 不变" "$(sql "SELECT max_risk FROM assessments WHERE id=$E3;")" "$E3_MAX_BEFORE"
eq "库里仍只有 25 行（唯一索引 + 先清后写）" \
   "$(sql "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$E3;")" "25"

# 逐项覆盖：把 (5,5) 那条的威胁从默认 T=3 改成 T=1
req GET "/api/assessments/$E3/risk-items?pageSize=200&importance=5&severity=5"
ITEM_55="$(jget data.items.0.id)"
eq "覆盖前该条来源为 default" "$(jget data.items.0.threat_source)" "default"

json PATCH "/api/assessments/$E3/risk-items/$ITEM_55" "{\"threat_code\":\"${TH1_CODE}\"}"
expect "逐项覆盖威胁为 T=1" 200
eq "  ↳ 该条来源变为 manual" "$(jget data.threat_source)" "manual"
# 覆盖后立刻用快照重算该条：A=5, T=1, V=5 → R=25
eq "独立算术：覆盖后 R = 25" "$(rmilli 5 1000 1000 5)" "25000"
eq "覆盖后该条 R = 25" "$(jmilli data.risk_value_r)" "25000"
eq "覆盖后该条 T = 1" "$(jmilli data.threat_weight_t)" "1000"

json POST "/api/assessments/$E3/calculate"
expect "覆盖后再整体重算" 200
req GET "/api/assessments/$E3/risk-items?pageSize=200&importance=5&severity=5"
eq "重算保留了逐项覆盖（仍为 manual）" "$(jget data.items.0.threat_source)" "manual"
eq "重算保留了覆盖后的威胁码" "$(jget data.items.0.threat_code)" "${TH1_CODE}"
eq "重算保留了覆盖后的 R = 25" "$(jmilli data.items.0.risk_value_r)" "25000"
eq "格 (5,5) 仍只有 1 条（重算不产生重复行）" "$(jget data.total)" "1"

# 清掉覆盖，回到基线（T=3 → R=75）。
# ⚠️ 必须重新取一次 item id：calculate 是「事务内先删后写」，
#    重算后风险项是**新插入的行**，自增 ID 全变了。拿着重算前的 ID 去
#    PATCH 会得到 404 —— 这不是接口的毛病，而是「风险项 ID 只在同一次
#    计算内有效」这条语义的直接后果（前端在重算后也必须重新拉列表）。
req GET "/api/assessments/$E3/risk-items?pageSize=200&importance=5&severity=5"
ITEM_55_NEW="$(jget data.items.0.id)"
ne "重算后该条换了新 ID（先删后写的直接后果）" "$ITEM_55_NEW" "$ITEM_55"

json PATCH "/api/assessments/$E3/risk-items/$ITEM_55_NEW" '{"threat_code":""}'
expect "清除逐项覆盖" 200
eq "清除后回落到任务级默认威胁 T=3" "$(jmilli data.threat_weight_t)" "3000"
eq "清除后 R 回到 75" "$(jmilli data.risk_value_r)" "75000"

# 删除一个评估：结果行应当被 CASCADE 带走
json POST /api/assessments \
  "{\"name\":\"E2E 待删除\",\"scope_type\":\"custom\",\"scope_ref\":${ASSET_JSON}}"
expect "建一个用于删除的评估" 201
E5="$(jget data.id)"
json POST "/api/assessments/$E5/calculate"
expect "先算出结果" 200
eq "删除前库里有 25 行" "$(sql "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$E5;")" "25"
json DELETE "/api/assessments/$E5"
expect "删除评估" 200
eq "评估删除后结果行被级联清空" "$(sql "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$E5;")" "0"
eq "资产级汇总也被级联清空" "$(sql "SELECT COUNT(*) FROM assessment_assets WHERE assessment_id=$E5;")" "0"

# ── 跨评估越权（IDOR）────────────────────────────────────────────────────
#
# 拿 E4 的风险项 id，去 E3 的路径下 PATCH。若实现只按 itemId 查而不校验
# 它是否属于路径上的 assessment，那就是一处 IDOR：能改掉**别的评估**的结论，
# 而且返回 200 时调用方完全看不出来。这里要求 404 而不是 403——
# 403 等于告诉对方"这条风险项确实存在，只是不归你"，存在性就泄漏了。
req GET "/api/assessments/$E4/risk-items?pageSize=1"
E4_ITEM="$(jget data.items.0.id)"
ne "取到了另一份评估的风险项 id" "$E4_ITEM" "$ITEM_55_NEW"
json PATCH "/api/assessments/$E3/risk-items/$E4_ITEM" "{\"threat_code\":\"${TH1_CODE}\"}"
expect "用别的评估的 itemId 覆盖本题风险项被拒" 404 RISK_ITEM_NOT_FOUND

# 确认它真的没被改（拒绝要是真的拒绝，不能只是返回码好看）
req GET "/api/assessments/$E4/risk-items?pageSize=200"
eq "另一份评估的风险项未被这次越权改动" \
   "$(sql "SELECT COUNT(*) FROM risk_items WHERE assessment_id=$E4 AND threat_source='manual';")" "0"

# ============================================================================
section "13. 审计员只读"
# ============================================================================

json POST /api/users \
  "{\"username\":\"e2e_auditor_$RANDOM\",\"display_name\":\"E2E 审计员\",\"password\":\"Auditor@2026x\",\"roles\":[\"auditor\"]}"
expect "管理员可创建只读账号" 201
AUDITOR_USER="$(jget data.username)"

login "$READONLY_JAR" "$AUDITOR_USER" "Auditor@2026x"
expect "只读账号可登录" 200
RO_CSRF="$SESSION_CSRF"

json_as "$READONLY_JAR" PATCH /api/auth/password \
  '{"old_password":"Auditor@2026x","new_password":"Auditor@2026y"}' "$RO_CSRF"
expect "只读账号首次改密" 200

login "$READONLY_JAR" "$AUDITOR_USER" "Auditor@2026y"
expect "只读账号改密后可登录" 200
RO_CSRF="$SESSION_CSRF"

json_as "$READONLY_JAR" GET "/api/assessments/$E3" '' "$RO_CSRF"
expect "只读角色可以看评估任务" 200

json_as "$READONLY_JAR" GET "/api/assessments/$E3/risk-items?pageSize=10" '' "$RO_CSRF"
expect "只读角色可以看风险项" 200

json_as "$READONLY_JAR" GET "/api/assessments/$E3/matrix" '' "$RO_CSRF"
expect "只读角色可以看矩阵" 200

json_as "$READONLY_JAR" GET "/api/assessments/$E3/export-data" '' "$RO_CSRF"
expect "只读角色可以导出报告数据" 200

json_as "$READONLY_JAR" GET /api/system/configs '' "$RO_CSRF"
expect "只读角色可以读系统配置（评估员要理解结果）" 200

json_as "$READONLY_JAR" POST /api/assessments \
  '{"name":"越权建","scope_type":"all"}' "$RO_CSRF"
expect "只读角色不能建评估" 403 FORBIDDEN

json_as "$READONLY_JAR" PATCH "/api/assessments/$E3" '{"name":"越权改"}' "$RO_CSRF"
expect "只读角色不能改评估" 403 FORBIDDEN

json_as "$READONLY_JAR" POST "/api/assessments/$E3/calculate" '' "$RO_CSRF"
expect "只读角色不能触发计算" 403 FORBIDDEN

json_as "$READONLY_JAR" DELETE "/api/assessments/$E3" '' "$RO_CSRF"
expect "只读角色不能删评估" 403 FORBIDDEN

json_as "$READONLY_JAR" PATCH "/api/assessments/$E3/risk-items/$ITEM_55_NEW" \
  "{\"threat_code\":\"${TH1_CODE}\"}" "$RO_CSRF"
expect "只读角色不能覆盖威胁" 403 FORBIDDEN

json_as "$READONLY_JAR" PATCH /api/system/configs '{"asset_weight":9.9}' "$RO_CSRF"
expect "只读角色不能改系统配置" 403 FORBIDDEN

# ============================================================================
section "14. 审计落库与服务端日志"
# ============================================================================

audit_has() {  # <动作> <描述>
  req GET "/api/audit-logs?action=$1&pageSize=1"
  if [ "$(jget data.total)" != "0" ]; then
    ok "$2"
  else
    bad "$2" "audit-logs?action=$1 的 total=0"
  fi
}

audit_has assessment.create          "建评估留下了审计（assessment.create）"
audit_has assessment.update          "改评估留下了审计（assessment.update）"
audit_has assessment.calculate       "计算留下了审计（assessment.calculate）"
audit_has assessment.risk_item_update "逐项覆盖威胁留下了审计（assessment.risk_item_update）"
audit_has assessment.export          "导出报告数据留下了审计（assessment.export）"
audit_has assessment.delete          "删评估留下了审计（assessment.delete）"
audit_has system_config.update       "改系统配置留下了审计（system_config.update）"

# 计算审计的明细要带得出「算了多少条、快照是什么」
req GET "/api/audit-logs?action=assessment.calculate&pageSize=20"
CALC_DETAIL="$(python3 -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    print(""); raise SystemExit
for it in items:
    d = str(it.get("detail", ""))
    if "risk_items_count" in d or "25" in d:
        print(d); raise SystemExit
print("")
' "$BODY" 2>/dev/null)"
contains "计算审计明细含风险项条数" "$CALC_DETAIL" "risk_items_count"
contains "计算审计明细含配置快照" "$CALC_DETAIL" "asset_weight"

# 服务端日志：不该有「写操作未记录审计」的告警，也不该有 ERROR
if grep -q "既未由中间件记录" "$SRV_LOG"; then
  bad "服务端日志出现「写操作未记录审计」告警" \
      "$(grep -m1 '既未由中间件记录' "$SRV_LOG")"
else
  ok "服务端日志没有「未记录审计」告警（reqctx 声明生效）"
fi

if grep -q '"level":"ERROR"' "$SRV_LOG"; then
  bad "服务端日志出现 ERROR" "$(grep -m1 '"level":"ERROR"' "$SRV_LOG")"
else
  ok "服务端日志无 ERROR"
fi

if grep -q "评估任务的配置快照不合法\|评估任务的配置快照无法解析" "$SRV_LOG"; then
  bad "出现了快照回退告警（说明快照没被正确使用）" \
      "$(grep -m1 '评估任务的配置快照' "$SRV_LOG")"
else
  ok "没有快照回退告警（历史评估用的确实是自己的快照）"
fi

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
  exit 1
fi

printf "\n  %sP4 风险评估引擎守门验证全部通过 ✅%s\n" "$C_GREEN" "$C_RESET"
