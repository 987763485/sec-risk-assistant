#!/usr/bin/env bash
# ============================================================================
# P5 报告导出 守门验证
#
# 验证什么（对应 docs/01-实现计划.md 里 P5 的验收标志
# 「Word 与 PDF 中文不乱码、图表正常、版式符合模板」）：
#
#   ▍本脚本最重要的一个设计决定：**把文件拆开看内部**
#
#   「导出成功、下载下来能打开」证明不了验收标志里的任何一条。一个所有
#   汉字都渲染成空心方框、或者整张明细表缺失的 docx，同样能 200 下载成功。
#
#   因此这里对三种产物都**解包到内部格式**再断言：
#     docx → word/document.xml（文本、表格、分页符、TOC 域、页脚）
#     xlsx → xl/worksheets/*.xml（工作表、单元格、**类型**）
#     pdf  → 内容流里的文本层（中文字符能不能被读回来）
#
#   这也是排查这类问题最快的手工手段（.docx 改名 .zip 直接看 XML），
#   这里把它自动化了。解析器在 scripts/lib/ooxml.py 与 scripts/lib/pdf_text.py。
#
#   覆盖的 13 节：
#
#    0. 环境准备：隔离库 sec_risk_report_e2e + 端口 18086 + 渲染上游可达性。
#    1. 登录并改掉引导密码。
#    2. 数据准备：5 档资产 × 5 档漏洞 + 1 条独立漏洞（制造一个「2 条」的矩阵格）、
#       两个威胁档、一个已计算任务、一个草稿任务，外加一条逐项覆盖的威胁。
#    3. Word：Content-Disposition 双端文件名、OOXML 结构（封面/目录/分页/
#       页脚/样式/合并单元格）+ 章节与表格内容。
#    4. Excel：三张表、明细行列数与数值类型（**数字不能写成文本**）、
#       矩阵表 25 格。
#    5. PDF：文本层抽回中文、命中章节标题与页码。
#    6. 五方一致：落库（直接查 MySQL）↔ 界面（risk-items）↔ export-data
#       ↔ Word 明细表 ↔ Excel 明细表，逐条比对四个数值与档位。
#    7. 未计算不可导出：草稿任务 409，且**不留下审计**。
#    8. 参数校验：格式、ID、空体各自 400/404。
#    9. 权限与会话：未登录 401、缺 CSRF 403、审计员可导出（设计如此）。
#   10. 上游不可用时的降级：停 docgen → Word 503 而 **Excel/PDF 仍可用**；
#       停 gotenberg → PDF 503 而 Word 仍可用；恢复后各自复原。
#   11. 导出确定性：同一任务连导两次，数值逐格相同（时间戳允许不同）。
#   12. 审计落库与服务端日志。
#
# ── 环境隔离 ───────────────────────────────────────────────────────────────
# 本脚本**不复用开发库**，临时建 sec_risk_report_e2e（理由同其它 verify-*.sh）。
# 端口用 18086，避免与 verify-assess.sh 的 18085 撞车。
#
# 用法： bash scripts/verify-report.sh
# 退出码：0 = 全部通过；1 = 存在失败项；2 = 前置条件不满足
#
# 前置条件：
#   1) MySQL 已启动：          make infra
#   2) 渲染上游已起并映射到宿主机回环：make infra 会做（见 deploy/compose.dev.yml）
#
#   ⚠️ 上游端口映射这一步不能跳过：主 compose 里 docgen / gotenberg 挂的是
#   `internal: true` 网络，而 Docker 会**静默丢弃** internal 网络上的端口映射
#   （不报错、`docker ps` 的 PORTS 列也空白）。宿主机上的 Go 进程因此连不上
#   它们，症状是「容器健康、配置看起来正确，导出 Word/PDF 一律 503」。
#   脚本会在第 0 节就把这条查出来，而不是等到第 3 节才看见一堆 503。
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT=18086
BASE="http://127.0.0.1:${PORT}"
E2E_DB="sec_risk_report_e2e"
E2E_ADMIN="admin"
# 临时库的临时口令：随进程生成，不写入任何文件，用完即随库删除
E2E_ADMIN_PW="Rp8!$(date +%s)$RANDOM"

OOXML="${ROOT}/scripts/lib/ooxml.py"
PDFTEXT="${ROOT}/scripts/lib/pdf_text.py"
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 \
  || PYTHON="/Users/chunle/.workbuddy/binaries/python/versions/3.13.12/bin/python3"

SRV_LOG="/tmp/sr-report-verify-srv.log"
BODY="/tmp/.sr-report-body"
HDR="/tmp/.sr-report-hdr"
DB_TSV="/tmp/.sr-report-db.tsv"

WORD_FILE="/tmp/.sr-report-word.docx"
EXCEL_FILE="/tmp/.sr-report-excel.xlsx"
PDF_FILE="/tmp/.sr-report-pdf.pdf"
PDF_TXT="/tmp/.sr-report-pdf.txt"
WORD_TABLES="/tmp/.sr-report-word-tables.tsv"
EXCEL_ITEMS="/tmp/.sr-report-excel-items.tsv"
EXCEL_AGAIN="/tmp/.sr-report-excel-again.xlsx"
UI_JSON="/tmp/.sr-report-ui.json"
EXPORT_JSON="/tmp/.sr-report-export.json"
MATRIX_JSON="/tmp/.sr-report-matrix.json"
CHECKS_PY="/tmp/.sr-report-checks.py"

ADMIN_JAR="/tmp/sr-report-admin.jar"
AUDITOR_JAR="/tmp/sr-report-auditor.jar"
AUDITOR_ID="$(date +%s)"

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
# HTTP 工具（与 verify-assess.sh 同源，改动请两边同步）
# ============================================================================

LAST_STATUS=0
LAST_CODE=""

# jget <点号路径> — 从 $BODY 中取值
#
# ⚠️ 数据文件路径通过参数传入，而不是用 stdin 重定向。
# 若写成 `python3 - <<'PY' < "$BODY"`，两个 stdin 重定向会互相覆盖，
# python 会把数据文件当脚本读取，函数永远返回空值 —— 静默失效，极难排查。
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

# file_code <file> — 从响应体文件里取业务码；不是 JSON（真的是一段二进制）时返回 <binary>
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
    *) bad "$1" "在文本中未找到「$3」" ;;
  esac
}

# file_has <描述> <文件> <子串>
file_has() {
  if grep -qF -- "$3" "$2" 2>/dev/null; then
    ok "$1"
  else
    bad "$1" "文件 ${2} 中未找到「${3}」"
  fi
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

# dl <格式> <评估ID> <输出文件> [jar] [csrf]
#
# 导出接口的响应体**要么是二进制、要么是 JSON 错误信封**，同一个 URL 两副
# 面孔（见 handler/report.go 的说明）。所以这里不能像 req/json 那样统一
# `jget code`：本节的成功路径下 $BODY 已经是一段 zip/pdf，再去 JSON.parse
# 只会得到空值，而空值会被 expect 当成「没有业务码」，于是 200 那一条
# 看着是绿的、实际什么也没验证。改成从输出文件里读，二进制就明确标成
# <binary>。
#
# -m 240：PDF 链路最慢（本进程渲染 HTML + Gotenberg 的 Chromium 转换），
# 服务端 write_timeout 是 180s。给到 240s 是为了让**服务端先决定结局**，
# 而不是 curl 先放弃、把一个已经渲染好的文件丢在服务端。
dl() {
  local format="$1" aid="$2" out="$3" jar="${4:-$ADMIN_JAR}" token="${5:-$SESSION_CSRF}"
  LAST_STATUS=$(curl -sS --noproxy '*' -m 240 -c "$jar" -b "$jar" -D "$HDR" -o "$out" \
    -w '%{http_code}' -X POST "$BASE/api/reports/export" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $token" \
    -d "{\"assessment_id\":${aid},\"format\":\"${format}\"}" 2>/dev/null)
  LAST_CODE=$(file_code "$out")
}

# ============================================================================
# 环境准备工具
# ============================================================================

env_value() {
  sed -n "s/^$1=//p" "$ROOT/.env" 2>/dev/null | head -1 | tr -d '"'\''' | tr -d '\r'
}

MYSQL_ROOT_PW="$(env_value MYSQL_ROOT_PASSWORD)"
MYSQL_USER_VAL="$(env_value MYSQL_USER)"; MYSQL_USER_VAL="${MYSQL_USER_VAL:-secrisk}"

# 渲染上游的宿主端口。.env 里可能没有这两项（它们只服务于 dev 场景），
# 因此显式给默认值 —— 留空会拼出 "http://127.0.0.1:" 这种地址，
# 而 curl 对它的报错是「URL 无效」，与「端口映射没建立」完全是两回事。
DOCGEN_PORT_VAL="$(env_value DOCGEN_PORT)"; DOCGEN_PORT_VAL="${DOCGEN_PORT_VAL:-8090}"
GOTENBERG_PORT_VAL="$(env_value GOTENBERG_PORT)"; GOTENBERG_PORT_VAL="${GOTENBERG_PORT_VAL:-3000}"
DOCGEN_URL="http://127.0.0.1:${DOCGEN_PORT_VAL}"
GOTENBERG_URL="http://127.0.0.1:${GOTENBERG_PORT_VAL}"
INTERNAL_SECRET="$(env_value SR_INTERNAL_SHARED_SECRET)"

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
# 「界面里是『RPT 漏洞 S=1』、落库里是『RPT ?? S=1』」看起来非常像写库时
# 编码坏了，排查方向会跑偏到迁移脚本与字段字符集上去。
# （历史脚本此前的 sql() 只读数值，所以一直没暴露这个问题。）
sql() {
  compose exec -T mysql mysql -N -B --default-character-set=utf8mb4 \
    -uroot -p"$MYSQL_ROOT_PW" "$E2E_DB" -e "$1" 2>/dev/null
}

# wait_http <url> <秒数> — 轮询到可达为止
wait_http() {
  local url="$1" secs="$2" i
  for i in $(seq 1 "$secs"); do
    if curl -fsS --noproxy '*' -m 2 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

# ensure_running <容器名> — 把容器拉回运行态并等到健康
#
# 第 10 节会主动停掉 docgen / gotenberg 来验证降级。这一步保证**无论脚本
# 是正常结束、断言失败退出、还是 Ctrl-C**，上游都会被恢复 —— 否则用户
# 下次打开页面发现导出是 503，且完全想不到是几分钟前的一次验证留下的。
ensure_running() {
  local name="$1" url="$2"
  if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]; then
    docker start "$name" >/dev/null 2>&1 || true
  fi
  wait_http "$url/health" 60 || true
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

  # 恢复渲染上游（第 10 节停过它们）
  ensure_running secrisk-docgen "$DOCGEN_URL"
  ensure_running secrisk-gotenberg "$GOTENBERG_URL"
  echo "  ${C_DIM}渲染上游已恢复运行${C_RESET}"

  if [ -n "$MYSQL_ROOT_PW" ]; then
    compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
      -e "DROP DATABASE IF EXISTS \`$E2E_DB\`;" >/dev/null 2>&1 \
      && echo "  ${C_DIM}已删除临时库 ${E2E_DB}${C_RESET}"
  fi
  rm -f "$ADMIN_JAR" "$AUDITOR_JAR" "$DB_TSV" "$PDF_TXT" "$WORD_TABLES" "$EXCEL_ITEMS" "$CHECKS_PY"
  rm -f "$UI_JSON" "$EXPORT_JSON" "$MATRIX_JSON" "$EXCEL_AGAIN"
  rm -f /tmp/.sr-report-word-text.txt /tmp/.sr-report-excel-*.tsv
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

# 渲染上游的**宿主机可达性**。这一条必须在起服务之前查：
# 它是最容易在配置上「看起来对」而实际不通的一环（见文件头说明）。
if ! curl -fsS --noproxy '*' -m 3 "$DOCGEN_URL/health" >/dev/null 2>&1; then
  echo "  docgen 在宿主机 ${DOCGEN_URL} 上不可达。"
  echo "  这通常意味着端口映射没建立（internal 网络会静默丢弃 ports）："
  docker port secrisk-docgen 2>/dev/null || echo "    secrisk-docgen 无端口映射"
  echo "  请执行 make infra（它会叠加 deploy/compose.dev.yml）后重试。"
  exit 2
fi
if ! curl -fsS --noproxy '*' -m 3 "$GOTENBERG_URL/health" >/dev/null 2>&1; then
  echo "  gotenberg 在宿主机 ${GOTENBERG_URL} 上不可达。"
  docker port secrisk-gotenberg 2>/dev/null || echo "    secrisk-gotenberg 无端口映射"
  echo "  请执行 make infra 后重试。"
  exit 2
fi
ok "渲染上游在宿主机可达（docgen / gotenberg）"

if [ -z "$INTERNAL_SECRET" ]; then
  echo "  未能从 .env 读取 SR_INTERNAL_SHARED_SECRET —— Word 导出会被 docgen 以 401 拒绝"
  exit 2
fi
ok "已读到服务间共享密钥（Word 链路要它）"

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

rm -f "$ADMIN_JAR"

# ------------------------------------------------------------------ 校验脚本

cat > "$CHECKS_PY" <<'PYEOF'
#!/usr/bin/env python3
"""比对脚本：把「报告里的数字」与「系统里的数字」逐条对齐。

调用： checks.py <lib-dir> <子命令> <参数...>

输出： 每行 `PASS <描述>` 或 `FAIL <描述> | <详情>`，由 bash 侧转成 ✅/❌。
       刻意不用退出码传递结果：这里有几十条独立断言，一条失败不该让后面的
       全部不跑 —— 那种「修一条跑一次」的节奏会让排查变成猜谜。
"""
import json
import re
import sys

LIB = sys.argv[1]
sys.path.insert(0, LIB)
import ooxml  # noqa: E402

LEVEL_LABEL = {
    'very_high': '很高', 'high': '高', 'medium': '中',
    'low': '低', 'very_low': '很低',
}

FAILURES = []


def check(cond, name, detail=''):
    if cond:
        print(f'PASS {name}')
    else:
        print(f'FAIL {name} | {detail}')
        FAILURES.append(name)


def go_num(v):
    """复刻 Go 的 strconv.FormatFloat(v,'f',-1,64)。

    报告里的数值文本由 report.Num 生成，而 Python 的 str(12.0) 是 "12.0"、
    Go 的是 "12"。不统一的话「报告值 = 落库值」的逐字比对会在整数上全错，
    看起来像渲染漏了小数位，实际只是两种语言的最短表示不同。
    本系统的数值都是 milli 的整数倍，三位小数足够无损。
    """
    f = float(v)
    if abs(f - round(f)) < 1e-9:
        return str(int(round(f)))
    return f'{f:.3f}'.rstrip('0').rstrip('.')


def milli(v):
    return int(round(float(v) * 1000))


def load_json(path):
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)


# ------------------------------------------------------------ 三源一致

def three_source(db_tsv, ui_json, export_json):
    db = []
    with open(db_tsv, encoding='utf-8') as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) < 4:
                continue
            db.append((parts[0], parts[1], milli(parts[2]), parts[3]))

    ui = load_json(ui_json)['data']['items']
    export = load_json(export_json)['data']['items']

    def norm(rows):
        return {(r['asset_name'], r['vuln_title']):
                (milli(r['risk_value_r']), r['risk_level']) for r in rows}

    db_map = {(a, v): (r, lv) for a, v, r, lv in db}
    ui_map, ex_map = norm(ui), norm(export)

    check(len(db_map) == len(ui_map) == len(ex_map),
          f'三源条数一致（落库/界面/export-data = {len(db_map)}/{len(ui_map)}/{len(ex_map)}）',
          f'落库 {len(db_map)}、界面 {len(ui_map)}、export-data {len(ex_map)}')

    check(set(db_map) == set(ui_map),
          '界面与落库的项目集合完全相同（无多、无漏）',
          f'仅在界面: {sorted(set(ui_map) - set(db_map))[:3]}；'
          f'仅在落库: {sorted(set(db_map) - set(ui_map))[:3]}')

    check(set(db_map) == set(ex_map),
          'export-data 与落库的项目集合完全相同',
          f'仅在 export: {sorted(set(ex_map) - set(db_map))[:3]}')

    diffs = [k for k in db_map if db_map[k] != ui_map.get(k)]
    check(not diffs, '逐条比对：R 值（定点）与风险等级完全一致',
          f'{len(diffs)} 条不一致，例如 {diffs[:3]}：'
          + '，'.join(f'{k} 落库={db_map[k]} 界面={ui_map.get(k)}' for k in diffs[:3]))


# ------------------------------------------------------------ Word

def docx_items(docx_path):
    """从 docx 里取出明细表，返回 [ [cell, ...], ... ]（不含表头行）。

    不按「第 6 张表」这种位置取，而是按表头内容找：报告的章节顺序是设计
    决定的，但脚本不该把「顺序」当成契约 —— 一旦章节调整，位置断言会
    变成「明细表比对静默跳过」，那比失败更糟。
    """
    z = ooxml.open_zip(docx_path)
    doc = z.read('word/document.xml').decode('utf-8')
    for _, _, _, tbl_inner in ooxml.elements(doc, 'tbl'):
        rows = []
        for _, _, _, row_inner in ooxml.elements(tbl_inner, 'tr'):
            rows.append([ooxml.text_of(c).replace('\n', ' ')
                         for _, _, _, c in ooxml.elements(row_inner, 'tc')])
        if rows and rows[0] and rows[0][0].strip() == '序号':
            return rows[1:], rows[0]
    return [], []


def word(docx_path, export_json):
    items = load_json(export_json)['data']['items']
    rows, headers = docx_items(docx_path)

    check(headers == ['序号', '资产', '漏洞', '威胁', '重要性', 'A', 'T', 'V', 'R', '等级'],
          'Word 明细表表头与预期一致',
          f'实际表头：{headers}')

    check(len(rows) == len(items),
          f'Word 明细表行数与导出的风险项条数一致（{len(items)} 行）',
          f'表里 {len(rows)} 行、export-data {len(items)} 条')

    if len(rows) != len(items):
        return

    bad_r, bad_level, bad_vuln, bad_seq = [], [], [], []
    for i, (row, it) in enumerate(zip(rows, items), start=1):
        # 列序：0 序号 1 资产 2 漏洞 3 威胁 4 重要性 5 A 6 T 7 V 8 R 9 等级
        if len(row) < 10:
            bad_r.append(f'第 {i} 行只有 {len(row)} 列')
            continue
        if row[0] != str(i):
            bad_seq.append(f'第 {i} 行序号为 {row[0]}')
        if row[2] != it['vuln_title']:
            bad_vuln.append(f'第 {i} 行 {row[2]!r} ≠ {it["vuln_title"]!r}')
        if row[8] != go_num(it['risk_value_r']):
            bad_r.append(f'第 {i} 行 {row[8]!r} ≠ {go_num(it["risk_value_r"])!r}')
        if row[9] != LEVEL_LABEL.get(it['risk_level'], it['risk_level']):
            bad_level.append(f'第 {i} 行 {row[9]!r}')

    check(not bad_seq, 'Word 明细表序号为 1..N 连续', '；'.join(bad_seq[:3]))
    check(not bad_vuln, 'Word 明细表「漏洞」列逐行与 export-data 相同', '；'.join(bad_vuln[:3]))
    check(not bad_r, 'Word 明细表 R 列逐行与 export-data 相同（报告值 = 落库值）',
          '；'.join(bad_r[:3]))
    check(not bad_level, 'Word 明细表等级列逐行与 export-data 相同', '；'.join(bad_level[:3]))


# ------------------------------------------------------------ Excel

def xlsx_rows(path, sheet):
    z = ooxml.open_zip(path)
    sheet_xml, shared = ooxml.resolve_sheet(z, sheet)

    def col_index(ref):
        letters = ''
        for ch in ref:
            if ch.isalpha():
                letters += ch
            else:
                break
        n = 0
        for ch in letters or 'A':
            n = n * 26 + (ord(ch) - ord('A') + 1)
        return n - 1

    out = []
    for _, _, _, row_inner in ooxml.elements(sheet_xml, 'row'):
        cells = {}
        width = 0
        for m in re.finditer(r'<c\b([^>]*)>(.*?)</c>', row_inner, re.S):
            attrs, body = m.group(1), m.group(2)
            ref_m = re.search(r'r="([A-Z]+\d+)"', attrs)
            if not ref_m:
                continue
            idx = col_index(ref_m.group(1))
            cells[idx] = ooxml.decode_cell(attrs, body, shared)
            width = max(width, idx + 1)
        if width:
            out.append([cells.get(i, '') for i in range(width)])
    return out


def excel(xlsx_path, export_json):
    items = load_json(export_json)['data']['items']
    rows = xlsx_rows(xlsx_path, '风险项明细')

    check(len(rows) >= 2, 'Excel 明细表至少含标题行与表头行', f'实际 {len(rows)} 行')
    if len(rows) < 2:
        return

    check(rows[0] and '风险项明细' in rows[0][0], 'Excel 明细表第 1 行是含表名的标题',
          f'实际：{rows[0][:1]}')
    check(rows[1][:11] == ['序号', '资产名称', '资产IP', '漏洞', '威胁',
                           '重要性', 'A', 'T', 'V', 'R', '等级'],
          'Excel 明细表表头与预期一致', f'实际表头：{rows[1][:11]}')

    data_rows = rows[2:]
    check(len(data_rows) == len(items),
          f'Excel 明细表数据行数与风险项条数一致（{len(items)} 行）',
          f'表里 {len(data_rows)} 行、export-data {len(items)} 条')
    if len(data_rows) != len(items):
        return

    bad_r, bad_level, bad_asset = [], [], []
    for i, (row, it) in enumerate(zip(data_rows, items), start=1):
        row = row + [''] * (11 - len(row))
        if row[1] != it['asset_name']:
            bad_asset.append(f'第 {i} 行 {row[1]!r}')
        if row[9] != go_num(it['risk_value_r']):
            bad_r.append(f'第 {i} 行 {row[9]!r} ≠ {go_num(it["risk_value_r"])!r}')
        if row[10] != LEVEL_LABEL.get(it['risk_level'], it['risk_level']):
            bad_level.append(f'第 {i} 行 {row[10]!r}')

    check(not bad_asset, 'Excel 明细表「资产名称」列逐行与 export-data 相同', '；'.join(bad_asset[:3]))
    check(not bad_r, 'Excel 明细表 R 列逐行与 export-data 相同', '；'.join(bad_r[:3]))
    check(not bad_level, 'Excel 明细表等级列逐行与 export-data 相同', '；'.join(bad_level[:3]))


# ------------------------------------------------------------ 入口

def main():
    cmd = sys.argv[2]
    if cmd == 'three-source':
        three_source(sys.argv[3], sys.argv[4], sys.argv[5])
    elif cmd == 'word':
        word(sys.argv[3], sys.argv[4])
    elif cmd == 'excel':
        excel(sys.argv[3], sys.argv[4])
    else:
        print(f'FAIL 未知子命令 {cmd} | 检查脚本调用参数')
    return 0


if __name__ == '__main__':
    sys.exit(main())
PYEOF

# run_checks — 把校验脚本的 PASS/FAIL 行转成 ok/bad
#
# ⚠️ 用进程替换 `< <(...)` 而不是管道：管道会让 while 跑在子 shell 里，
#    ok/bad 的计数传不回父 shell，最后汇总显示 0 项、脚本假绿退出。
run_checks() {
  local line
  while IFS= read -r line; do
    case "$line" in
      PASS\ *) ok "${line#PASS }" ;;
      FAIL\ *) bad "${line#FAIL }" ;;
      *) [ -n "$line" ] && info "$line" ;;
    esac
  done
}

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
  SR_INTERNAL_SHARED_SECRET="$INTERNAL_SECRET" \
  SR_INTERNAL_DOCGEN_URL="$DOCGEN_URL" \
  SR_INTERNAL_GOTENBERG_URL="$GOTENBERG_URL" \
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

NEW_PW="${E2E_ADMIN_PW}New1"
json PATCH /api/auth/password \
  "{\"old_password\":\"$E2E_ADMIN_PW\",\"new_password\":\"$NEW_PW\"}"
expect "首次改密成功" 200

login "$ADMIN_JAR" "$E2E_ADMIN" "$NEW_PW"
expect "改密后可重新登录" 200
ADMIN_NAME="$E2E_ADMIN"

# ============================================================================
section "2. 数据准备（资产 / 漏洞 / 威胁 / 评估任务）"
# ============================================================================

# ── 威胁字典：两档权重，用于验证 T 真的进报告 ───────────────────────────
#
# 只用两档就够：任务的默认威胁与「逐项覆盖」各取一个，报告里的 T 列
# 因此有两种取值，比全用同一个值更能证明「这一列是数据驱动的」。
json POST /api/dictionaries \
  '{"category":"threat","code":"rpt_t3","name":"RPT 威胁 T=3","weight":3}'
expect "建威胁字典 rpt_t3（权重 3）" 201
TH_DEFAULT="$(jget data.code)"

json POST /api/dictionaries \
  '{"category":"threat","code":"rpt_t5","name":"RPT 威胁 T=5","weight":5}'
expect "建威胁字典 rpt_t5（权重 5）" 201
TH_OVERRIDE="$(jget data.code)"

# ── 资产：5 档重要性 ────────────────────────────────────────────────────
ASSET_IDS=()
for i in 1 2 3 4 5; do
  json POST /api/assets \
    "{\"name\":\"RPT-ASSET-${i}\",\"asset_type\":\"server\",\"ip_address\":\"10.20.30.${i}\",\"importance\":${i}}"
  expect "建资产 RPT-ASSET-${i}（重要性 ${i}）" 201
  ASSET_IDS+=("$(jget data.id)")
done

# ── 漏洞：5 档严重程度 + 1 条额外的严重程度 5 ──────────────────────────
#
# 额外那条只挂到 A5 上：这样矩阵里 (重要性 5, 严重程度 5) 这一格会有 **2 条**，
# 其余格各 1 条。全是 1 的矩阵看起来整齐，却证明不了「计数是对的」——
# 一个把格内计数恒写成 1 的实现同样能通过。
VULN_IDS=()
for s in 1 2 3 4 5; do
  json POST /api/vulnerabilities "{\"title\":\"RPT 漏洞 S=${s}\",\"severity\":${s}}"
  expect "建漏洞 RPT 漏洞 S=${s}（严重程度 ${s}）" 201
  VULN_IDS+=("$(jget data.id)")
done

json POST /api/vulnerabilities '{"title":"RPT 漏洞 S=5（附加）","severity":5}'
expect "建附加漏洞（严重程度 5）" 201
VULN_EXTRA="$(jget data.id)"

ALL_ASSET_JSON="$(printf '%s,' "${ASSET_IDS[@]}")"
ALL_ASSET_JSON="[${ALL_ASSET_JSON%,}]"

for idx in 0 1 2 3 4; do
  json POST "/api/vulnerabilities/${VULN_IDS[$idx]}/assets" "{\"asset_ids\":${ALL_ASSET_JSON}}"
  expect "把漏洞 S=$((idx + 1)) 挂到 5 台资产上" 200
done
json POST "/api/vulnerabilities/${VULN_EXTRA}/assets" "{\"asset_ids\":[${ASSET_IDS[4]}]}"
expect "附加漏洞只挂到 A5（制造一个计数为 2 的矩阵格）" 200

# ── 主评估任务 ──────────────────────────────────────────────────────────
json POST /api/assessments \
  "{\"name\":\"P5 报告导出验证\",\"description\":\"覆盖三格式与五方一致\",\"scope_type\":\"custom\",\"scope_ref\":${ALL_ASSET_JSON},\"default_threat_code\":\"${TH_DEFAULT}\"}"
expect "建主评估任务" 201
MAIN_ID="$(jget data.id)"
MAIN_NAME="$(jget data.name)"
eq "新建任务初始状态为 draft" "$(jget data.status)" "draft"

# ── 草稿任务（第 7 节要用它验证「未计算不可导出」）─────────────────────
json POST /api/assessments \
  "{\"name\":\"P5 草稿任务\",\"scope_type\":\"custom\",\"scope_ref\":${ALL_ASSET_JSON},\"default_threat_code\":\"${TH_DEFAULT}\"}"
expect "建草稿任务" 201
DRAFT_ID="$(jget data.id)"

# ── 计算 ────────────────────────────────────────────────────────────────
#
# 必须先算：逐项覆盖只能作用在已存在的风险项上，而报告也只从已计算的
# 任务里取数（未计算在接口层就被 409 拦住，见第 7 节）。
json POST "/api/assessments/${MAIN_ID}/calculate" '{}'
expect "计算主评估（幂等落库）" 200
CALC_COUNT="$(jget data.risk_items_count)"
eq "计算产出 26 条风险项（5×5 + 1）" "$CALC_COUNT" "26"

# ── 逐项覆盖一条风险项的威胁 ────────────────────────────────────────────
#
# 覆盖会让这一条的 T 从 3 变成 5，于是报告里的 T 列出现第二种取值 ——
# 也就证明了报告读的是**落库后的风险项**，而不是任务级默认威胁。
json GET "/api/assessments/${MAIN_ID}/risk-items?pageSize=1"
FIRST_ITEM="$(jget data.items.0.id)"
if [ -n "$FIRST_ITEM" ]; then
  json PATCH "/api/assessments/${MAIN_ID}/risk-items/${FIRST_ITEM}" \
    "{\"threat_code\":\"${TH_OVERRIDE}\"}"
  expect "逐项覆盖一条风险项的威胁" 200
  eq "覆盖后该条目的 T 变为 5" "$(jget data.threat_weight_t)" "5"
else
  bad "逐项覆盖一条风险项的威胁" "取不到任何风险项 id"
fi

# ============================================================================
section "3. Word 报告（中文、版式、模板结构）"
# ============================================================================

dl word "$MAIN_ID" "$WORD_FILE"
expect "导出 Word 成功" 200
eq "Content-Type 为 docx" "$(hdr content-type)" \
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

DISPOSITION="$(hdr content-disposition)"
contains "Content-Disposition 带 RFC 5987 的 filename*" "$DISPOSITION" "filename*=UTF-8''"
contains "Content-Disposition 带 ASCII 兜底名" "$DISPOSITION" "security-assessment-report.docx"

# 抽 filename* 的值并解码。
#
# 分两步（先 sed 取编码串、再 python 解码）而不是在 `python3 -c` 里塞一个
# 含单引号的正则：`filename*=UTF-8''…` 里那对连续单引号在 shell 的单引号
# 字符串里需要 `'"'"'` 这种拼接，写出来几乎没法读，改错一个引号就会静默
# 匹配不到（返回空串，然后断言以「名字里没有评估名」的形式失败）。
EXT_NAME="$(printf '%s' "$DISPOSITION" | sed -n "s/.*filename\*=UTF-8''\([^;]*\).*/\1/p")"
DECODED_NAME="$("$PYTHON" -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' \
  "$EXT_NAME" 2>/dev/null)"
info "下载文件名：${DECODED_NAME}"
# 文件名里的评估名由服务端清洗（SanitizeFileName）：字母/数字/汉字、
# 以及 `- _ 空格 .` 原样保留，其余字符换成下划线（防的是 `"` 造成的
# 响应头注入、`/` 被当成路径、控制字符让浏览器拒绝保存）。
# 这里刻意断言「含评估名原文」而不是「含某种改写形态」——把清洗规则
# 抄进断言，等于在测试里维护第二份实现，规则一变两边就会各说各话。
contains "解码后的文件名含评估名" "$DECODED_NAME" "$MAIN_NAME"
case "$DECODED_NAME" in
  *.docx) ok "解码后的文件名扩展名为 .docx" ;;
  *) bad "解码后的文件名扩展名为 .docx" "实际：${DECODED_NAME}" ;;
esac

if [ "$(head -c 2 "$WORD_FILE")" = "PK" ]; then
  ok "产物是 zip 容器（docx 的物理形态）"
else
  bad "产物是 zip 容器（docx 的物理形态）" "$(file -b "$WORD_FILE" 2>/dev/null)"
fi

# ── OOXML 结构：这些点失败都是「编译/运行都不报错，只是样式不生效」───────
WORD_STRUCT="$("$PYTHON" "$OOXML" docx-structure "$WORD_FILE" 2>/dev/null)"
sval() { printf '%s\n' "$WORD_STRUCT" | sed -n "s/^$1=//p"; }

eq "封面与目录之后各留一页，且 6 个章节另起一页（共 8 处分页符）" \
  "$(sval page_breaks)" "8"
eq "w:sectPr 是 w:body 的最后一个子元素（顺序错 Word 会拒绝打开）" \
  "$(sval sectpr_last)" "true"
eq "目录是真正的 TOC 域（而不是手写的一串标题）" "$(sval toc_field)" "true"
eq "TOC 域含 separate（缺它目录一片空白且不报错）" "$(sval toc_separate)" "true"
eq "页脚含 PAGE 域（页码才会自动更新）" "$(sval footer_page_field)" "true"
eq "报告用到的自定义样式全部已注册（引用未注册的 StyleId 不报错但无效）" \
  "$(sval styles_registered)" "true"
eq "表格数量为 6（概述/配置/等级分布/矩阵/资产汇总/明细）" "$(sval table_count)" "6"
eq "矩阵说明行用了横向合并单元格（w:gridSpan）" "$(sval has_gridspan)" "true"
eq "跨页表头重复（长表格翻页后仍能看到列名）" "$(sval has_tblheader)" "true"

# 页脚文本：报告要能自己回答「哪份评估、何时生成」
FOOTER_TEXT="$(sval footer_text)"
contains "页脚含评估名" "$FOOTER_TEXT" "$MAIN_NAME"

# ── 内容：章节齐全 + 中文没有丢 ─────────────────────────────────────────
"$PYTHON" "$OOXML" docx-text "$WORD_FILE" > "/tmp/.sr-report-word-text.txt" 2>/dev/null

for heading in "一、评估概述" "二、评估方法与配置" "三、风险等级分布" \
               "四、风险矩阵" "五、资产风险汇总" "六、风险项明细" "附：口径说明"; do
  file_has "Word 含章节「${heading}」" "/tmp/.sr-report-word-text.txt" "$heading"
done

file_has "Word 含评估任务名" "/tmp/.sr-report-word-text.txt" "$MAIN_NAME"
file_has "Word 含导出人登录名" "/tmp/.sr-report-word-text.txt" "$ADMIN_NAME"
file_has "Word 含 GB/T 20984 的计算口径说明" "/tmp/.sr-report-word-text.txt" "GB/T 20984"

# 表格：明细表表头 + 逐行数值比对（第 6 节统一做，这里先确认表存在）
"$PYTHON" "$OOXML" docx-tables "$WORD_FILE" > "$WORD_TABLES" 2>/dev/null
eq "Word 表格里恰好有一张以「序号」开头的明细表" \
  "$(grep -c '^序号' "$WORD_TABLES")" "1"

# ============================================================================
section "4. Excel 报告（三张表、数值类型、矩阵）"
# ============================================================================

dl excel "$MAIN_ID" "$EXCEL_FILE"
expect "导出 Excel 成功" 200
eq "Content-Type 为 xlsx" "$(hdr content-type)" \
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
contains "Content-Disposition 兜底名是 .xlsx" "$(hdr content-disposition)" \
  "security-assessment-report.xlsx"

if [ "$(head -c 2 "$EXCEL_FILE")" = "PK" ]; then
  ok "产物是 zip 容器（xlsx 的物理形态）"
else
  bad "产物是 zip 容器（xlsx 的物理形态）" "$(file -b "$EXCEL_FILE" 2>/dev/null)"
fi

SHEETS="$("$PYTHON" "$OOXML" xlsx-sheets "$EXCEL_FILE" 2>/dev/null | tr '\n' ',')"
eq "工作表为「风险项明细 / 资产风险汇总 / 风险矩阵」三张" \
  "$SHEETS" "风险项明细,资产风险汇总,风险矩阵,"

# ── 数值必须是数值 ──────────────────────────────────────────────────────
#
# 这是 Excel 导出最容易犯、又最难看出来的错误：把数字写成文本，
# 单元格看起来一样，业务方却无法求和/排序 —— 而他们要 Excel 正是因为要算。
# 断言用「不属于文本类型」而不是「等于某个数值类型常量」：OOXML 里数值
# 单元格**根本不写 t 属性**，写 `== number` 会永远为假。
"$PYTHON" "$OOXML" xlsx-cell "$EXCEL_FILE" 风险项明细 G3 H3 I3 J3 K3 B3 > "$EXCEL_ITEMS" 2>/dev/null
celltype() { sed -n "s/^$1\t\([^\t]*\).*/\1/p" "$EXCEL_ITEMS"; }
cellvalue() { sed -n "s/^$1\t[^\t]*\t//p" "$EXCEL_ITEMS"; }

for col in G H I J; do
  oneof "明细表 ${col}3 列（数值）不是文本" "$(celltype "${col}3")" "number" "formula"
done
oneof "明细表 K3 列（等级）是文本" "$(celltype K3)" "shared" "inline"
oneof "明细表 B3 列（资产名称）是文本" "$(celltype B3)" "shared" "inline"

# 阳性对照：同一张表的文本列必须被认成文本。少了这一条，「类型断言」
# 本身坏了（比如类型恒返回同一个值）也看不出来。
if [ "$(celltype K3)" = "shared" ]; then
  ok "阳性对照：等级列的文本类型判定有效（shared）"
else
  bad "阳性对照：等级列的文本类型判定有效（shared）" "实际 $(celltype K3)"
fi

info "明细表首行 A=$(cellvalue G3) T=$(cellvalue H3) V=$(cellvalue I3) R=$(cellvalue J3) 等级=$(cellvalue K3)"

# ── 矩阵表：两块 5×5 ────────────────────────────────────────────────────
MATRIX_SHEET="$("$PYTHON" "$OOXML" xlsx-tsv "$EXCEL_FILE" 风险矩阵 2>/dev/null)"
eq "矩阵表第 3 行是严重程度 1 的整行（行首档位 + 5 格计数 = 6 列）" \
  "$(printf '%s\n' "$MATRIX_SHEET" | sed -n '3p' | awk -F'\t' '{print NF}')" "6"
# 非空行构成：标题 1 + 计数块表头 1 + 计数 5 + 等级块表头 1 + 等级 5 = 13
# （两块之间那个空行不写入任何单元格，因此不出现在逐行输出里）
eq "矩阵表含计数块与等级块共 13 行非空（1+1+5+1+5）" \
  "$(printf '%s\n' "$MATRIX_SHEET" | grep -c .)" "13"

# ============================================================================
section "5. PDF 报告（中文文本层）"
# ============================================================================

dl pdf "$MAIN_ID" "$PDF_FILE"
expect "导出 PDF 成功" 200
eq "Content-Type 为 application/pdf" "$(hdr content-type)" "application/pdf"
contains "Content-Disposition 兜底名是 .pdf" "$(hdr content-disposition)" \
  "security-assessment-report.pdf"

if [ "$(head -c 5 "$PDF_FILE")" = "%PDF-" ]; then
  ok "产物是 PDF（%PDF- 魔数）"
else
  bad "产物是 PDF（%PDF- 魔数）" "$(head -c 16 "$PDF_FILE" | od -c | head -1)"
fi

"$PYTHON" "$PDFTEXT" "$PDF_FILE" > "$PDF_TXT" 2>/dev/null
if [ -s "$PDF_TXT" ]; then
  ok "从 PDF 里抽回了文本层（$(grep -o . "$PDF_TXT" | grep -c . ) 字符）"
else
  bad "从 PDF 里抽回了文本层" "抽出的文本为空 —— PDF 里可能只有图形没有文字"
fi

# ⚠️ 这一条是 P5 验收标志的第一句。只断言「是 PDF、页数够」证明不了它：
#    一个所有汉字都渲染成空心方框的 PDF 同样满足那两个条件。
#    比对用的是不含空格的子串：PDF 文本层对空格的保留左右不定，
#    用整名去比会在「名字里恰好有个空格」时失败，而那与乱码无关。
file_has "PDF 文本层含评估任务名（中文未乱码）" "$PDF_TXT" "报告导出验证"
file_has "PDF 正文含「风险评估报告」标题" "$PDF_TXT" "网络安全风险评估报告"
file_has "PDF 含章节「一、评估概述」" "$PDF_TXT" "一、评估概述"
file_has "PDF 含章节「六、风险项明细」" "$PDF_TXT" "六、风险项明细"
file_has "PDF 含口径说明章节" "$PDF_TXT" "附：口径说明"
file_has "PDF 含 GB/T 20984 计算口径" "$PDF_TXT" "GB/T 20984"
file_has "PDF 页脚含页码（第 … 页 / 共 … 页）" "$PDF_TXT" "共 "
file_has "PDF 页脚含评估名（与 Word 同源的 footerText）" "$PDF_TXT" "报告导出验证"

# ============================================================================
section "6. 五方一致（落库 / 界面 / export-data / Word / Excel）"
# ============================================================================

sql "SELECT asset_name, vuln_title, risk_value_r, risk_level
     FROM risk_items WHERE assessment_id = ${MAIN_ID} ORDER BY id" > "$DB_TSV"
DB_ROWS="$(grep -c . "$DB_TSV")"
eq "隔离库里落着预期条数的风险项（5×5 + 1）" "$DB_ROWS" "26"

req GET "/api/assessments/${MAIN_ID}/risk-items?pageSize=200"
expect "取界面风险项" 200
cp "$BODY" "$UI_JSON"
eq "界面返回全部风险项" "$(jlen data.items)" "26"

req GET "/api/assessments/${MAIN_ID}/export-data"
expect "取 export-data" 200
cp "$BODY" "$EXPORT_JSON"
eq "export-data 返回全部风险项" "$(jlen data.items)" "26"

req GET "/api/assessments/${MAIN_ID}/matrix"
expect "取风险矩阵" 200
cp "$BODY" "$MATRIX_JSON"
eq "矩阵恒为 25 格" "$(jlen data.cells)" "25"
eq "矩阵 total 与风险项条数一致" "$(jget data.total)" "26"

run_checks < <("$PYTHON" "$CHECKS_PY" "${ROOT}/scripts/lib" three-source \
  "$DB_TSV" "$UI_JSON" "$EXPORT_JSON" 2>&1)

run_checks < <("$PYTHON" "$CHECKS_PY" "${ROOT}/scripts/lib" word \
  "$WORD_FILE" "$EXPORT_JSON" 2>&1)

run_checks < <("$PYTHON" "$CHECKS_PY" "${ROOT}/scripts/lib" excel \
  "$EXCEL_FILE" "$EXPORT_JSON" 2>&1)

# 矩阵里那一格「2 条」：证明计数不是恒为 1
CELL_22="$("$PYTHON" -c '
import json, sys
cells = json.load(open(sys.argv[1], encoding="utf-8"))["data"]["cells"]
for c in cells:
    if c["importance"] == 5 and c["severity"] == 5:
        print(c["count"]); break
else:
    print("missing")
' "$MATRIX_JSON" 2>/dev/null)"
eq "矩阵格 (重要性 5, 严重程度 5) 计数为 2（证明计数真是数出来的）" "$CELL_22" "2"

# ============================================================================
section "7. 未计算不可导出"
# ============================================================================

req GET "/api/audit-logs?action=report.export&pageSize=1"
AUDIT_BEFORE="$(jget data.total)"

for fmt in word excel pdf; do
  dl "$fmt" "$DRAFT_ID" "$BODY"
  expect "草稿任务导出 ${fmt} 被拒（409 REPORT_NOT_CALCULATED）" 409 REPORT_NOT_CALCULATED
done

req GET "/api/audit-logs?action=report.export&pageSize=1"
eq "被拒的导出没有留下审计（失败不产生 report.export）" "$(jget data.total)" "$AUDIT_BEFORE"

# ============================================================================
section "8. 参数校验"
# ============================================================================

dl "" "$MAIN_ID" "$BODY"
expect "format 为空被拒" 400 INVALID_PARAM

dl docx "$MAIN_ID" "$BODY"
expect "未知格式 docx 被拒（可选值只有 word/excel/pdf）" 400 INVALID_PARAM

dl word 0 "$BODY"
expect "assessment_id 为 0 被拒" 400 INVALID_PARAM

dl word 99999991 "$BODY"
expect "不存在的评估任务被拒" 404

LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
  -w '%{http_code}' -X POST "$BASE/api/reports/export" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SESSION_CSRF" \
  -d 'not-a-json' 2>/dev/null)
LAST_CODE=$(jget code)
expect "请求体不是合法 JSON 被拒" 400 INVALID_PARAM

# ============================================================================
section "9. 权限与会话"
# ============================================================================

# 未登录：先给一个**匿名会话**取 CSRF 令牌。
#
# 不取令牌直接发请求的话，拦住这次的会是 CSRF 中间件（403 AUTH_CSRF_INVALID）
# 而不是认证中间件，于是断言「未登录被拒」虽然通过（都是 4xx），
# 实际却没有验证到认证这一层 —— 一条「靠另一个原因碰巧通过」的断言。
ANON_JAR="/tmp/sr-report-anon.jar"
rm -f "$ANON_JAR"
ANON_CSRF="$(csrf_token "$ANON_JAR")"
LAST_STATUS=$(curl -sS --noproxy '*' -c "$ANON_JAR" -b "$ANON_JAR" -o "$BODY" \
  -w '%{http_code}' -X POST "$BASE/api/reports/export" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $ANON_CSRF" \
  -d "{\"assessment_id\":${MAIN_ID},\"format\":\"excel\"}" 2>/dev/null)
LAST_CODE=$(jget code)
expect "未登录（无会话）导出被认证层拒绝" 401
rm -f "$ANON_JAR"

LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
  -w '%{http_code}' -X POST "$BASE/api/reports/export" \
  -H 'Content-Type: application/json' \
  -d "{\"assessment_id\":${MAIN_ID},\"format\":\"excel\"}" 2>/dev/null)
LAST_CODE=$(jget code)
expect "缺 CSRF 头的写请求被拒（导出是 POST 的理由之一）" 403

# 审计员：全站只读，但**持有 report:read**。
# 这是刻意的设计——审计岗要能把报告取走归档，没有导出权限的审计员
# 只能靠截图留痕。反过来也说明：这个接口的写语义（留审计）与读权限
# 是两件事，POST 只解决 CSRF 与预取，不是「写权限」。
AUDITOR_USER="audit${AUDITOR_ID}"
AUDITOR_PW="Audit!${AUDITOR_ID}aa"
json POST /api/users \
  "{\"username\":\"${AUDITOR_USER}\",\"display_name\":\"P5 审计员\",\"password\":\"${AUDITOR_PW}\",\"roles\":[\"auditor\"]}"
expect "建审计员账号" 201

rm -f "$AUDITOR_JAR"
login "$AUDITOR_JAR" "$AUDITOR_USER" "$AUDITOR_PW"
expect "审计员可登录" 200

# 新建用户首次登录会被要求改密，改密之前任何业务请求都是
# 403 AUTH_MUST_CHANGE_PASSWORD。少这一步的话，下面的导出会以一个
# 与「权限」毫无关系的理由失败，而断言文案写的是「审计员可以导出」——
# 于是人会去查 RBAC 配置，查半天发现是密码没改。
AUDITOR_PW2="${AUDITOR_PW}X"
json_as "$AUDITOR_JAR" PATCH /api/auth/password \
  "{\"old_password\":\"${AUDITOR_PW}\",\"new_password\":\"${AUDITOR_PW2}\"}" "$SESSION_CSRF"
expect "审计员首次登录后完成改密" 200

login "$AUDITOR_JAR" "$AUDITOR_USER" "$AUDITOR_PW2"
expect "审计员改密后可重新登录" 200

# 注意 login 会把 SESSION_CSRF 换成审计员的令牌 —— 这正是我们想要的：
# 下一个请求就该用他的会话发。
dl excel "$MAIN_ID" "$BODY" "$AUDITOR_JAR" "$SESSION_CSRF"
expect "审计员（只读角色）可以导出报告" 200

login "$ADMIN_JAR" "$E2E_ADMIN" "$NEW_PW"
expect "切回管理员会话" 200

# ============================================================================
section "10. 渲染上游不可用时的降级"
# ============================================================================
#
# ▍这条链路的意义
#
# 三种格式走三条技术路线，因此**依赖也是分开的**：
#   word  → docgen（.NET）
#   pdf   → 本进程渲染 HTML + Gotenberg（Chromium）
#   excel → excelize，纯 Go、进程内，**不依赖任何上游**
#
# 所以「上游挂了就一律导不出来」是错的。这一节逐条验证这个边界：
# 停掉一个上游，受影响的那一种必须 503，**另一种必须仍然可用**。
# 之前有过真实故障：internal 网络静默吞掉端口映射，症状就是这里
# 第一次导出收到 503 —— 而 Excel 本该照常工作。
info "停止 docgen（Word 的上游）"
docker stop secrisk-docgen >/dev/null 2>&1

dl word "$MAIN_ID" "$BODY"
expect "docgen 不可用时，Word 导出返回 503 REPORT_RENDER_FAILED" 503 REPORT_RENDER_FAILED

dl excel "$MAIN_ID" "$EXCEL_FILE.tmp"
expect "同一时刻 Excel 仍可导出（不依赖上游）" 200
rm -f "$EXCEL_FILE.tmp"

dl pdf "$MAIN_ID" "$PDF_FILE.tmp"
expect "同一时刻 PDF 仍可导出（它只依赖 gotenberg）" 200
rm -f "$PDF_FILE.tmp"

info "恢复 docgen"
docker start secrisk-docgen >/dev/null 2>&1
if wait_http "$DOCGEN_URL/health" 60; then
  dl word "$MAIN_ID" "$WORD_FILE.tmp"
  expect "docgen 恢复后 Word 导出立即复原" 200
  rm -f "$WORD_FILE.tmp"
else
  bad "docgen 恢复后 Word 导出立即复原" "docgen 未在 60s 内就绪"
fi

info "停止 gotenberg（PDF 的上游）"
docker stop secrisk-gotenberg >/dev/null 2>&1

dl pdf "$MAIN_ID" "$BODY"
expect "gotenberg 不可用时，PDF 导出返回 503 REPORT_RENDER_FAILED" 503 REPORT_RENDER_FAILED

dl word "$MAIN_ID" "$WORD_FILE.tmp"
expect "同一时刻 Word 仍可导出（它只依赖 docgen）" 200
rm -f "$WORD_FILE.tmp"

info "恢复 gotenberg"
docker start secrisk-gotenberg >/dev/null 2>&1
if wait_http "$GOTENBERG_URL/health" 90; then
  dl pdf "$MAIN_ID" "$PDF_FILE.tmp"
  expect "gotenberg 恢复后 PDF 导出立即复原" 200
  rm -f "$PDF_FILE.tmp"
else
  bad "gotenberg 恢复后 PDF 导出立即复原" "gotenberg 未在 90s 内就绪"
fi

# ============================================================================
section "11. 导出确定性"
# ============================================================================
#
# 同一份数据、同一个接口，连续导两次必须得到同一批数字。
# 这条同时覆盖两个容易静默出错的地方：
#   - 报告里遍历 map 的地方（Go 的 map 顺序随机）—— 表格行序会抖；
#   - 取数路径里混进 time.Now() 之类会变的东西 —— 数值会漂。
# 文件名里的时间戳是**允许**不同的（精确到分钟，且它本来就是「何时导出」）。
dl excel "$MAIN_ID" "$EXCEL_AGAIN"
expect "再次导出 Excel 成功" 200

"$PYTHON" "$OOXML" xlsx-tsv "$EXCEL_FILE" 风险项明细 > /tmp/.sr-report-excel-first.tsv 2>/dev/null
"$PYTHON" "$OOXML" xlsx-tsv "$EXCEL_AGAIN" 风险项明细 > /tmp/.sr-report-excel-again.tsv 2>/dev/null

# 只比数据区（第 3 行起）：第 1 行的标题里含「生成于 <时刻>」，
# 跨分钟的两次导出本就该不同，拿它参与比对会把正确行为判成失败。
tail -n +3 /tmp/.sr-report-excel-first.tsv > /tmp/.sr-report-excel-first-data.tsv
tail -n +3 /tmp/.sr-report-excel-again.tsv > /tmp/.sr-report-excel-again-data.tsv
if diff -q /tmp/.sr-report-excel-first-data.tsv /tmp/.sr-report-excel-again-data.tsv >/dev/null 2>&1; then
  ok "两次导出的数据区逐格相同（行序稳定、无随机量混入）"
else
  bad "两次导出的数据区逐格相同（行序稳定、无随机量混入）" \
      "$(diff /tmp/.sr-report-excel-first-data.tsv /tmp/.sr-report-excel-again-data.tsv | head -4)"
fi

rm -f /tmp/.sr-report-excel-first.tsv /tmp/.sr-report-excel-again.tsv \
      /tmp/.sr-report-excel-first-data.tsv /tmp/.sr-report-excel-again-data.tsv

# ============================================================================
section "12. 审计落库与服务端日志"
# ============================================================================

audit_has() {  # <动作> <描述>
  req GET "/api/audit-logs?action=$1&pageSize=1"
  if [ "$(jget data.total)" != "0" ]; then
    ok "$2"
  else
    bad "$2" "audit-logs?action=$1 的 total=0"
  fi
}

audit_has report.export "导出留下了审计（report.export）"

# 明细要能回答「谁、导了什么格式、文件多大、涉及多少条」——
# 报告一旦被转发出去，审计日志就不在它身边了，这几项是事后追查的唯一线索。
req GET "/api/audit-logs?action=report.export&pageSize=30"
EXPORT_DETAIL="$("$PYTHON" -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    print(""); raise SystemExit
for it in items:
    d = str(it.get("detail", ""))
    if "file_name" in d and "size_bytes" in d:
        print(d); raise SystemExit
print("")
' "$BODY" 2>/dev/null)"
contains "导出审计明细含文件名" "$EXPORT_DETAIL" "file_name"
contains "导出审计明细含文件大小" "$EXPORT_DETAIL" "size_bytes"
contains "导出审计明细含格式" "$EXPORT_DETAIL" "format"
contains "导出审计明细含风险项条数" "$EXPORT_DETAIL" "risk_items_count"

# 审计员自己导出的那一次也要有记录，且操作人是他本人。
# 审计日志若只记管理员的操作，审计岗就无法自证「我什么时候导过哪些数据」——
# 而那正是这个岗位存在的意义。
EXPORT_USERS="$("$PYTHON" -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    print(""); raise SystemExit
print(" ".join(str(it.get("username", "")) for it in items))
' "$BODY" 2>/dev/null)"
contains "审计日志记录了审计员本人的那次导出" "$EXPORT_USERS" "$AUDITOR_USER"

# 服务端日志：不该有「写操作未记录审计」的告警。
# （第 10 节刻意制造的 503 会在日志里留下 ERROR，那是**预期**的，不在此断言内。）
if grep -q "既未由中间件记录" "$SRV_LOG"; then
  bad "服务端日志出现「写操作未记录审计」告警" \
      "$(grep -m1 '既未由中间件记录' "$SRV_LOG")"
else
  ok "服务端日志没有「未记录审计」告警（reqctx 声明生效）"
fi

if grep -q "报告渲染上游不可用" "$SRV_LOG"; then
  ok "上游不可用时日志明确记为「渲染上游不可用」（而不是笼统的 500）"
else
  bad "上游不可用时日志明确记为「渲染上游不可用」" "日志里找不到这条记录"
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
  printf "  ${C_DIM}本轮产物：%s  %s  %s${C_RESET}\n" "$WORD_FILE" "$EXCEL_FILE" "$PDF_FILE"
  exit 1
fi

printf "\n  ${C_DIM}产物已保留，可直接打开人工确认：${C_RESET}\n"
printf "    Word  %s\n" "$WORD_FILE"
printf "    Excel %s\n" "$EXCEL_FILE"
printf "    PDF   %s\n" "$PDF_FILE"
printf "\n  %sP5 报告导出守门验证全部通过 ✅%s\n" "$C_GREEN" "$C_RESET"
