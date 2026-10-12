#!/usr/bin/env bash
# ============================================================================
# P2 资产与字典 守门验证
#
# 验证什么（对应 docs/01-实现计划.md 里 P2 的验收标志「导入 500 行资产成功，
# 错误可定位到具体行号」）：
#
#   1. 批量导入：500 行真的写进去了；错误行号是**源文件行号**（含表头、
#      从 1 开始、且不会被中间的空行带偏）；commit 的原子性；缺列 / 超行 /
#      体积 / 格式 / 空文件各自的错误码；GBK 编码的 CSV；缺失资产组的
#      两种处置（记错误 vs 自动创建）。
#   2. 业务字典：默认返回含停用项、码不可变、内置项不可删、停用后不能
#      被新资产选用。
#   3. 资产分组：物化路径形态、同层重名、成环、层级上限、删除拦截。
#   4. 资产台账：编号全局唯一、三态 PATCH 的「清空」真的生效、
#      按分组筛选默认含子树。
#   5. 授权与审计：只读角色写操作被拒；五类写操作都留下了审计记录；
#      服务端日志里没有 P1 遗留的那条「未记录审计」误报。
#
# ── 环境隔离 ───────────────────────────────────────────────────────────────
# 本脚本**不复用开发库**，而是临时建一个 sec_risk_asset_e2e 库。理由与
# verify-web.sh 相同：本脚本要往台账里塞 500+ 条资产、还要建一堆分组，
# 跑在开发库上会污染本地数据；而且引导管理员的口令只在「账号不存在」
# 时才生效，用开发库就得知道开发库里那个口令 —— 让验证脚本依赖一个
# 开发期口令，既别扭又不可靠（口令一改脚本就静默失效）。
#
# 端口用 18080 而不是 8080：验证脚本不该顺手杀掉用户正在用的 dev server。
#
# 用法： bash scripts/verify-asset.sh
# 退出码：0 = 全部通过；1 = 存在失败项
#
# 前置条件：MySQL 已启动（make infra）。
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT=18080
BASE="http://127.0.0.1:${PORT}"
E2E_DB="sec_risk_asset_e2e"
E2E_ADMIN="admin"
# 临时库的临时口令：随进程生成，不写入任何文件，用完即随库删除
E2E_ADMIN_PW="As2!$(date +%s)$RANDOM"

SRV_LOG="/tmp/sr-asset-verify-srv.log"
BODY="/tmp/.sr-asset-body"
HDR="/tmp/.sr-asset-hdr"
FIX="/tmp/sr-asset-fixtures"
ADMIN_JAR="/tmp/sr-asset-admin.jar"
READONLY_JAR="/tmp/sr-asset-readonly.jar"

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

# ---------------------------------------------------------------- HTTP 工具

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

# jfind <点号路径> <匹配字段> <匹配值> <返回字段> — 在数组里按字段匹配后取子字段
jfind() {
  python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[5], encoding="utf-8"))
except Exception:
    print(""); raise SystemExit
for k in sys.argv[1].split("."):
    if not k:
        continue
    d = d[int(k)] if isinstance(d, list) else d.get(k)
    if d is None:
        print(""); raise SystemExit
if not isinstance(d, list):
    print(""); raise SystemExit
# argv: 2=匹配字段 3=匹配值 4=返回字段 5=数据文件
for item in d:
    if isinstance(item, dict) and str(item.get(sys.argv[2])) == sys.argv[3]:
        print(item.get(sys.argv[4], "")); raise SystemExit
print("")
' "$1" "$2" "$3" "$4" "$BODY" 2>/dev/null
}

# req <method> <path> [curl args...] — 以管理员会话发出只读请求
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

# oneof <描述> <实际> <候选1> [候选2] [候选3] — 用于「数值可能带小数」这类断言
# ⚠️ 变量后紧跟中文标点时必须写成 ${VAR}。bash 在非 C locale 下会把多字节
#    字符的首字节并进变量名，导致 `got_row（: unbound variable` 这类报错 ——
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
  # payload 允许省略：无请求体的写操作（DELETE）与只读请求都不需要它，
  # 而强制传一个 `''` 只会让调用处多一处噪音
  local method="$1" path="$2" payload="${3:-}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
    -w '%{http_code}' -X "$method" "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $SESSION_CSRF" \
    -d "$payload" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# json_as <jar> <method> <path> [json body] [csrf] — 用指定会话发请求（用于越权断言）
json_as() {
  local jar="$1" method="$2" path="$3" payload="${4:-}" token="${5:-$SESSION_CSRF}"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$jar" -b "$jar" -o "$BODY" \
    -w '%{http_code}' -X "$method" "$BASE$path" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $token" \
    -d "$payload" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# upload <path> <file> <create_missing_groups> — multipart 上传（预览 / 提交共用）
#
# ⚠️ 不要手写 Content-Type：multipart 必须带一个随机 boundary，
#    只有 curl 在序列化 -F 时才知道。`-F` 会自动设好。
upload() {
  local path="$1" file="$2" missing="$3"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE$path" \
    -H "X-CSRF-Token: $SESSION_CSRF" \
    -F "file=@${file}" \
    -F "create_missing_groups=${missing}" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# upload_missing_field — 刻意不带 file 字段，验证 ASSET_IMPORT_FILE_MISSING
upload_no_file() {
  local path="$1"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE$path" \
    -H "X-CSRF-Token: $SESSION_CSRF" \
    -F "create_missing_groups=false" 2>/dev/null)
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
  rm -rf "$FIX" "$ADMIN_JAR" "$READONLY_JAR"
  echo "  ${C_DIM}开发库与其它数据未被触碰${C_RESET}"
}
trap cleanup EXIT
# Ctrl-C / kill 也要走 cleanup。下次运行开头会先 DROP 再建，所以残留不至于
# 累积；但让中断当场收干净，比留一个库等着下次来擦更符合「自我清理」的预期。
trap 'exit 130' INT TERM

section "0. 环境准备"

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

mkdir -p "$FIX"
rm -f "$ADMIN_JAR" "$READONLY_JAR"

section "1. 生成测试文件（500 行 / 错误定位 / GBK / 异常文件）"

python3 - "$FIX" <<'PY'
import csv, io, os, sys

out = sys.argv[1]

HEADER = ["资产名称","资产编号","资产类型","IP 地址","端口","主机名","操作系统",
          "资产组","重要性","负责人","归属部门","状态","标签","备注"]

def row(name="", no="", typ="", ip="", port="", host="", os_="", group="",
        imp="", owner="", dept="", status="", tags="", desc=""):
    return [name, no, typ, ip, port, host, os_, group, imp, owner, dept, status, tags, desc]

def write_csv(name, lines, encoding="utf-8"):
    path = os.path.join(out, name)
    with open(path, "w", encoding=encoding, newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        for line in lines:
            w.writerow(line)
    return path

# ── ① 500 行全部合格
#
# 类型列刻意在「码」与「中文名」之间交替：别名解析是导入里最容易静默
# 出错的一处（写错一个名字，500 行会一起报错），值得在同一次导入里覆盖。
bulk = [HEADER]
for i in range(1, 501):
    bulk.append(row(
        name=f"批量资产-{i:03d}",
        no=f"BULK-{i:04d}",
        typ="server" if i % 3 else "服务器",
        ip=f"10.{i // 250}.{(i // 5) % 250}.{i % 250}",
        port=str(8000 + i),
        host=f"bulk-{i:03d}.example.com",
        os_="CentOS 7.9",
        imp=str((i % 5) + 1),
        owner="批量导入",
        dept="运维部",
        status="in_use" if i % 2 else "在用",
        tags="批量,导入",
        desc=f"第 {i} 条批量资产",
    ))
write_csv("bulk500.csv", bulk)

# ── ② 行号定位
#
# 文件形态是刻意构造的：**中间夹了空行**。
# 这一条针对的是 CSV 特有的坑 —— csv.Reader 会跳过空行，若行号用「第几条
# 记录」来数，文件里每多一个空行，后面所有提示就整体偏移，而偏移后的
# 行号看起来完全合理（用户会去改出错行的上一行）。
#
# 行号对照（含表头、从 1 开始）：
#   2  合格  ← 被第 15、16 行引用作重复基准
#   3  空行
#   4  资产名称 为空
#   5  空行
#   6  空行
#   7  资产类型 不存在
#   8  端口 越界
#   9  重要性 越界
#   10 状态 无法识别
#   11 IP 地址 形似 IP 但不合法
#   12 资产编号 含非法字符
#   13 资产组 不存在
#   14 合格（中文类型名 + 中文状态 + 中文逗号标签）
#   15 与第 2 行「名称 + IP」重复（故不给编号，否则先撞编号查重）
#   16 与第 2 行资产编号重复
errors = [
    HEADER,
    row(name="重复基准资产", no="E2E-NO-0001", typ="server", ip="192.0.2.1",
        port="443", status="in_use"),
    [],
    row(name="", no="E2E-NO-0002", typ="server", ip="192.0.2.2"),
    [],
    [],
    row(name="坏类型", no="E2E-NO-0003", typ="不存在的类型", ip="192.0.2.3"),
    row(name="坏端口", no="E2E-NO-0004", typ="server", ip="192.0.2.4", port="99999"),
    row(name="坏重要性", no="E2E-NO-0005", typ="server", ip="192.0.2.5", imp="9"),
    row(name="坏状态", no="E2E-NO-0006", typ="server", ip="192.0.2.6", status="随便"),
    row(name="坏IP", no="E2E-NO-0007", typ="server", ip="999.1.1.1"),
    row(name="坏编号", no="BAD NO!", typ="server", ip="192.0.2.8"),
    row(name="坏资产组", no="E2E-NO-0009", typ="server", ip="192.0.2.9",
        group="无此组xyz"),
    row(name="合格资产二", no="E2E-NO-0010", typ="网络设备", ip="192.0.2.10",
        status="已下线", tags="核心，生产"),
    row(name="重复基准资产", typ="server", ip="192.0.2.1"),
    row(name="编号撞车资产", no="E2E-NO-0001", typ="server", ip="192.0.2.11"),
]
write_csv("errors.csv", errors)

# ── ③ 缺必需列（去掉「资产类型」）
write_csv("missing_cols.csv", [HEADER, ["只有名称", "", "", "", "", "", "", "", "", "", "", "", "", ""]])
# 重写：表头缺「资产类型」
with open(os.path.join(out, "missing_cols.csv"), "w", encoding="utf-8", newline="") as fh:
    w = csv.writer(fh, lineterminator="\n")
    w.writerow([h for h in HEADER if h != "资产类型"])
    w.writerow(["只有名称", "NO-1", "192.0.2.20"])

# ── ④ 只有表头（无数据行）
write_csv("only_header.csv", [HEADER])

# ── ⑤ 超过 5000 行上限（5001 条数据行）
write_csv("toomany.csv",
          [HEADER] + [row(name=f"超限-{i}", typ="server", ip=f"10.200.{i // 250}.{i % 250}")
                      for i in range(5001)])

# ── ⑥ GBK 编码（Excel 简体中文版「另存为 CSV」的默认编码）
write_csv("gbk.csv", [
    HEADER,
    row(name="GBK 编码资产一", no="GBK-0001", typ="服务器", ip="192.0.2.31", status="在用"),
    row(name="GBK 编码资产二", no="GBK-0002", typ="server", ip="192.0.2.32"),
], encoding="gbk")

# ── ⑦ 引用了不存在的资产组（含中间层级）
write_csv("groups.csv", [
    HEADER,
    row(name="导入组资产一", no="GRP-0001", typ="server", ip="192.0.2.41",
        group="导入总部/导入华东/导入机房A"),
    row(name="导入组资产二", no="GRP-0002", typ="server", ip="192.0.2.42",
        group="导入总部/导入华东/导入机房A"),
    row(name="导入组资产三", no="GRP-0003", typ="server", ip="192.0.2.43",
        group="导入华南"),
])

# ── ⑧ 伪装成 xlsx 的垃圾（PK 魔数正确、内容损坏）
with open(os.path.join(out, "broken.xlsx"), "wb") as fh:
    fh.write(b"PK\x03\x04" + b"\x00" * 512)

# ── ⑨ 超过 10 MB 体积上限
with open(os.path.join(out, "huge.csv"), "wb") as fh:
    fh.write(b"a" * (12 << 20))

print("fixtures written to", out)
PY

[ -f "$FIX/bulk500.csv" ] || { bad "测试文件生成失败"; exit 2; }
ok "已生成 9 份测试文件"

section "2. 启动后端（指向临时库）"

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

section "3. 登录并改掉初始密码"

login "$ADMIN_JAR" "$E2E_ADMIN" "$E2E_ADMIN_PW"
expect "引导管理员可登录" 200

# 引导管理员带 must_change_password，改密前访问不了任何业务接口。
NEW_PW="${E2E_ADMIN_PW}New1"
json PATCH /api/auth/password \
  "{\"old_password\":\"$E2E_ADMIN_PW\",\"new_password\":\"$NEW_PW\"}"
expect "首次改密成功" 200

login "$ADMIN_JAR" "$E2E_ADMIN" "$NEW_PW"
expect "改密后可重新登录" 200

req GET /api/assets
expect "会话可用（资产列表返回 200）" 200

section "4. 业务字典"

req GET /api/dictionaries
expect "字典列表（默认含停用项）" 200
DICT_TOTAL=$(jlen data.items)
ne "字典列表非空" "$DICT_TOTAL" "0"

# 内置项：服务器（code=server）
req GET "/api/dictionaries?category=asset_type"
DICT_SERVER_ID=$(jfind data.items code server id)
ne "内置资产类型「服务器」存在" "$DICT_SERVER_ID" ""

# 停用一项内置资产类型，随后它不应再可用于新资产
json PATCH "/api/dictionaries/$DICT_SERVER_ID" '{"enabled":false}'
expect "停用内置资产类型「服务器」" 200

json POST /api/assets '{"name":"用了停用类型的资产","asset_type":"server"}'
expect "停用类型不能用于新建资产" 400 ASSET_TYPE_UNKNOWN

# 停用项仍能被翻译出中文名（这正是「停用」优于「删除」的地方）
json POST /api/assets '{"name":"临时资产-校验停用","asset_type":"network_device"}'
expect "启用中的类型可以新建资产" 201
TEMP_ASSET_ID=$(jget data.id)
json GET "/api/assets/$TEMP_ASSET_ID"
eq "停用类型仍能翻译出中文名" "$(jget data.asset_type_name)" "网络设备"

# 停用项仍出现在维护页的列表里（默认不过滤 enabled）
req GET "/api/dictionaries?category=asset_type"
eq "停用项仍出现在字典维护列表中" \
  "$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(sum(1 for i in d["data"]["items"] if i["code"] == "server" and i["enabled"] is False))
' "$BODY")" "1"

# 恢复服务器类型，后面的导入要用
json PATCH "/api/dictionaries/$DICT_SERVER_ID" '{"enabled":true}'
expect "重新启用内置资产类型" 200

# 内置项不可删除
#
# 状态码是 409 而不是 400：请求本身没毛病，是「当前状态不允许」——
# 与 DICTIONARY_IN_USE / ASSET_GROUP_NAME_TAKEN 等同一类。契约的
# Conflict 一项里列的就是它。
json DELETE "/api/dictionaries/$DICT_SERVER_ID" ''
expect "内置字典项不可删除" 409 DICTIONARY_BUILTIN_READONLY

# 字典码不可变：传一个不同的值
json PATCH "/api/dictionaries/$DICT_SERVER_ID" '{"code":"server_renamed"}'
expect "字典码不可修改" 400 DICTIONARY_CODE_IMMUTABLE

# 非法的类别
json POST /api/dictionaries '{"category":"nope","code":"x","name":"X"}'
expect "字典类别非法" 400 DICTIONARY_CATEGORY_INVALID

# 新建一个自定义类型，供后面的「引用中不可删」使用
json POST /api/dictionaries \
  '{"category":"asset_type","code":"e2e_custom_type","name":"E2E 自定义类型"}'
expect "新建自定义资产类型" 201
CUSTOM_TYPE_ID=$(jget data.id)
oneof "资产类型的权重固定为 1" "$(jget data.weight)" "1" "1.0"

json POST /api/assets '{"name":"用自定义类型的资产","asset_type":"e2e_custom_type"}'
expect "自定义类型可用于新建资产" 201
CUSTOM_ASSET_ID=$(jget data.id)

json DELETE "/api/dictionaries/$CUSTOM_TYPE_ID" ''
expect "被资产引用的类型不可删除" 409 DICTIONARY_IN_USE

# 清理：把这条资产删掉，让后面的计数断言干净
json DELETE "/api/assets/$CUSTOM_ASSET_ID" ''
expect "删除刚才的临时资产" 204
json DELETE "/api/dictionaries/$CUSTOM_TYPE_ID" ''
expect "不再被引用后可以删除" 204

json DELETE "/api/assets/$TEMP_ASSET_ID" ''
expect "删除临时资产（network_device）" 204

section "5. 导入模板下载与结构"

LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
  -o "$FIX/template.xlsx" -D "$FIX/template.hdr" -w '%{http_code}' \
  "$BASE/api/assets/import/template" 2>/dev/null)
expect "下载导入模板" 200

if [ "$LAST_STATUS" = "200" ]; then
  eq "Content-Type 是 xlsx" \
     "$(grep -i '^content-type:' "$FIX/template.hdr" | tr -d '\r' | awk '{print $2}')" \
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

  # 中文文件名必须走 RFC 5987 的 filename*
  contains "Content-Disposition 带 RFC 5987 的 filename*" \
    "$(grep -i '^content-disposition:' "$FIX/template.hdr" | tr -d '\r')" \
    "filename*=UTF-8''"
  contains "Content-Disposition 带 ASCII 兜底名" \
    "$(grep -i '^content-disposition:' "$FIX/template.hdr" | tr -d '\r')" \
    "asset-import-template.xlsx"

  python3 - "$FIX/template.xlsx" <<'PY'
import re, sys, zipfile

path = sys.argv[1]
fails, passes = [], []

def check(ok, name, detail=""):
    (passes if ok else fails).append(name)
    print(f"  {'✔' if ok else '✖'} {name}" + (f"\n      {detail}" if detail and not ok else ""))

z = zipfile.ZipFile(path)
names = set(z.namelist())

# 把「工作表名 → 部件路径」按 OOXML 的关系解析出来，而不是假设
# 资产导入 = sheet1.xml。部件编号是 excelize 的实现细节，
# 用它当判据的校验器会在依赖升级时误报。
wb = z.read("xl/workbook.xml").decode("utf-8")
rels = z.read("xl/_rels/workbook.xml.rels").decode("utf-8")

rel_target = {}
for tag in re.findall(r"<Relationship\b[^>]*>", rels):
    rid = re.search(r'Id="([^"]*)"', tag)
    tgt = re.search(r'Target="([^"]*)"', tag)
    if rid and tgt:
        rel_target[rid.group(1)] = tgt.group(1)

order, part_of = [], {}
for tag in re.findall(r"<sheet\b[^>]*>", wb):
    nm = re.search(r'name="([^"]*)"', tag)
    rid = re.search(r'r:id="([^"]*)"', tag)
    if not nm or not rid:
        continue
    name = nm.group(1)
    target = rel_target.get(rid.group(1), "").lstrip("/")
    part = target if target.startswith("xl/") else "xl/" + target
    order.append(name)
    part_of[name] = part

check(order[:2] == ["资产导入", "填写说明"],
      "工作表顺序为「资产导入」「填写说明」", f"实际：{order}")

shared = []
if "xl/sharedStrings.xml" in names:
    sst = z.read("xl/sharedStrings.xml").decode("utf-8")
    # <si> 里可能有多段 <t>（富文本），拼起来还原成完整字符串
    for si in re.findall(r"<si\b.*?</si>", sst, re.S):
        shared.append("".join(re.findall(r"<t[^>]*>(.*?)</t>", si, re.S)))

def values_of(part):
    """取某张表里**实际写入的字符串值**（按行优先顺序）"""
    xml = z.read(part).decode("utf-8")
    out = []
    for cell in re.findall(r"<c\b[^>]*>.*?</c>|<c\b[^>]*/>", xml, re.S):
        if 't="s"' in cell:
            m = re.search(r"<v>(\d+)</v>", cell)
            if m and int(m.group(1)) < len(shared):
                out.append(shared[int(m.group(1))])
        elif 't="inlineStr"' in cell:
            out.extend(re.findall(r"<t[^>]*>(.*?)</t>", cell, re.S))
    return out

# ⚠️ 判据是「数据表里的**值**」而不是「行数」。
# 单元格样式的批量应用（把整列设成文本格式，多留 64 行）会让 excelize
# 为空白行也写出 <row> 节点 —— 数据表里因此有 65 个空行。按行数断言会把
# 这个正常行为判成「模板带了示例数据」，而真正该问的问题是
# 「有没有多出示例数据」。
expected = ["资产名称","资产编号","资产类型","IP 地址","端口","主机名","操作系统",
            "资产组","重要性","负责人","归属部门","状态","标签","备注"]
data_values = values_of(part_of["资产导入"])
check(data_values == expected,
      "数据表里只有 14 个表头，没有任何示例数据行",
      f"实际值：{data_values[:20]}")

guide_values = values_of(part_of["填写说明"])
check("核心交换机-01" in guide_values,
      "示例值放在「填写说明」表里（数据表里没有）")
check("server" in guide_values and "服务器" in guide_values,
      "说明表列出了可用资产类型（码与名称）")

# 表头与说明必须逐列对齐：说明表第一列就是列名
guide_headers = [v for v in guide_values if v in expected]
check(len(guide_headers) >= len(expected),
      "说明表覆盖了全部 14 列", f"覆盖到 {guide_headers}")

styles = z.read("xl/styles.xml").decode("utf-8")
check('numFmtId="49"' in styles, "存在「文本」数字格式（资产编号 / IP 列强制文本）")

print(f"  模板结构：通过 {len(passes)}/{len(passes) + len(fails)} 项")
if fails:
    sys.exit(1)
PY
  if [ $? -eq 0 ]; then ok "模板内部结构断言全部通过"; else bad "模板内部结构断言失败"; fi
fi

section "6. 导入：500 行成功（P2 验收标志）"

# 先取一个基线：本脚本前面几节也建过资产，写死 500 会让断言与
# 「前面几节建了几条」耦合，将来加一条断言就会连带把这里改坏。
req GET "/api/assets?page=1&pageSize=1"
TOTAL_BEFORE=$(jget data.total)

upload /api/assets/import/preview "$FIX/bulk500.csv" false
expect "预览 500 行文件" 200
eq "识别为 csv 格式"        "$(jget data.format)" "csv"
eq "总数据行数 500"         "$(jget data.total_rows)" "500"
eq "合格 500 行"            "$(jget data.valid_rows)" "500"
eq "错误 0 行"              "$(jget data.error_rows)" "0"
eq "错误明细为空"           "$(jlen data.errors)" "0"
eq "未被截断"               "$(jget data.truncated_errors)" "False"
eq "未引用任何资产组"       "$(jlen data.unmatched_groups)" "0"

upload /api/assets/import/commit "$FIX/bulk500.csv" false
expect "提交导入" 200
eq "写入 500 条资产" "$(jget data.imported)" "500"
eq "未新建资产组"    "$(jget data.created_groups)" "0"

req GET "/api/assets?page=1&pageSize=1"
eq "台账总数增加了 500 条" "$(jget data.total)" "$((TOTAL_BEFORE + 500))"

req GET "/api/assets?keyword=BULK-0500&page=1&pageSize=10"
eq "按资产编号可检索到" "$(jget data.total)" "1"
eq "编号完整保留前导零" "$(jget data.items.0.asset_no)" "BULK-0500"

section "7. 导入：错误可定位到源文件行号"

upload /api/assets/import/preview "$FIX/errors.csv" false
expect "预览含错误文件" 200
eq "总数据行数 12（3 个空行不计入）" "$(jget data.total_rows)" "12"
eq "合格 2 行"                      "$(jget data.valid_rows)" "2"
eq "错误 10 行"                     "$(jget data.error_rows)" "10"
eq "错误明细 10 条"                 "$(jlen data.errors)" "10"
eq "列出了未匹配的资产组"           "$(jlen data.unmatched_groups)" "1"
eq "未匹配组名正确"                 "$(jget data.unmatched_groups.0)" "无此组xyz"

# 逐条核对行号 —— 这正是 P2 的验收要求
check_row() {
  local idx="$1" want_row="$2" want_col="$3" desc="$4"
  local got_row got_col
  got_row=$(jget "data.errors.$idx.row")
  got_col=$(jget "data.errors.$idx.column")
  if [ "$got_row" = "$want_row" ] && [ "$got_col" = "$want_col" ]; then
    ok "$desc → 行 ${got_row}（列 ${got_col}）"
  else
    bad "$desc" "期望 行 ${want_row} / 列 ${want_col}，实际 行 ${got_row} / 列 ${got_col}"
  fi
}

check_row 0 4  "资产名称"   "空行之后行号未偏移，空名称定位到第 4 行"
check_row 1 7  "资产类型"   "不存在的类型定位到第 7 行"
check_row 2 8  "端口"       "越界端口定位到第 8 行"
check_row 3 9  "重要性"     "越界重要性定位到第 9 行"
check_row 4 10 "状态"       "无法识别的状态定位到第 10 行"
check_row 5 11 "IP 地址"    "形似 IP 的非法值定位到第 11 行"
check_row 6 12 "资产编号"   "非法编号定位到第 12 行"
check_row 7 13 "资产组"     "不存在的资产组定位到第 13 行"
check_row 8 15 "资产名称"   "文件内重名定位到第 15 行"
check_row 9 16 "资产编号"   "文件内编号重复定位到第 16 行"

contains "重复提示指出了首次出现的行号" "$(jget data.errors.8.message)" "第 2 行"
contains "重名原因说明了判据" "$(jget data.errors.8.message)" "名称 + IP 地址"

# 原子性：commit 必须一条都不写，并把完整预览挂进 data
#
# 这一份同时命中两种失败：第 13 行「资产组不存在」+ 另外 9 行是别的问题。
# 有别的行级错误时必须是 HAS_ERRORS（优先级高于 GROUP_NOT_FOUND），
# 否则用户只会看到「组不存在」，而真正的数据错误被藏了起来。
req GET "/api/assets?page=1&pageSize=1"
BEFORE_TOTAL=$(jget data.total)

upload /api/assets/import/commit "$FIX/errors.csv" false
expect "含错误的文件提交被拒" 409 ASSET_IMPORT_HAS_ERRORS
eq "409 响应体里带着完整预览（错误明细）" "$(jlen data.errors)" "10"
eq "409 里首条错误的行号仍为 4"           "$(jget data.errors.0.row)" "4"
eq "409 里错误行数正确"                   "$(jget data.error_rows)" "10"

req GET "/api/assets?page=1&pageSize=1"
eq "提交失败后台账一条都没多" "$(jget data.total)" "$BEFORE_TOTAL"

section "8. 导入：文件级失败与编码"

upload /api/assets/import/preview "$FIX/missing_cols.csv" false
expect "缺少必需列被拒" 400 ASSET_IMPORT_MISSING_COLUMNS
contains "错误信息列出了缺失的列名" "$(jget message)" "资产类型"

upload /api/assets/import/preview "$FIX/only_header.csv" false
expect "只有表头（无数据行）被拒" 400 ASSET_IMPORT_NO_ROWS

upload /api/assets/import/preview "$FIX/toomany.csv" false
expect "超过 5000 行上限被拒" 400 ASSET_IMPORT_TOO_MANY_ROWS

upload /api/assets/import/preview "$FIX/broken.xlsx" false
expect "损坏的 xlsx 被拒（按魔数判为 xlsx 后解析失败）" 400 ASSET_IMPORT_FORMAT_INVALID

upload /api/assets/import/preview "$FIX/huge.csv" false
expect "超过 10 MB 的文件被拒" 400 ASSET_IMPORT_FILE_TOO_LARGE

upload_no_file /api/assets/import/preview
expect "未选择文件被拒" 400 ASSET_IMPORT_FILE_MISSING

upload /api/assets/import/preview "$FIX/gbk.csv" false
expect "GBK 编码的 CSV 可解析" 200
eq "GBK 文件识别为 csv"     "$(jget data.format)" "csv"
eq "GBK 文件数据行数 2"     "$(jget data.total_rows)" "2"
eq "GBK 文件无错误行"       "$(jget data.error_rows)" "0"
eq "GBK 中文类型名解析成功" "$(jget data.valid_rows)" "2"

# 中文逗号也当标签分隔符
upload /api/assets/import/commit "$FIX/gbk.csv" false
expect "提交 GBK 文件" 200
eq "GBK 文件写入 2 条" "$(jget data.imported)" "2"

section "9. 导入：缺失资产组的两种处置"

upload /api/assets/import/preview "$FIX/groups.csv" false
expect "未选自动创建时可预览" 200
eq "引用不存在的组记为行错误" "$(jget data.error_rows)" "3"
eq "缺组时合格 0 行"         "$(jget data.valid_rows)" "0"
eq "汇总了 2 个未匹配的组"   "$(jlen data.unmatched_groups)" "2"
# 排序是 sort.Strings，即**按 UTF-8 字节**比。两个名字都以「导入」开头，
# 第三个字才分岔：「华」(E5 8D 8E) 小于「总」(E6 80 BB)，所以「导入华南」
# 排在「导入总部/…」前面 —— 这与「按中文拼音」的直觉不同，别当成 bug 去改。
# 这里真正要守住的是「顺序稳定且两个都在」，而不是某个符合直觉的次序。
eq "未匹配组按字节序排序（第 1 个）" "$(jget data.unmatched_groups.0)" "导入华南"
eq "未匹配组按字节序排序（第 2 个）" "$(jget data.unmatched_groups.1)" "导入总部/导入华东/导入机房A"

# 只缺组、没有别的毛病时，报的是更具体的 GROUP_NOT_FOUND 而不是 HAS_ERRORS
upload /api/assets/import/commit "$FIX/groups.csv" false
expect "未选自动创建时提交被拒" 400 ASSET_IMPORT_GROUP_NOT_FOUND

upload /api/assets/import/preview "$FIX/groups.csv" true
expect "勾选自动创建后可预览" 200
eq "勾选后不再记行错误"       "$(jget data.error_rows)" "0"
eq "勾选后合格 3 行"         "$(jget data.valid_rows)" "3"
eq "汇总了待创建的组"         "$(jlen data.groups_to_create)" "2"
eq "待创建组含中间层级"       "$(jget data.groups_to_create.1)" "导入总部/导入华东/导入机房A"

upload /api/assets/import/commit "$FIX/groups.csv" true
expect "勾选自动创建后提交成功" 200
eq "写入 3 条资产" "$(jget data.imported)" "3"
# 导入总部 / 导入总部/导入华东 / 导入总部/导入华东/导入机房A / 导入华南
eq "新建 4 个资产组（含中间层级）" "$(jget data.created_groups)" "4"

req GET /api/asset-groups
GROUP_COUNT=$(jlen data.items)
eq "资产组树里出现 2 个根组" "$GROUP_COUNT" "2"

section "10. 资产分组：物化路径 / 成环 / 层级 / 删除拦截"

json POST /api/asset-groups '{"name":"总部","description":"E2E 根组"}'
expect "新建根组" 201
ROOT_ID=$(jget data.id)
ROOT_PATH=$(jget data.path)
contains "根组的物化路径以 / 开头结尾" "$ROOT_PATH" "/"

json POST /api/asset-groups '{"name":"总部","description":"重复的根组"}'
expect "同层重名被拒" 409 ASSET_GROUP_NAME_TAKEN

json POST /api/asset-groups "{\"parent_id\":$ROOT_ID,\"name\":\"华东区\"}"
expect "在根组下新建子组" 201
EAST_ID=$(jget data.id)
EAST_PATH=$(jget data.path)
contains "子组路径以父组路径为前缀" "$EAST_PATH" "$ROOT_PATH"
eq "子组 depth 为 1" "$(jget data.depth)" "1"

json POST /api/asset-groups "{\"parent_id\":$EAST_ID,\"name\":\"机房A\"}"
expect "新建第三层" 201
ROOM_ID=$(jget data.id)
eq "第三层 depth 为 2" "$(jget data.depth)" "2"

# 环检测：把「总部」移到自己的后代「机房A」下
json POST "/api/asset-groups/$ROOT_ID/move" "{\"parent_id\":$ROOM_ID}"
expect "把节点移入自己的后代被拒（成环）" 400 ASSET_GROUP_CYCLE

# 移到自身同样成环
json POST "/api/asset-groups/$ROOT_ID/move" "{\"parent_id\":$ROOT_ID}"
expect "把节点移到自己下面被拒" 400 ASSET_GROUP_CYCLE

# 层级上限：一路建到第 9 层
#
# 根为 0 层，上限 7（共 8 层），因此从根往下连续建 7 层都应当成功，
# 第 8 层被拒。名字用固定序号而不是 $RANDOM，避免极小概率的同名干扰断言。
DEEP_PARENT="$ROOT_ID"
DEEP_CODE=""
for i in 1 2 3 4 5 6 7; do
  json POST /api/asset-groups "{\"parent_id\":$DEEP_PARENT,\"name\":\"深层-$i\"}"
  if [ "$LAST_STATUS" != "201" ]; then
    DEEP_CODE="$LAST_CODE"
    break
  fi
  DEEP_PARENT=$(jget data.id)
done
eq "可以一路建到第 8 层" "$DEEP_CODE" ""
json POST /api/asset-groups "{\"parent_id\":$DEEP_PARENT,\"name\":\"第9层\"}"
expect "超过 8 层上限被拒" 400 ASSET_GROUP_DEPTH_EXCEEDED

# 移动：把「机房A」整棵子树先挪到顶层，再挪回来
json POST "/api/asset-groups/$ROOM_ID/move" '{"parent_id":null}'
expect "移动到顶层（parent_id 为 null）" 200
eq "移动后 depth 变为 0" "$(jget data.depth)" "0"
json POST "/api/asset-groups/$ROOM_ID/move" "{\"parent_id\":$EAST_ID}"
expect "移回原父组" 200
eq "移回后 depth 恢复为 2" "$(jget data.depth)" "2"

# 供后面的分组筛选断言使用
json POST /api/asset-groups '{"name":"华南区"}'
expect "新建「华南区」根组" 201
SOUTH_ID=$(jget data.id)

section "11. 资产台账：唯一编号 / 三态 / 分组筛选"

json POST /api/assets \
  "{\"name\":\"机房A-服务器1\",\"asset_no\":\"E2E-A-1\",\"asset_type\":\"server\",\"group_id\":$ROOM_ID,\"importance\":5,\"tags\":[\"核心\",\"生产\"]}"
expect "新建资产（挂在机房A）" 201
A1_ID=$(jget data.id)
eq "重要性回读为 5"     "$(jget data.importance)" "5"
eq "标签回读为数组"     "$(jlen data.tags)" "2"
eq "服务端补齐了组名"   "$(jget data.group_name)" "机房A"
eq "服务端补齐了类型名" "$(jget data.asset_type_name)" "服务器"

json POST /api/assets \
  "{\"name\":\"机房A-服务器2\",\"asset_type\":\"server\",\"group_id\":$ROOM_ID}"
expect "新建第二条资产" 201
A2_ID=$(jget data.id)
eq "未填重要性按中档 3" "$(jget data.importance)" "3"
eq "未填状态按在用"     "$(jget data.status)" "in_use"

json POST /api/assets \
  "{\"name\":\"华东区-网络设备\",\"asset_type\":\"network_device\",\"group_id\":$EAST_ID}"
expect "新建直挂华东区的资产" 201
A3_ID=$(jget data.id)

json POST /api/assets \
  "{\"name\":\"华南区-存储\",\"asset_type\":\"storage\",\"group_id\":$SOUTH_ID}"
expect "新建直挂华南区的资产" 201
A4_ID=$(jget data.id)

# 编号唯一
json POST /api/assets '{"name":"编号撞车","asset_no":"E2E-A-1","asset_type":"server"}'
expect "资产编号全局唯一" 409 ASSET_NO_TAKEN

# 多个「未编号」资产应当共存（NULL 不参与唯一索引）
json POST /api/assets '{"name":"未编号一","asset_type":"server"}'
expect "未编号资产可创建（一）" 201
U1_ID=$(jget data.id)
json POST /api/assets '{"name":"未编号二","asset_type":"server"}'
expect "未编号资产可创建（二）" 201
U2_ID=$(jget data.id)
json DELETE "/api/assets/$U1_ID" ''
json DELETE "/api/assets/$U2_ID" ''

# 参数校验
json POST /api/assets '{"name":"坏状态","asset_type":"server","status":"nope"}'
expect "非法状态被拒" 400 INVALID_PARAM

json GET "/api/assets?page=1&pageSize=5&status=nope"
expect "列表的非法状态筛选被拒" 400 INVALID_PARAM

json GET "/api/assets?page=1&pageSize=5&importance=9"
expect "列表的非法重要性筛选被拒" 400 INVALID_PARAM

json GET "/api/assets?page=1&pageSize=5&group_id=999999"
expect "不存在的分组返回明确错误而不是空列表" 404 ASSET_GROUP_NOT_FOUND

# 三态 PATCH：先看「不传 = 不修改」
json PATCH "/api/assets/$A1_ID" '{"description":"只改备注"}'
expect "只改备注" 200
eq "不传的字段未被清空（编号仍在）" "$(jget data.asset_no)" "E2E-A-1"
eq "不传的字段未被清空（端口仍为空）" "$(jget data.port)" "0"
eq "不传的字段未被清空（分组仍在）" "$(jget data.group_id)" "$ROOM_ID"

# 再给端口与编号，然后显式 null 清空
json PATCH "/api/assets/$A1_ID" '{"port":8443}'
expect "设置端口" 200
eq "端口已写入" "$(jget data.port)" "8443"

json PATCH "/api/assets/$A1_ID" '{"port":null}'
expect "显式 null 清空端口" 200
eq "端口已清空为 0（即未填写）" "$(jget data.port)" "0"

json PATCH "/api/assets/$A1_ID" '{"asset_no":null}'
expect "显式 null 清空资产编号" 200
eq "编号已清空" "$(jget data.asset_no)" ""

json PATCH "/api/assets/$A1_ID" '{"group_id":null}'
expect "显式 null 移出分组" 200
eq "分组已清空" "$(jget data.group_id)" ""

json PATCH "/api/assets/$A1_ID" "{\"asset_no\":\"E2E-A-1\",\"group_id\":$ROOM_ID}"
expect "把编号与分组设回去" 200
eq "编号已恢复" "$(jget data.asset_no)" "E2E-A-1"
eq "分组已恢复" "$(jget data.group_id)" "$ROOM_ID"

# 用着已停用类型的资产可以继续保存（只在类型真的变了时才校验）
json POST /api/dictionaries '{"category":"asset_type","code":"e2e_deprecated","name":"E2E 待停用"}'
DEPR_ID=$(jget data.id)
json POST /api/assets '{"name":"用待停用类型","asset_type":"e2e_deprecated"}'
DEPR_ASSET_ID=$(jget data.id)
json PATCH "/api/dictionaries/$DEPR_ID" '{"enabled":false}'
expect "停用该类型" 200
json PATCH "/api/assets/$DEPR_ASSET_ID" '{"description":"改备注不应被类型校验拦下"}'
expect "已停用类型的资产仍可编辑" 200
json PATCH "/api/assets/$DEPR_ASSET_ID" '{"asset_type":"e2e_custom_type"}'
expect "改成不存在的类型被拒" 400 ASSET_TYPE_UNKNOWN

# 分组筛选：默认含子树
json GET "/api/assets?page=1&pageSize=50&group_id=$EAST_ID"
eq "按华东区筛选默认含子树（3 条）" "$(jget data.total)" "3"

json GET "/api/assets?page=1&pageSize=50&group_id=$EAST_ID&include_children=false"
eq "只看直挂华东区（1 条）" "$(jget data.total)" "1"

json GET "/api/assets?page=1&pageSize=50&group_id=$ROOM_ID&include_children=false"
eq "只看直挂机房A（2 条）" "$(jget data.total)" "2"

# 删除拦截
json DELETE "/api/asset-groups/$EAST_ID" ''
expect "有子组的分组不可删除" 409 ASSET_GROUP_HAS_CHILDREN

json DELETE "/api/asset-groups/$ROOM_ID" ''
expect "仍有资产的分组不可删除" 409 ASSET_GROUP_HAS_ASSETS

# 关键词检索覆盖五个字段
json GET "/api/assets?page=1&pageSize=5&keyword=机房A-服务器1"
eq "按名称可检索" "$(jget data.total)" "1"

json GET "/api/assets?page=1&pageSize=5&keyword=E2E-A-1"
eq "按资产编号可检索" "$(jget data.total)" "1"

# LIKE 通配符必须被转义：% 不应匹配到任何东西
json GET "/api/assets?page=1&pageSize=5&keyword=%25"
eq "关键词里的 % 被转义（不会退化成通配符）" "$(jget data.total)" "0"

# 清理这一节建出来的资产，避免影响后续计数
for id in "$A1_ID" "$A2_ID" "$A3_ID" "$A4_ID" "$DEPR_ASSET_ID"; do
  [ -n "$id" ] && json DELETE "/api/assets/$id" '' >/dev/null 2>&1
done
json DELETE "/api/dictionaries/$DEPR_ID" '' >/dev/null 2>&1

section "12. 授权：只读角色不能写"

json POST /api/users \
  "{\"username\":\"e2e_auditor_$RANDOM\",\"display_name\":\"E2E 审计员\",\"password\":\"Auditor@2026x\",\"roles\":[\"auditor\"]}"
expect "管理员可创建只读账号" 201
AUDITOR_USER=$(jget data.username)

login "$READONLY_JAR" "$AUDITOR_USER" "Auditor@2026x"
expect "只读账号可登录" 200
RO_CSRF="$SESSION_CSRF"

# 审计员改密后即可读
json_as "$READONLY_JAR" PATCH /api/auth/password \
  '{"old_password":"Auditor@2026x","new_password":"Auditor@2026y"}' "$RO_CSRF"
expect "只读账号首次改密" 200

login "$READONLY_JAR" "$AUDITOR_USER" "Auditor@2026y"
expect "只读账号改密后登录" 200
RO_CSRF="$SESSION_CSRF"

json_as "$READONLY_JAR" GET /api/assets '' "$RO_CSRF"
expect "只读角色可以看台账" 200

json_as "$READONLY_JAR" POST /api/assets \
  '{"name":"越权创建","asset_type":"server"}' "$RO_CSRF"
expect "只读角色不能新建资产" 403 FORBIDDEN

json_as "$READONLY_JAR" POST /api/asset-groups '{"name":"越权分组"}' "$RO_CSRF"
expect "只读角色不能新建资产组" 403 FORBIDDEN

json_as "$READONLY_JAR" POST /api/dictionaries \
  '{"category":"asset_type","code":"x","name":"X"}' "$RO_CSRF"
expect "只读角色不能新建字典项" 403 FORBIDDEN

json_as "$READONLY_JAR" GET '/api/assets/import/template' '' "$RO_CSRF"
expect "只读角色不能下载导入模板" 403 FORBIDDEN

section "13. 审计落库与服务端日志"

req GET "/api/audit-logs?action=asset.import&page=1&pageSize=5"
expect "查询导入审计" 200
[ "$(jget data.total)" != "0" ] \
  && ok "导入操作留下了审计记录（asset.import）" \
  || bad "导入操作未留下审计记录" "total=$(jget data.total)"

req GET "/api/audit-logs?action=asset.create&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "资产新建留下了审计记录（asset.create）" \
  || bad "资产新建未留下审计记录" "total=$(jget data.total)"

req GET "/api/audit-logs?action=asset_group.create&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "资产组新建留下了审计记录（asset_group.create）" \
  || bad "资产组新建未留下审计记录" "total=$(jget data.total)"

req GET "/api/audit-logs?action=dictionary.create&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "字典新建留下了审计记录（dictionary.create）" \
  || bad "字典新建未留下审计记录" "total=$(jget data.total)"

# 审计动作枚举必须覆盖 P2 新增的 11 个动作
req GET "/api/audit-logs?action=asset_group.move&page=1&pageSize=5"
expect "asset_group.move 是合法的审计动作" 200
req GET "/api/audit-logs?action=dictionary.delete&page=1&pageSize=5"
expect "dictionary.delete 是合法的审计动作" 200

# 导入审计明细里带文件名与条数。
#
# 分两处断言，不能合并：审计列表按时间倒序，pageSize=1 拿到的是**最新**一条，
# 而本脚本最后一次成功导入是 groups.csv（imported=3）。验收标志关心的是
# 500 行那一次，因此要单独在最近若干条里按文件名把它捞出来。
req GET "/api/audit-logs?action=asset.import&page=1&pageSize=1"
contains "最新一条导入审计含文件名" "$(jget data.items.0.detail)" "groups.csv"
contains "最新一条导入审计含写入条数" "$(jget data.items.0.detail)" "imported"

req GET "/api/audit-logs?action=asset.import&page=1&pageSize=20"
BULK_DETAIL=$(python3 -c '
import json, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8")).get("data", {}).get("items") or []
except Exception:
    print(""); raise SystemExit
for it in items:
    if "bulk500.csv" in str(it.get("detail", "")):
        print(it.get("detail", "")); raise SystemExit
print("")
' "$BODY" 2>/dev/null)
contains "500 行那次的审计明细含文件名" "$BULK_DETAIL" "bulk500.csv"
contains "500 行那次的审计明细含条数"   "$BULK_DETAIL" "500"

# P1 遗留缺陷：service 层已落审计的写请求，中间件不该再打「未记录审计」的告警
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

printf "\n  %sP2 资产与字典守门验证全部通过 ✅%s\n" "$C_GREEN" "$C_RESET"
