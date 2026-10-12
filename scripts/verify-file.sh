#!/usr/bin/env bash
# ============================================================================
# P3 文件上传与解析 守门验证
#
# 验证什么（对应 docs/01-实现计划.md 里 P3 的验收标志「上传 3 类样本报告
# 均能解析出漏洞」）：
#
#   1. 上传三重校验：扩展名 / MIME / 魔数。内容与扩展名不符以内容为准拒绝；
#      合法样本能过；未带 file 字段与超大文件各自的错误码。
#   2. 哈希去重幂等：同一内容上传两次返回同一个 file_id 与 duplicate=true，
#      磁盘上不会留下第二份物理文件。
#   3. 三类样本解析：Nessus / OpenVAS / Excel(CSV) 各解析出预期条数，
#      severity 按「CVSS 优先、等级词兜底」换算成 1–5。
#   4. 两阶段解析的核心语义：预览是只读的（可反复预览、不产生审计、
#      不改 parse_status）；commit 重新解析重新校验；重复 commit 409。
#   5. 原子性与行级报错：Excel 有一行不合格时一条都不写，错误行号是
#      **源文件行号**（含表头、从 1 开始）。
#   6. 资产自动关联：按 host_ip 精确匹配；未匹配的 IP 不阻塞 commit。
#   7. 漏洞清单：筛选（等级 / 来源三态 / 关联情况）、手工录入（等级词映射）、
#      三态 PATCH 的「清空端口」真的生效。
#   8. 手动挂资产：整体替换语义、传空数组清空、**不影响自动关联**。
#   9. 文件删除语义：有漏洞引用时 409 FILE_IN_USE；force 事务级联删；
#      删除后下载 404。
#  10. 授权与审计：只读角色不能上传/解析/删文件；写操作留下审计记录。
#  11. 规模：500 条漏洞的报告能一次解析入库（对应 P2 的 500 行同一量级）。
#
# ── 环境隔离 ───────────────────────────────────────────────────────────────
# 本脚本**不复用开发库**，而是临时建一个 sec_risk_file_e2e 库（理由与
# verify-asset.sh 相同：本脚本要往库里塞 500+ 条漏洞与若干文件记录，
# 跑在开发库上会污染本地数据）。
#
# 端口用 18084：验证脚本不该顺手杀掉用户正在用的 dev server。
#
# 用法： bash scripts/verify-file.sh
# 退出码：0 = 全部通过；1 = 存在失败项
#
# 前置条件：MySQL 已启动（make infra）。
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT=18084
BASE="http://127.0.0.1:${PORT}"
E2E_DB="sec_risk_file_e2e"
E2E_ADMIN="admin"
# 临时库的临时口令：随进程生成，不写入任何文件，用完即随库删除
E2E_ADMIN_PW="Pf3!$(date +%s)$RANDOM"

SRV_LOG="/tmp/sr-file-verify-srv.log"
BODY="/tmp/.sr-file-body"
HDR="/tmp/.sr-file-hdr"
FIX="/tmp/sr-file-fixtures"
ADMIN_JAR="/tmp/sr-file-admin.jar"
READONLY_JAR="/tmp/sr-file-readonly.jar"

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

# oneof <描述> <实际> <候选1> [候选2] [候选3]
#
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

# upload <file> [声明的文件名] — multipart 上传（上传 / 预览 / 提交共用）
#
# ⚠️ 不要手写 Content-Type：multipart 必须带一个随机 boundary，
#    只有 curl 在序列化 -F 时才知道。`-F` 会自动设好。
#
# 第二个参数用于「内容与扩展名不符」的负路径：curl 的 `-F "file=@path;filename=x.xlsx"`
# 允许把 a.csv 的内容以 x.xlsx 的名字提交 —— 这正是攻击者改后缀的动作。
upload() {
  local file="$1" name="${2:-}"
  local spec
  if [ -n "$name" ]; then
    spec="file=@${file};filename=${name}"
  else
    spec="file=@${file}"
  fi
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE/api/files/upload" \
    -H "X-CSRF-Token: $SESSION_CSRF" \
    -F "$spec" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# upload_as <jar> <file> — 用指定会话上传（越权断言）
upload_as() {
  local jar="$1" file="$2"
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$jar" -b "$jar" -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE/api/files/upload" \
    -H "X-CSRF-Token: $RO_CSRF" \
    -F "file=@${file}" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# upload_no_file — 刻意不带 file 字段
upload_no_file() {
  LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
    -w '%{http_code}' -X POST "$BASE/api/files/upload" \
    -H "X-CSRF-Token: $SESSION_CSRF" \
    -F "note=no-file-here" 2>/dev/null)
  LAST_CODE=$(jget code)
}

# parse_req <preview|commit> <file_id>
parse_req() {
  json POST "/api/parser/$1" "{\"file_id\":$2}"
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
  # 上传目录也要清：里面是本脚本上传的样本文件与它们的哈希命名副本
  rm -rf "$FIX" "$ADMIN_JAR" "$READONLY_JAR"
  if [ -n "${E2E_UPLOAD_DIR:-}" ]; then
    rm -rf "$E2E_UPLOAD_DIR"
    echo "  ${C_DIM}已删除临时上传目录 ${E2E_UPLOAD_DIR}${C_RESET}"
  fi
  echo "  ${C_DIM}开发库与其它数据未被触碰${C_RESET}"
}
trap cleanup EXIT
# Ctrl-C / kill 也要走 cleanup
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

# 上传目录也隔离：否则临时库删了，样本文件会一个个留在 storage/uploads 里
E2E_UPLOAD_DIR="/tmp/sr-file-uploads"
rm -rf "$E2E_UPLOAD_DIR"
mkdir -p "$FIX" "$E2E_UPLOAD_DIR"
rm -f "$ADMIN_JAR" "$READONLY_JAR"

section "1. 生成测试样本（三类报告 / 行级错误 / 500 条 / 异常文件）"

python3 - "$FIX" <<'PY'
import csv, os, sys

out = sys.argv[1]

def write(name, text, encoding="utf-8"):
    path = os.path.join(out, name)
    with open(path, "w", encoding=encoding, newline="") as fh:
        fh.write(text)
    return path

# ── ① Nessus：4 条 ReportItem 分布在 2 台主机 ──────────────────────────────
#
# 覆盖点：CDATA 描述、多 CVE（含小写，要被规范化）、port=0 + svc_name=general
# （系统级漏洞，端口应为空）、HostProperties 里的 UUID name（IP 要取 HOST tag）、
# INFO 级（severity=0 → 1）、CVSS 分值与 severity 属性**不一致**的那条
# （以 CVSS 为准：3.7 → 2 级，而不是 severity="2" 恰好也是 2 —— 用 8.1 那条更明显：
# 属性写 severity="3" 而 CVSS 8.1 → 应为 4 级）。
nessus = '''<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Policy><policyName>e2e</policyName></Policy>
  <Report name="20260930-内网扫描">
    <ReportHost name="d0f1a2b3-4c5d-6e7f-8a9b-0c1d2e3f4a5b">
      <HostProperties>
        <tag name="HOST">192.168.1.10</tag>
        <tag name="NAME">web-01</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="2" pluginID="42873" pluginName="SSL Medium Strength Cipher Suites Supported">
        <description>The remote host supports medium strength ciphers.</description>
        <solution>Reconfigure the application.</solution>
        <risk_factor>MEDIUM</risk_factor>
        <cve>CVE-2016-2183</cve>
        <cve>cve-2016-6329</cve>
        <cvss_base_score>3.7</cvss_base_score>
      </ReportItem>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="10662" pluginName="OpenSSH &lt; 9.8 Multiple Vulnerabilities">
        <description><![CDATA[According to its banner, the version of OpenSSH is prior to 9.8.]]></description>
        <solution><![CDATA[Upgrade to OpenSSH 9.8 or later.]]></solution>
        <risk_factor>HIGH</risk_factor>
        <cve>CVE-2024-6387</cve>
        <cvss_base_score>8.1</cvss_base_score>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="4" pluginID="12053" pluginName="Nessus Scan Information">
        <description>Scan metadata.</description>
        <solution>n/a</solution>
        <risk_factor>CRITICAL</risk_factor>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="HOST">10.0.0.5</tag>
      </HostProperties>
      <ReportItem port="0" svc_name="general" protocol="" severity="0" pluginID="19506" pluginName="Nessus Scan Information">
        <description>Information about this scan.</description>
        <risk_factor>INFO</risk_factor>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
'''
write("sample.nessus", nessus)

# ── ② OpenVAS：3 条 result ────────────────────────────────────────────────
#
# 覆盖点：port 形如 "443/tcp"（拆成端口 + 协议）、"general/tcp"（端口应为空）、
# host 带别名 "10.0.0.5 (db-01)"（只取 IP）、severity=-1.0（QOD 不可判 →
# 按信息级处理而不是报错）、severity="9.8"（CVSS ≥9 → 5 级）。
openvas = '''<?xml version="1.0" encoding="UTF-8"?>
<report extension="xml" type="full_report" id="a1b2c3d4-1111-2222-3333-444455556666" format="xml">
  <envelope>
    <name>OpenVAS 扫描 2026-09-30</name>
  </envelope>
  <host count="2">
    <host><ip>192.168.1.10</ip></host>
    <host><ip>10.0.0.5 (db-01)</ip></host>
  </host>
  <results start="1" max="3">
    <result id="100001">
      <host>192.168.1.10</host>
      <hostname>web-01.corp.local</hostname>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.108443">
        <name>TLS Version 1.1 Protocol Detection</name>
        <family>General</family>
        <cvss_base>4.3</cvss_base>
        <cve>CVE-2011-3389</cve>
      </nvt>
      <severity>4.3</severity>
      <name>TLS Version 1.1 Protocol Detection</name>
      <threat>Medium</threat>
      <description>The remote service accepts connections using TLS 1.1.</description>
      <solution>Disable TLS 1.1.</solution>
    </result>
    <result id="100002">
      <host>10.0.0.5 (db-01)</host>
      <hostname>db-01.corp.local</hostname>
      <port>5432/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103980">
        <name>PostgreSQL Weak Password</name>
        <family>Default Accounts</family>
        <cvss_base>9.8</cvss_base>
        <cve>CVE-1999-0502</cve>
      </nvt>
      <severity>9.8</severity>
      <name>PostgreSQL Weak Password</name>
      <threat>High</threat>
      <description>The PostgreSQL service uses a weak password.</description>
      <solution>Change the password.</solution>
    </result>
    <result id="100003">
      <host>10.0.0.5</host>
      <port>general/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.900600">
        <name>Unsupported Operating System</name>
      </nvt>
      <severity>-1.0</severity>
      <name>Unsupported Operating System</name>
      <threat>None</threat>
      <description>The remote OS is no longer supported.</description>
    </result>
  </results>
</report>
'''
write("sample_openvas.xml", openvas)

# ── ③ Excel 类（CSV）：3 条，IP 全部不在台账里 ─────────────────────────────
#
# 刻意让这 3 条的主机 IP（192.168.1.20 / .30）在资产台账中不存在：
# 「未匹配 IP 不阻塞 commit」这条语义要靠它来验证，未关联的漏洞也方便
# 后面验证手动补挂。
VULN_HEADER = ["漏洞名称", "CVE编号", "严重程度", "主机IP", "端口", "协议", "服务",
               "漏洞描述", "修复建议"]

def vrow(name="", cve="", sev="", ip="", port="", proto="", svc="", desc="", sol=""):
    return [name, cve, sev, ip, port, proto, svc, desc, sol]

def write_csv(name, rows, encoding="utf-8"):
    path = os.path.join(out, name)
    with open(path, "w", encoding=encoding, newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(VULN_HEADER)
        for r in rows:
            w.writerow(r)
    return path

write_csv("vulns.csv", [
    vrow("弱口令登录", "CVE-1999-0502", "高", "192.168.1.20", "22", "tcp", "ssh",
         "设备存在默认或弱口令", "更换强口令"),
    vrow("未授权访问接口", "", "中", "192.168.1.20", "8080", "tcp", "http",
         "管理接口未做鉴权", "增加鉴权"),
    vrow("过期证书", "", "低", "192.168.1.30", "443", "tcp", "https",
         "证书 90 天内到期", "更新证书"),
])

# ── ④ 500 条：规模验证（对应 P2 的 500 行资产） ───────────────────────────
write_csv("bulk500.csv",
          [vrow("批量漏洞-{0:03d}".format(i), "CVE-2020-{:04d}".format(1000 + i),
                ["信息", "低", "中", "高", "严重"][i % 5],
                "10.{}.{}.{}".format(10 + (i // 250), (i // 50) % 5, i % 50),
                str(1000 + i), "tcp", "svc{}".format(i % 7),
                "批量样本第 {} 条".format(i), "修复建议 {}".format(i))
           for i in range(1, 501)])

# ── ⑤ 行级错误：第 3 行缺漏洞名称、第 4 行严重程度非法 ────────────────────
#
# 期望报错行号 = 源文件行号（含表头、从 1 开始）：3 与 4。
# 用来验证「行号保真」——用户打开 Excel 直接跳过去就能改。
#
# 刻意只留两行错误：本文件还要验证「error_rows 是真实总数」这条口径，
# 多一条错误行就得跟着调计数，断言会变得难以阅读。
write_csv("badrows.csv", [
    vrow("正常的一条", "", "中", "192.168.1.40", "80", "tcp", "http", "", ""),
    vrow("", "", "中", "192.168.1.40", "80", "tcp", "http", "名称是空的", ""),
    vrow("严重程度非法", "", "很严重", "192.168.1.40", "80", "tcp", "http", "", ""),
])

# ── ⑥ 缺列：表头里没有「漏洞名称」 ───────────────────────────────────────
#
# 九列里只有「漏洞名称」是必需的（其余列留空都按缺省处理），所以要让
# missing_columns 非空，必须缺的就是这一列。缺一个非必需列**不是**错误：
# 那正是「只想填三列」的正常用法。
with open(os.path.join(out, "missing_col.csv"), "w", encoding="utf-8", newline="") as fh:
    w = csv.writer(fh, lineterminator="\n")
    w.writerow(["CVE编号", "严重程度", "主机IP", "端口"])
    w.writerow(["CVE-2021-44228", "严重", "192.168.1.50", "8080"])

# ── ⑦ 只有表头（0 条） ───────────────────────────────────────────────────
write_csv("empty.csv", [])

# ── ⑧ 超限：5001 条 > MaxVulns(5000) ─────────────────────────────────────
write_csv("too_many.csv",
          [vrow("超限 {}".format(i), "", "低", "192.168.1.60", "80", "tcp", "http", "", "")
           for i in range(5001)])

# ── ⑨ 负路径用的异常文件 ─────────────────────────────────────────────────
# 伪扩展名之①：CSV 内容以 .nessus 的名字提交（Nessus 是 XML 大类，
# 首字符必须是 '<'，这里是汉字 —— 魔数校验必须拦下）
write("disguised.nessus", open(os.path.join(out, "vulns.csv"), encoding="utf-8").read())
# 伪扩展名之②：CSV 内容以 .xlsx 的名字提交（xlsx 必须 PK 魔数）
write("disguised.xlsx", open(os.path.join(out, "vulns.csv"), encoding="utf-8").read())
# 扩展名不在白名单
write("notallowed.txt", "漏洞名称,主机IP\n随便写,1.2.3.4\n")
# 二进制垃圾：声明成 .xml，首字符不是 '<'
with open(os.path.join(out, "garbage.xml"), "wb") as fh:
    fh.write(b"\x00\x01\x02MZ\x90\x00garbage-not-xml")
# 超大文件：11 MB > 10 MB 上限
with open(os.path.join(out, "huge.csv"), "w", encoding="utf-8", newline="") as fh:
    fh.write(",".join(VULN_HEADER) + "\n")
    line = "填充" + "x" * 900 + ",,,192.168.1.70,80,tcp,http,,\n"
    fh.write(line * 12000)
print("样本已生成于", out)
PY

ls -1 "$FIX" | sed "s/^/    /"
ok "测试样本生成完毕"

section "2. 启动后端（指向临时库）"

(
  cd server
  SR_DATABASE_NAME="$E2E_DB" \
  SR_AUTH_BOOTSTRAP_USERNAME="$E2E_ADMIN" \
  SR_AUTH_BOOTSTRAP_PASSWORD="$E2E_ADMIN_PW" \
  SR_SERVER_PORT="$PORT" \
  SR_STORAGE_UPLOAD_DIR="$E2E_UPLOAD_DIR" \
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

NEW_PW="${E2E_ADMIN_PW}New1"
json PATCH /api/auth/password \
  "{\"old_password\":\"$E2E_ADMIN_PW\",\"new_password\":\"$NEW_PW\"}"
expect "首次改密成功" 200

login "$ADMIN_JAR" "$E2E_ADMIN" "$NEW_PW"
expect "改密后可重新登录" 200

req GET /api/files
expect "会话可用（文件列表返回 200）" 200

# ---------------------------------------------------------------- 4. 准备工作

section "4. 台账准备与解析模板"

# 解析的自动关联按 host_ip 精确匹配 assets.ip_address，先建两台网内的资产
json POST /api/assets '{"name":"web-01","asset_type":"server","ip_address":"192.168.1.10","importance":5}'
expect "建资产 web-01（192.168.1.10）" 201
ASSET_WEB_ID=$(jget data.id)

json POST /api/assets '{"name":"db-01","asset_type":"server","ip_address":"10.0.0.5","importance":4}'
expect "建资产 db-01（10.0.0.5）" 201
ASSET_DB_ID=$(jget data.id)

# 模板下载：静态 xlsx，验证 PK 魔数与文件名
LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
  -o "$FIX/template.xlsx" -D "$FIX/template.hdr" -w '%{http_code}' \
  "$BASE/api/parser/template" 2>/dev/null)
expect "下载漏洞导入模板" 200
eq "模板 Content-Type 是 xlsx" \
   "$(grep -i '^content-type:' "$FIX/template.hdr" | tr -d '\r' | awk '{print $2}')" \
   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
eq "模板是真正的 xlsx（PK 魔数）" "$(head -c 2 "$FIX/template.xlsx")" "PK"
contains "模板响应头带 attachment" "$(cat "$FIX/template.hdr")" "attachment"

# ---------------------------------------------------------------- 5. 上传校验

section "5. 上传三重校验与哈希去重"

upload "$FIX/sample.nessus"
expect "上传 Nessus 报告" 200
NESSUS_ID=$(jget data.file.id)
eq "新上传不是重复" "$(jget data.duplicate)" "False"
eq "上传即嗅探出格式" "$(jget data.file.format)" "nessus"
eq "初始解析状态是 unparsed" "$(jget data.file.parse_status)" "unparsed"
NESSUS_SHA=$(jget data.file.sha256)
eq "sha256 长度 64" "$(printf '%s' "$NESSUS_SHA" | wc -c | tr -d ' ')" "64"

# 幂等：同内容再传一次
upload "$FIX/sample.nessus"
expect "重复上传同一内容不报错" 200
eq "重复上传返回同一 file_id" "$(jget data.file.id)" "$NESSUS_ID"
eq "重复上传标记 duplicate" "$(jget data.duplicate)" "True"

# 磁盘上只应有一份物理文件：上传目录里除模板外，属于本次会话的文件数 == 1
UPLOADED_FILES=$(find "$E2E_UPLOAD_DIR" -type f | wc -l | tr -d ' ')
eq "去重后磁盘上只有一份物理文件" "$UPLOADED_FILES" "1"

# 落盘名与用户提交的文件名无关：必须是 32 位十六进制、且不带扩展名。
# 这条是「路径穿越不可能」的直接判据——用户可控的字符串根本没进路径。
ON_DISK_NAME=$(find "$E2E_UPLOAD_DIR" -type f -exec basename {} \; | head -n 1)
if [[ "$ON_DISK_NAME" =~ ^[0-9a-f]{32}$ ]]; then
  ok "落盘名为 32 位十六进制、无扩展名（与原始文件名无关）"
else
  bad "落盘名不符合约定：$ON_DISK_NAME"
fi
# 相对路径还要带月分目录：YYYYMM/<32位十六进制>
ON_DISK_REL=$(find "$E2E_UPLOAD_DIR" -type f | sed "s|^$E2E_UPLOAD_DIR/||")
if [[ "$ON_DISK_REL" =~ ^[0-9]{6}/[0-9a-f]{32}$ ]]; then
  ok "落盘相对路径为 YYYYMM/<32位十六进制>"
else
  bad "落盘相对路径不符合约定：$ON_DISK_REL"
fi

# 伪扩展名：内容与扩展名不符，以内容为准拒绝
upload "$FIX/disguised.nessus"
expect "CSV 内容冒充 .nessus 被拒" 400 FILE_TYPE_REJECTED
upload "$FIX/disguised.xlsx"
expect "CSV 内容冒充 .xlsx 被拒" 400 FILE_TYPE_REJECTED

# 扩展名不在白名单
upload "$FIX/notallowed.txt"
expect "不在白名单的扩展名被拒" 400 FILE_TYPE_REJECTED

# 二进制垃圾声明成 xml
upload "$FIX/garbage.xml"
expect "内容不是 XML 却被声明为 xml 时被拒" 400 FILE_TYPE_REJECTED

# 未带 file 字段。错误码与外层一致用 FILE_TYPE_REJECTED：站在用户角度
# 「没选文件」与「选了个不认的文件」是同一类问题（这次请求里没有可接受的
# 文件），前端按同一个码提示即可，不必为前者多写一个分支。
upload_no_file
expect "未带 file 字段" 400 FILE_TYPE_REJECTED

# 超大文件：413（Content-Length 预检先拦下）
upload "$FIX/huge.csv"
expect "超过 10 MB 的报告被拒" 413 FILE_TOO_LARGE

# 负路径不应留下垃圾文件
UPLOADED_FILES=$(find "$E2E_UPLOAD_DIR" -type f | wc -l | tr -d ' ')
eq "被拒的上传没有留下残留文件" "$UPLOADED_FILES" "1"

section "6. 两阶段解析：预览是只读的"

parse_req preview "$NESSUS_ID"
expect "预览 Nessus 报告" 200
eq "预览识别为 nessus" "$(jget data.format)" "nessus"
eq "Nessus 解析出 4 条" "$(jget data.total)" "4"
eq "4 条都能匹配到资产（口径是漏洞条数）" "$(jget data.matched_count)" "4"
eq "没有未匹配的 IP" "$(jlen data.unmatched_ips)" "0"
MATCHED_PREVIEW=$(jget data.matched_count)

# 预览不改状态、不写漏洞：再查一次文件详情与漏洞总数
req GET "/api/files/$NESSUS_ID"
eq "预览不改变 parse_status" "$(jget data.parse_status)" "unparsed"
eq "预览不写漏洞（vuln_count 仍为 0）" "$(jget data.vuln_count)" "0"
req GET "/api/vulnerabilities?page=1&pageSize=5"
eq "预览没有产生任何漏洞记录" "$(jget data.total)" "0"

# 预览是只读的，所以可以反复预览
parse_req preview "$NESSUS_ID"
expect "同一文件可以反复预览" 200
eq "第二次预览结果一致" "$(jget data.total)" "4"

# 预览不产生审计
req GET "/api/audit-logs?action=file.parse&page=1&pageSize=5"
eq "预览不产生 file.parse 审计" "$(jget data.total)" "0"

section "7. 解析入库：Nessus / OpenVAS"

parse_req commit "$NESSUS_ID"
expect "提交解析 Nessus 报告" 200
eq "Nessus 入库 4 条" "$(jget data.imported)" "4"
eq "自动关联 4 条（两台主机都有对应资产）" "$(jget data.linked_auto)" "4"
eq "预览与 commit 的匹配口径一致" "$(jget data.linked_auto)" "$MATCHED_PREVIEW"
eq "未匹配 IP 数为 0" "$(jget data.unmatched_ips)" "0"

req GET "/api/files/$NESSUS_ID"
eq "commit 后状态变为 parsed" "$(jget data.parse_status)" "parsed"
eq "commit 后 vuln_count 落库" "$(jget data.vuln_count)" "4"

# 重复 commit 被拒（并发裁决点）
parse_req commit "$NESSUS_ID"
expect "同一文件不能重复 commit" 409 FILE_ALREADY_PARSED

# severity 换算：CVSS 优先于 severity 属性
#
# severity_raw 存的是**定级依据**：Nessus 条目带 cvss_base_score 时存分值
# （客观数值优先于等级属性），不带时才存等级词。因此这里断言的是 8.1，
# 而不是报告里那个具有欺骗性的 severity="3"。
req GET "/api/vulnerabilities?keyword=OpenSSH&page=1&pageSize=5"
eq "按关键字能检索到 OpenSSH 漏洞" "$(jget data.total)" "1"
OPENSSH_ID=$(jget data.items.0.id)
eq "CVSS 8.1 → 4 级（压过属性里的 severity=3）" "$(jget data.items.0.severity)" "4"
eq "severity_raw 记录定级依据（CVSS 分值）" "$(jget data.items.0.severity_raw)" "8.1"
eq "CVE 已大写去重" "$(jget data.items.0.cve_ids)" "CVE-2024-6387"
eq "来源文件回填" "$(jget data.items.0.source_file_id)" "$NESSUS_ID"

req GET "/api/vulnerabilities?keyword=SSL+Medium&page=1&pageSize=5"
eq "多 CVE 用逗号连成一列" "$(jget data.items.0.cve_ids)" "CVE-2016-2183,CVE-2016-6329"
eq "CVSS 3.7 → 2 级" "$(jget data.items.0.severity)" "2"

req GET "/api/vulnerabilities?keyword=Nessus+Scan+Information&page=1&pageSize=5"
eq "两条 Scan Information 都入库" "$(jget data.total)" "2"

# INFO 级（severity=0 → 1）与 port=0 清空
req GET "/api/vulnerabilities?severity=1&page=1&pageSize=5"
eq "INFO 级映射为 1" "$(jget data.total)" "1"
eq "port=0 的条目端口为空" "$(jget data.items.0.port)" ""

# OpenVAS：预览 → 入库
upload "$FIX/sample_openvas.xml"
expect "上传 OpenVAS 报告" 200
OVAS_ID=$(jget data.file.id)
eq "上传即嗅探为 openvas" "$(jget data.file.format)" "openvas"

parse_req preview "$OVAS_ID"
expect "预览 OpenVAS 报告" 200
eq "OpenVAS 解析出 3 条" "$(jget data.total)" "3"
eq "3 条都匹配到资产（含带别名的主机）" "$(jget data.matched_count)" "3"
eq "没有未匹配的 IP" "$(jlen data.unmatched_ips)" "0"

parse_req commit "$OVAS_ID"
expect "提交解析 OpenVAS 报告" 200
eq "OpenVAS 入库 3 条" "$(jget data.imported)" "3"
eq "OpenVAS 自动关联 3 条" "$(jget data.linked_auto)" "3"

# 端口形态之一：443/tcp
req GET "/api/vulnerabilities?keyword=TLS+Version&page=1&pageSize=5"
eq "443/tcp 拆出端口" "$(jget data.items.0.port)" "443"
eq "443/tcp 拆出协议" "$(jget data.items.0.protocol)" "tcp"
eq "CVSS 4.3 → 3 级" "$(jget data.items.0.severity)" "3"

# 主机带别名时只取 IP —— 别名留进 host_ip 会让自动关联永远匹配不上
req GET "/api/vulnerabilities?keyword=PostgreSQL+Weak&page=1&pageSize=5"
eq "别名主机被拆成纯 IP" "$(jget data.items.0.host_ip)" "10.0.0.5"
eq "5432/tcp 拆出端口" "$(jget data.items.0.port)" "5432"
eq "CVSS 9.8 → 5 级" "$(jget data.items.0.severity)" "5"

# severity=-1.0（QOD 不可判）按信息级处理，不报错
req GET "/api/vulnerabilities?keyword=Unsupported+Operating+System&page=1&pageSize=5"
eq "severity=-1.0 按信息级入库" "$(jget data.items.0.severity)" "1"
eq "general/tcp 的端口为空" "$(jget data.items.0.port)" ""
eq "general/tcp 仍保留协议" "$(jget data.items.0.protocol)" "tcp"

section "8. 三类样本之三：Excel(CSV) 与未匹配 IP 不阻塞"

upload "$FIX/vulns.csv"
expect "上传 CSV 报告" 200
CSV_ID=$(jget data.file.id)
eq "上传即嗅探为 excel" "$(jget data.file.format)" "excel"

parse_req preview "$CSV_ID"
expect "预览 CSV 报告" 200
eq "CSV 解析出 3 条" "$(jget data.total)" "3"
eq "CSV 的 IP 都不在台账，一条也匹配不上" "$(jget data.matched_count)" "0"
eq "汇总出 2 个未匹配 IP（去重）" "$(jlen data.unmatched_ips)" "2"

# 未匹配不阻塞 commit —— 这正是「先传报告、后补资产」的支撑
parse_req commit "$CSV_ID"
expect "未匹配 IP 不阻塞入库" 200
eq "CSV 入库 3 条" "$(jget data.imported)" "3"
eq "CSV 自动关联 0 条" "$(jget data.linked_auto)" "0"
eq "返回未匹配 IP 个数" "$(jget data.unmatched_ips)" "3"

req GET "/api/vulnerabilities?source_file_id=$CSV_ID&page=1&pageSize=10"
eq "按来源文件三态筛选（>0）生效" "$(jget data.total)" "3"
req GET "/api/vulnerabilities?linked=false&page=1&pageSize=10"
eq "「未关联」筛选只剩 CSV 这 3 条" "$(jget data.total)" "3"
req GET "/api/vulnerabilities?linked=true&page=1&pageSize=10"
eq "「已关联」筛选是 Nessus + OpenVAS 的 7 条" "$(jget data.total)" "7"

section "9. 原子性与行级报错行号"

upload "$FIX/badrows.csv"
expect "上传含错误行的 CSV" 200
BAD_ID=$(jget data.file.id)

parse_req preview "$BAD_ID"
expect "预览含错误行的文件（预览本身成功）" 200
eq "错误行数：第 3、4 行不合格" "$(jget data.error_rows)" "2"
eq "错误明细定位到源文件第 3 行" "$(jget data.errors.0.row)" "3"
eq "第 3 行的列名是「漏洞名称」" "$(jget data.errors.0.column)" "漏洞名称"
eq "第 4 行被指出的问题是严重程度" "$(jget data.errors.1.row)" "4"
contains "第 4 行的原因提到严重程度" "$(jget data.errors.1.message)" "严重程度"

# commit 必须整体拒绝，且带完整预览
parse_req commit "$BAD_ID"
expect "有错误行时整批拒绝" 409 VULN_HAS_ERRORS
eq "409 响应体带完整预览（error_rows）" "$(jget data.error_rows)" "2"
eq "409 响应体里带错误明细行号" "$(jget data.errors.0.row)" "3"
req GET "/api/files/$BAD_ID"
eq "被拒后文件仍是 unparsed" "$(jget data.parse_status)" "unparsed"
req GET "/api/vulnerabilities?keyword=正常的一条&page=1&pageSize=5"
eq "原子性：那一行也没写进去" "$(jget data.total)" "0"

# 缺列
upload "$FIX/missing_col.csv"
expect "上传缺列文件" 200
MISS_ID=$(jget data.file.id)
parse_req preview "$MISS_ID"
expect "预览缺列文件" 200
eq "缺的正是必需列「漏洞名称」" "$(jget data.missing_columns.0)" "漏洞名称"
eq "只缺这一列" "$(jlen data.missing_columns)" "1"
parse_req commit "$MISS_ID"
expect "缺必需列时 commit 拒绝" 400 VULN_IMPORT_MISSING_COLUMNS

# 只有表头 → 0 条
upload "$FIX/empty.csv"
expect "上传只有表头的文件" 200
EMPTY_ID=$(jget data.file.id)
parse_req commit "$EMPTY_ID"
expect "空文件 commit 报「没有条目」" 400 VULN_IMPORT_NO_ROWS

# 超过 5000 条上限
upload "$FIX/too_many.csv"
expect "上传 5001 条的文件" 200
MANY_ID=$(jget data.file.id)
parse_req commit "$MANY_ID"
expect "超过条数上限被拒" 400 VULN_IMPORT_TOO_MANY_ROWS

section "10. 规模：500 条一次入库"

upload "$FIX/bulk500.csv"
expect "上传 500 条的报告" 200
BULK_ID=$(jget data.file.id)
parse_req preview "$BULK_ID"
expect "预览 500 条" 200
eq "解析出 500 条" "$(jget data.total)" "500"
parse_req commit "$BULK_ID"
expect "500 条一次入库（P3 验收标志）" 200
eq "写入 500 条" "$(jget data.imported)" "500"
req GET "/api/files/$BULK_ID"
eq "文件的 vuln_count 是 500" "$(jget data.vuln_count)" "500"

section "11. 漏洞清单：手工录入 / 三态编辑 / 关联"

# 手工录入：只给等级词，按词映射
json POST /api/vulnerabilities \
  '{"title":"手工发现的弱口令","cve_ids":["cve-1999-0502","CVE-1999-0502"],"severity_raw":"高危","host_ip":"192.168.1.10","port":3389,"protocol":"tcp","service":"rdp"}'
expect "手工录入漏洞" 201
MANUAL_ID=$(jget data.id)
eq "手工录入的 source_file_id 为空" "$(jget data.source_file_id)" ""
eq "「高危」映射为 4 级" "$(jget data.severity)" "4"
eq "重复 CVE 被去重且大写" "$(jget data.cve_ids)" "CVE-1999-0502"

req GET "/api/vulnerabilities?source_file_id=0&page=1&pageSize=10"
eq "手工录入用 source_file_id=0 筛出" "$(jget data.total)" "1"

json POST /api/vulnerabilities '{"title":"手工录入无严重程度"}'
expect "severity 与 severity_raw 都不给时用默认 3 级" 201
eq "默认严重程度是 3" "$(jget data.severity)" "3"
DEFAULT_SEV_ID=$(jget data.id)

json POST /api/vulnerabilities '{"title":"","severity":5}'
expect "漏洞名称为空被拒" 400 INVALID_PARAM

json POST /api/vulnerabilities '{"title":"非法等级","severity":9}'
expect "严重程度超出 1–5 被拒" 400 INVALID_PARAM

# 三态 PATCH：不传 = 不修改；null = 清空；给值 = 设值
json PATCH "/api/vulnerabilities/$MANUAL_ID" '{"solution":"改掉口令"}'
expect "只改一个字段时其它字段不动" 200
eq "port 未被误清空（不传 = 不修改）" "$(jget data.port)" "3389"
eq "description 仍为空" "$(jget data.description)" ""

json PATCH "/api/vulnerabilities/$MANUAL_ID" '{"port":null}'
expect "显式传 null 清空端口" 200
eq "端口已清空" "$(jget data.port)" ""

json PATCH "/api/vulnerabilities/$MANUAL_ID" '{"port":8080}'
expect "重新给端口" 200
eq "端口已设为 8080" "$(jget data.port)" "8080"

json PATCH "/api/vulnerabilities/$MANUAL_ID" '{"port":0}'
expect "传 0 等同于清空（0 不是合法端口）" 200
eq "端口被清空" "$(jget data.port)" ""

json PATCH "/api/vulnerabilities/$MANUAL_ID" '{"severity":5}'
expect "改等级" 200
eq "等级已改为 5" "$(jget data.severity)" "5"

# 详情含关联资产（自动关联来自解析）
req GET "/api/vulnerabilities/$OPENSSH_ID"
expect "查看漏洞详情" 200
eq "详情带 auto 关联资产" "$(jget data.assets.0.matched_by)" "auto"
eq "关联的正是 IP 命中的那台资产" "$(jget data.assets.0.asset_id)" "$ASSET_WEB_ID"

# 手动关联是整体替换；且不影响 auto
json POST "/api/vulnerabilities/$OPENSSH_ID/assets" "{\"asset_ids\":[$ASSET_DB_ID]}"
expect "手动挂一台资产（整体替换）" 200
MANUAL_LINKED=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
items = d.get("data", {}).get("assets") or []
print(",".join("{}:{}".format(i["asset_id"], i["matched_by"]) for i in items))
' "$BODY" 2>/dev/null)
contains "auto 关联未被手动操作覆盖" "$MANUAL_LINKED" "$ASSET_WEB_ID:auto"
contains "手动关联以 manual 记入" "$MANUAL_LINKED" "$ASSET_DB_ID:manual"
eq "关联总数变成 2" "$(jlen data.assets)" "2"

json GET "/api/vulnerabilities/$OPENSSH_ID"
eq "linked_count 反映两种关联之和" "$(jget data.vulnerability.linked_count)" "2"

json POST "/api/vulnerabilities/$OPENSSH_ID/assets" '{"asset_ids":[]}'
expect "传空数组清空手动关联" 200
eq "只剩 auto 一条" "$(jlen data.assets)" "1"
eq "剩下的是 auto" "$(jget data.assets.0.matched_by)" "auto"

json POST "/api/vulnerabilities/$OPENSSH_ID/assets" '{"asset_ids":[999999]}'
expect "挂不存在的资产被拒" 404 ASSET_NOT_FOUND

LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" -o "$BODY" \
  -w '%{http_code}' -X POST "$BASE/api/vulnerabilities/$OPENSSH_ID/assets" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SESSION_CSRF" \
  -d '{"asset_ids":["abc"]}' 2>/dev/null)
LAST_CODE=$(jget code)
expect "asset_ids 里出现非数字被拒" 400 INVALID_PARAM

# 给一条未关联的 CSV 漏洞补挂资产
req GET "/api/vulnerabilities?source_file_id=$CSV_ID&linked=false&page=1&pageSize=5"
CSV_VULN_ID=$(jget data.items.0.id)
json POST "/api/vulnerabilities/$CSV_VULN_ID/assets" "{\"asset_ids\":[$ASSET_WEB_ID]}"
expect "给未关联的漏洞补挂资产" 200
req GET "/api/vulnerabilities?source_file_id=$CSV_ID&linked=false&page=1&pageSize=5"
eq "补挂后未关联的少了一条" "$(jget data.total)" "2"

# 删除漏洞
json DELETE "/api/vulnerabilities/$DEFAULT_SEV_ID" ''
expect "删除手工录入的漏洞" 200
req GET "/api/vulnerabilities/$DEFAULT_SEV_ID"
expect "删除后取详情 404" 404 VULN_NOT_FOUND

section "12. 文件删除语义：RESTRICT 与 force 级联"

json DELETE "/api/files/$NESSUS_ID" ''
expect "文件仍有漏洞引用时删除被拒" 409 FILE_IN_USE

# 下载原件：内容应与上传的样本逐字节一致
LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
  -o "$FIX/downloaded.nessus" -D "$HDR" -w '%{http_code}' \
  "$BASE/api/files/$NESSUS_ID/download" 2>/dev/null)
expect "下载已解析文件" 200
if cmp -s "$FIX/sample.nessus" "$FIX/downloaded.nessus"; then
  ok "下载内容与原文件逐字节一致"
else
  bad "下载内容与原文件不一致"
fi
contains "下载响应头带 attachment" "$(cat "$HDR")" "attachment"
contains "下载响应头带 nosniff" "$(cat "$HDR")" "nosniff"

req GET "/api/files/$NESSUS_ID"
NESSUS_VULNS=$(jget data.vuln_count)

json DELETE "/api/files/$NESSUS_ID?force=true" ''
expect "force 删除带漏洞的文件" 200
req GET "/api/files/$NESSUS_ID"
expect "文件已删除" 404 FILE_NOT_FOUND
req GET "/api/vulnerabilities?source_file_id=$NESSUS_ID&page=1&pageSize=5"
eq "级联删掉了全部 $NESSUS_VULNS 条漏洞" "$(jget data.total)" "0"
LAST_STATUS=$(curl -sS --noproxy '*' -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
  -o "$BODY" -w '%{http_code}' "$BASE/api/files/$NESSUS_ID/download" 2>/dev/null)
LAST_CODE=$(jget code)
expect "删除后下载 404" 404 FILE_NOT_FOUND

# 清单还能正常查询（级联没把别的漏洞带走）
#
# 此时的构成：500 条批量 + 3 条 OpenVAS + 3 条 CSV + 1 条手工录入 = 507。
# 这个数字本身就是一条断言 —— 级联删除只该带走 Nessus 那 4 条。
req GET "/api/vulnerabilities?page=1&pageSize=10"
eq "其余漏洞仍在（500 批量 + 3 OpenVAS + 3 CSV + 1 手工）" "$(jget data.total)" "507"

section "13. 授权：只读角色不能写"

json POST /api/users \
  "{\"username\":\"e2e_auditor_$RANDOM\",\"display_name\":\"E2E 审计员\",\"password\":\"Auditor@2026x\",\"roles\":[\"auditor\"]}"
expect "管理员可创建只读账号" 201
AUDITOR_USER=$(jget data.username)

login "$READONLY_JAR" "$AUDITOR_USER" "Auditor@2026x"
expect "只读账号可登录" 200
RO_CSRF="$SESSION_CSRF"

json_as "$READONLY_JAR" PATCH /api/auth/password \
  '{"old_password":"Auditor@2026x","new_password":"Auditor@2026y"}' "$RO_CSRF"
expect "只读账号首次改密" 200

login "$READONLY_JAR" "$AUDITOR_USER" "Auditor@2026y"
expect "只读账号改密后登录" 200
RO_CSRF="$SESSION_CSRF"

json_as "$READONLY_JAR" GET /api/files '' "$RO_CSRF"
expect "只读角色可以看文件列表" 200

json_as "$READONLY_JAR" GET /api/vulnerabilities '' "$RO_CSRF"
expect "只读角色可以看漏洞清单" 200

json_as "$READONLY_JAR" GET "/api/files/$CSV_ID/download" '' "$RO_CSRF" >/dev/null 2>&1
LAST_STATUS=$(curl -sS --noproxy '*' -c "$READONLY_JAR" -b "$READONLY_JAR" \
  -o /dev/null -w '%{http_code}' "$BASE/api/files/$CSV_ID/download" 2>/dev/null)
expect "只读角色可以下载文件" 200

upload_as "$READONLY_JAR" "$FIX/sample.nessus"
expect "只读角色不能上传报告" 403 FORBIDDEN

json_as "$READONLY_JAR" POST /api/parser/preview "{\"file_id\":$CSV_ID}" "$RO_CSRF"
expect "只读角色不能解析" 403 FORBIDDEN

json_as "$READONLY_JAR" DELETE "/api/files/$CSV_ID" '' "$RO_CSRF"
expect "只读角色不能删文件" 403 FORBIDDEN

json_as "$READONLY_JAR" POST /api/vulnerabilities '{"title":"越权创建","severity":5}' "$RO_CSRF"
expect "只读角色不能手工录入漏洞" 403 FORBIDDEN

json_as "$READONLY_JAR" POST "/api/vulnerabilities/$CSV_VULN_ID/assets" '{"asset_ids":[]}' "$RO_CSRF"
expect "只读角色不能改关联" 403 FORBIDDEN

section "14. 审计落库与服务端日志"

req GET "/api/audit-logs?action=file.upload&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "上传留下了审计（file.upload）" \
  || bad "上传未留下审计" "total=$(jget data.total)"

req GET "/api/audit-logs?action=file.upload_duplicate&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "重复上传单独记账（file.upload_duplicate）" \
  || bad "重复上传未单独记账" "total=$(jget data.total)"

req GET "/api/audit-logs?action=file.parse&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "解析留下了审计（file.parse）" \
  || bad "解析未留下审计" "total=$(jget data.total)"

req GET "/api/audit-logs?action=file.delete&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "删除文件留下了审计（file.delete）" \
  || bad "删除文件未留下审计" "total=$(jget data.total)"

req GET "/api/audit-logs?action=vuln.create&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "手工录入留下了审计（vuln.create）" \
  || bad "手工录入未留下审计" "total=$(jget data.total)"

req GET "/api/audit-logs?action=vuln.link&page=1&pageSize=5"
[ "$(jget data.total)" != "0" ] \
  && ok "手动挂资产留下了审计（vuln.link）" \
  || bad "手动挂资产未留下审计" "total=$(jget data.total)"

# 解析审计的明细里带文件名与条数（回答「这份报告谁解析的、进来多少条」）
req GET "/api/audit-logs?action=file.parse&page=1&pageSize=20"
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
contains "解析审计明细含文件名" "$BULK_DETAIL" "bulk500.csv"
contains "解析审计明细含条数" "$BULK_DETAIL" "500"

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

printf "\n  %sP3 文件上传与解析守门验证全部通过 ✅%s\n" "$C_GREEN" "$C_RESET"
