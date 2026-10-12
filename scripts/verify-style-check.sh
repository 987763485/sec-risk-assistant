#!/usr/bin/env bash
# ============================================================================
# P0 守门验证 —— 用真实无头浏览器运行「Element Plus × Tailwind」共存断言
#
# 为什么必须用真浏览器：
#   `.w-full` 是否生效、按钮背景是否透明，取决于**真实的 CSS 级联与布局计算**。
#   静态分析 CSS 文本只能证明「规则写对了」，证明不了「浏览器算出来是对的」。
#   而这件事恰恰是 P0 最重要的风险点 —— 判断错了，后续几十个页面全部返工。
#
# 做法：
#   1. 起 Go 主服务与 Vite dev server
#   2. 用无头 Chrome 打开 /dev/style-check
#   3. 从页面里提取机器可读的结果快照（<pre data-testid="style-check-report">）
#   4. 逐项断言，并产出截图供人工复核
#
# 用法：
#   bash scripts/verify-style-check.sh
#   bash scripts/verify-style-check.sh --keep    # 保留服务不退出（调试用）
#
# ── 环境隔离 ───────────────────────────────────────────────────────────────
# 与其它 verify-* 脚本同一条纪律：**不碰开发库**。脚本自建临时库
# sec_risk_style_e2e、把后端指过去，退出时整体 DROP（含 INT/TERM 兜底）。
#
# 端口也避开 8080（本机 dev server 的端口）：脚本自己要起一个后端，撞上去
# 只会得到 bind 失败 —— 而 wait_for 报的是「进程提前退出」，从报错里根本
# 看不出是端口冲突。四个 verify-* 脚本依次用 18080 / 18081 / 18082 / 18083。
# ============================================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
NODE_BIN="/Users/chunle/.workbuddy/binaries/node/versions/22.22.2-6/bin"
PYTHON="/Users/chunle/.workbuddy/binaries/python/versions/3.13.12/bin/python3"

VITE_PORT="${VITE_PORT:-5174}"
# API 端口避开 8080：本机 dev server 占着 8080，而本脚本自己要起一个后端，
# 撞上去只会得到 bind 失败 —— 但 wait_for 看到的是「进程提前退出」，
# 从报错里根本看不出是端口冲突。三个 verify-* 脚本用 18080/18081/18082，
# 这里用 18083。
API_PORT="${API_PORT:-18083}"
# 隔离临时库：与 verify-auth / verify-web / verify-asset 同一条纪律 ——
# 验证脚本不该往开发库里写任何东西。
E2E_DB="${E2E_DB:-sec_risk_style_e2e}"
URL="http://127.0.0.1:${VITE_PORT}/dev/style-check"

OUT_DIR="${ROOT}/.verify"
KEEP="${1:-}"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; RESET=$'\033[0m'

# 读 .env 里的数据库凭据，用于建/删隔离临时库。口令不进命令行历史。
#
# 末尾的 `|| true` 不是摆设：本脚本开了 `set -e` + `pipefail`，而
# env_value 是一串管道，只要 sed 读不到文件就返回非零，管道整体随之失败，
# 赋值语句失败 → 脚本在读取配置这一步直接退出，报错还落在别处。
env_value() {
  sed -n "s/^$1=//p" "$ROOT/.env" 2>/dev/null | head -1 | tr -d '"'\''' | tr -d '\r' || true
}
MYSQL_ROOT_PW="$(env_value MYSQL_ROOT_PASSWORD)"
MYSQL_USER_VAL="$(env_value MYSQL_USER)"; MYSQL_USER_VAL="${MYSQL_USER_VAL:-secrisk}"
compose() { docker compose "$@"; }

mkdir -p "$OUT_DIR"
SERVER_PID=""
VITE_PID=""

log()  { printf '%s\n' "${CYAN}[verify]${RESET} $*"; }
ok()   { printf '%s\n' "${GREEN}✔${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW}!${RESET} $*"; }
err()  { printf '%s\n' "${RED}✖${RESET} $*" >&2; }

cleanup() {
  for pid in "$VITE_PID" "$SERVER_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      # 等它真的退出。不等的话 bash 会在退出前给每个被杀的子进程打印一行
      # `PID Terminated`，夹在断言结果与清理信息之间，看上去像报错。
      wait "$pid" 2>/dev/null || true
    fi
  done
  # Chrome headless 不自动退出，兜底清理，避免残留进程越积越多
  pkill -9 -f "Google Chrome.*--headless" 2>/dev/null || true
  # 临时库整体删除。`|| true` 是必须的：cleanup 跑在 EXIT trap 里，而本脚本
  # 开了 set -e，一条失败的命令会让清理中途断掉，临时库就留在磁盘上了。
  if [[ -n "$MYSQL_ROOT_PW" ]]; then
    compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
      -e "DROP DATABASE IF EXISTS \`$E2E_DB\`;" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- 前置检查
[[ -x "$CHROME" ]] || { err "未找到 Chrome：$CHROME"; exit 1; }

if [[ ! -x server/bin/api ]]; then
  log "未找到后端二进制，先构建…"
  ( cd server && CGO_ENABLED=0 go build -trimpath -o bin/api ./cmd/api )
fi

if [[ ! -d web/node_modules ]]; then
  err "web/node_modules 不存在，请先执行 make web-install"
  exit 1
fi

# ---------------------------------------------------------------- 隔离临时库
if [[ -z "$MYSQL_ROOT_PW" ]]; then
  err "未能从 .env 读取 MYSQL_ROOT_PASSWORD，无法创建隔离临时库"
  exit 1
fi
# 先删后建：上次若被 kill -9 打断（EXIT trap 不执行），这个库会留在磁盘上，
# 先删让脚本对任何残留免疫，也顺手把上次的残骸收掉。
compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" -e \
  "DROP DATABASE IF EXISTS \`$E2E_DB\`;
   CREATE DATABASE \`$E2E_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
   GRANT ALL PRIVILEGES ON \`$E2E_DB\`.* TO '$MYSQL_USER_VAL'@'%';
   FLUSH PRIVILEGES;" >/dev/null 2>&1 || true
if ! compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
     -e "USE \`$E2E_DB\`;" >/dev/null 2>&1; then
  err "创建隔离临时库 $E2E_DB 失败，请确认 make infra 已就绪"
  exit 1
fi
log "已创建隔离临时库 ${E2E_DB}"

# ---------------------------------------------------------------- 启动服务
log "启动后端（:${API_PORT}）…"
# SR_DATABASE_NAME 覆盖 .env 里的开发库 —— 这一行是不碰开发库的唯一保证
( cd server && SR_DATABASE_NAME="$E2E_DB" SR_SERVER_PORT="$API_PORT" \
    exec ./bin/api ) > "$OUT_DIR/server.log" 2>&1 &
SERVER_PID=$!

log "启动 Vite dev server（:${VITE_PORT}）…"
# VITE_API_PROXY_TARGET 必须显式传：vite.config.ts 的 dev 代理默认指向
# http://127.0.0.1:8080，不覆盖的话页面的 /api 会打到**开发后端**上。
( cd web && VITE_API_PROXY_TARGET="http://127.0.0.1:$API_PORT" \
    exec "${NODE_BIN}/node" node_modules/vite/bin/vite.js \
    --host 127.0.0.1 --port "$VITE_PORT" --strictPort ) > "$OUT_DIR/vite.log" 2>&1 &
VITE_PID=$!

wait_for() {
  local url="$1" name="$2" pid="$3" i
  for i in $(seq 1 60); do
    if curl -fsS --noproxy '*' -o /dev/null "$url" 2>/dev/null; then
      ok "$name 已就绪（${i}s）"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      err "$name 进程提前退出，日志："
      tail -30 "$OUT_DIR/server.log" "$OUT_DIR/vite.log" 2>/dev/null || true
      return 1
    fi
    sleep 1
  done
  err "$name 就绪超时"
  return 1
}

wait_for "http://127.0.0.1:${API_PORT}/api/health" "后端" "$SERVER_PID"
wait_for "http://127.0.0.1:${VITE_PORT}/" "前端" "$VITE_PID"

# ---------------------------------------------------------------- 无头浏览器
PROFILE_DIR="$(mktemp -d)"
DOM_FILE="$OUT_DIR/style-check.dom.html"
SHOT_FILE="$OUT_DIR/style-check.png"

# Chrome 的 --headless=new 在 dump-dom / screenshot 之后**不会自动退出**
# （浏览器主进程会一直驻留），因此必须「轮询产物 → 出现即强杀」，
# 不能依赖进程自然结束，也不能依赖 macOS 上不存在的 timeout。
#
# 参数：
#   $1 stdout 落盘路径（dump-dom 时即 DOM 本身）
#   $2 产物就绪判定命令（shell 片段，返回 0 视为就绪）
#   $3 Chrome 的 stderr 日志路径
#   $4... 传给 Chrome 的参数
run_chrome() {
  local stdout_file="$1"
  local ready_check="$2"
  local log_file="$3"
  shift 3

  "$CHROME" "$@" > "$stdout_file" 2> "$log_file" &
  local chrome_pid=$!
  local i

  for i in $(seq 1 90); do
    sleep 1
    if eval "$ready_check" 2>/dev/null; then
      break
    fi
    kill -0 "$chrome_pid" 2>/dev/null || break
  done

  sleep 1
  # wait 要紧跟在 kill 后面：bash 会在「执行下一条命令之前」为被信号杀死的
  # job 打印一行 `PID Killed: 9`，夹在断言输出里看着像出错。放到 pkill 之后就
  # 来不及了 —— pkill 本身就会触发那次 job 状态检查。
  kill -9 "$chrome_pid" 2>/dev/null || true
  wait "$chrome_pid" 2>/dev/null || true
  # headless 会拉起一批子进程，一并清掉，避免残留占用 profile 目录
  pkill -9 -P "$chrome_pid" 2>/dev/null || true
}

CHROME_FLAGS=(
  --headless=new
  --disable-gpu
  --no-sandbox
  --no-first-run
  --no-default-browser-check
  --no-proxy-server
  --disable-dev-shm-usage
  --user-data-dir="$PROFILE_DIR"
  --window-size=1440,1900
  --virtual-time-budget=15000
)

log "用无头 Chrome 加载 $URL …"

# 页面断言是异步执行的，快照偶尔会抓在断言完成之前。
# 用「快照里是否已含有效结果」作为判据重试，而不是盲目等待固定时长。
snapshot_has_results() {
  "$PYTHON" - "$DOM_FILE" <<'PYEOF' >/dev/null 2>&1
import sys, re, html, json, pathlib
dom = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
m = re.search(r'<pre[^>]*data-testid="style-check-report"[^>]*>(.*?)</pre>', dom, re.S)
if not m:
    sys.exit(1)
try:
    data = json.loads(html.unescape(m.group(1)).strip())
except Exception:
    sys.exit(1)
sys.exit(0 if data.get('total', 0) > 0 else 1)
PYEOF
}

for attempt in 1 2 3; do
  run_chrome "$DOM_FILE" "grep -qF '</html>' '$DOM_FILE'" "$OUT_DIR/chrome-dom.log" \
    "${CHROME_FLAGS[@]}" --dump-dom "$URL"

  if snapshot_has_results; then
    break
  fi

  if [[ "$attempt" -lt 3 ]]; then
    warn "第 $attempt 次快照未包含断言结果（可能抓在断言完成前），重试…"
  fi
done

if ! grep -q 'data-testid="style-check-report"' "$DOM_FILE" 2>/dev/null; then
  err "页面 DOM 中未找到结果快照，Chrome 日志尾部："
  tail -20 "$OUT_DIR/chrome-dom.log" 2>/dev/null || true
  exit 1
fi

if ! snapshot_has_results; then
  err "三次快照均未包含有效断言结果，页面可能未执行断言。"
  err "请检查 .verify/style-check.dom.html 与 .verify/vite.log"
  exit 1
fi

ok "已获取页面 DOM 与断言结果（$(wc -c < "$DOM_FILE" | tr -d ' ') 字节）"

log "生成页面截图…"
run_chrome "$OUT_DIR/chrome-shot.log" "[ -s '$SHOT_FILE' ]" "$OUT_DIR/chrome-shot-err.log" \
  "${CHROME_FLAGS[@]}" --screenshot="$SHOT_FILE" "$URL"

if [[ -s "$SHOT_FILE" ]]; then
  ok "截图已生成：$SHOT_FILE"
else
  warn "截图未生成（不影响断言结果）"
fi

# ---------------------------------------------------------------- 断言
log "解析页面结果…"
"$PYTHON" - "$DOM_FILE" "$SHOT_FILE" <<'PYEOF'
import sys, re, html, json, pathlib

dom_path, shot_path = sys.argv[1], sys.argv[2]
dom = pathlib.Path(dom_path).read_text(encoding='utf-8', errors='replace')

m = re.search(r'<pre[^>]*data-testid="style-check-report"[^>]*>(.*?)</pre>', dom, re.S)
if not m:
    print("\033[31m✖\033[0m 页面中未找到结果快照元素 —— 说明组件未能渲染或断言未执行")
    print("  请检查 .verify/style-check.dom.html 与 .verify/vite.log")
    sys.exit(2)

try:
    data = json.loads(html.unescape(m.group(1)).strip())
except json.JSONDecodeError as e:
    print(f"\033[31m✖\033[0m 结果快照不是合法 JSON：{e}")
    sys.exit(2)

DIM, GREEN, RED, RESET = '\033[2m', '\033[32m', '\033[31m', '\033[0m'

print()
for c in data['checks']:
    mark = GREEN + '✔' if c['status'] == 'pass' else RED + '✖'
    print('  ' + mark + RESET + ' ' + c['title'])
    print('      ' + DIM + c['actual'] + RESET)

print()
print(f"  通过 {data['passed']}/{data['total']} 项")

shot = pathlib.Path(shot_path)
if shot.exists():
    print(f"  {DIM}截图：{shot}{RESET}")

if data['allPassed'] and data['total'] > 0:
    print(f"\n{GREEN}样式共存守门验证全部通过 ✅{RESET}")
    sys.exit(0)

print(f"\n{RED}样式共存守门验证未通过 ❌{RESET}")
sys.exit(1)
PYEOF

STATUS=$?

if [[ "$KEEP" == "--keep" ]]; then
  warn "--keep 模式：服务保持运行（后端 PID=${SERVER_PID}，前端 PID=${VITE_PID}），按 Ctrl-C 退出"
  trap - EXIT
  wait
fi

exit "$STATUS"
