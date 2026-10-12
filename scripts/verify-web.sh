#!/usr/bin/env bash
# ============================================================================
# 前端端到端冒烟验证
#
# 与 verify-auth.sh 的分工：
#   verify-auth.sh  打 HTTP 接口，验证后端授权规则（74 项断言）
#   verify-web.sh   开真实浏览器，验证页面真的能用（守卫 / 动态路由 / 渲染）
#
# 为什么必须两条都跑：接口全对、页面白屏，是完全可能的。
# 类型检查与 lint 只能证明代码自洽，证明不了「点下去有反应」。
#
# ── 环境隔离 ───────────────────────────────────────────────────────────────
# 本脚本**不复用开发库**，而是临时建一个 sec_risk_e2e 库：
#
#   1. 引导管理员的口令只在「账号不存在」时才生效，用开发库就得知道
#      开发库里那个管理员的口令 —— 让验证脚本依赖一个开发期口令，
#      既别扭又不可靠（口令一改脚本就静默失效）。
#   2. 冒烟过程会创建/禁用账号，跑在开发库上会污染本地数据。
#
# 所以：建一个干净的库 + 自己定一个临时口令，跑完即删。全程不碰开发库。
#
# 用法： bash scripts/verify-web.sh
# ============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
E2E_DB="sec_risk_e2e"
# API 端口刻意避开 8080：8080 是本机 dev server 的端口，而启动前会 free_port
# 掉端口占用者以避开残留的旧进程，占 8080 就会顺手把开发者正在跑的后端杀掉。
# 18080/18081/18082 分别归 verify-asset / verify-auth / verify-web，互不冲突。
API_PORT=18082
WEB_PORT=4173
E2E_ADMIN="admin"
# 临时库的临时口令：随进程生成，不写入任何文件，用完即随库删除
E2E_ADMIN_PW="E2e!$(date +%s)$RANDOM"

PASS=0; FAIL=0
SRV_PID=""; WEB_PID=""

ok()   { PASS=$((PASS+1)); printf "  %s✅%s %s\n" "$GREEN" "$RESET" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "  %s❌%s %s\n" "$RED" "$RESET" "$1"; }
section() { printf "\n%s── %s ──%s\n" "$CYAN" "$1" "$RESET"; }

# ────────────────────────────────────────────────────────────── 环境准备

# 读取 .env 中的数据库凭据。脚本自己读文件，口令不进命令行历史，
# 也不出现在本文件的源码里。
env_value() {
  sed -n "s/^$1=//p" "$ROOT/.env" 2>/dev/null | head -1 | tr -d '"'\''' | tr -d '\r'
}

MYSQL_ROOT_PW="$(env_value MYSQL_ROOT_PASSWORD)"
MYSQL_USER_VAL="$(env_value MYSQL_USER)"; MYSQL_USER_VAL="${MYSQL_USER_VAL:-secrisk}"
MYSQL_PASS_VAL="$(env_value MYSQL_PASSWORD)"; MYSQL_PASS_VAL="${MYSQL_PASS_VAL:-secrisk_dev_pwd}"

compose() { docker compose "$@"; }

free_port() {
  local port="$1"
  local pids
  pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
    sleep 1
  fi
}

wait_http() {
  local url="$1" label="$2" tries="${3:-60}"
  for _ in $(seq "$tries"); do
    if curl -sS --noproxy '*' -o /dev/null -m 2 "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  bad "$label 未就绪：$url"
  return 1
}

cleanup() {
  section "清理"
  # wait 不只是回收僵尸：少了它 bash 会在退出前给每个被杀的 job 打印一行
  # `PID Killed: 9`，夹在汇总和清理信息之间，看上去像报错。
  if [ -n "$SRV_PID" ]; then kill -9 "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; fi
  if [ -n "$WEB_PID" ]; then kill -9 "$WEB_PID" 2>/dev/null; wait "$WEB_PID" 2>/dev/null; fi
  free_port "$API_PORT"
  free_port "$WEB_PORT"
  if [ -n "$MYSQL_ROOT_PW" ]; then
    compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PW" \
      -e "DROP DATABASE IF EXISTS \`$E2E_DB\`;" >/dev/null 2>&1 \
      && echo "  ${DIM}已删除临时库 $E2E_DB${RESET}"
  fi
  echo "  ${DIM}开发库 sec_risk 与其它数据未被触碰${RESET}"
}
trap cleanup EXIT
# Ctrl-C / kill 也要走 cleanup，否则临时库会留在磁盘上等着下次来擦。
trap 'exit 130' INT TERM

section "0. 环境准备"

if ! docker compose ps --format '{{.Name}}' 2>/dev/null | grep -q secrisk-mysql; then
  echo "  MySQL 容器未运行，请先执行 make infra"
  exit 2
fi
ok "MySQL 容器在运行"

free_port "$API_PORT"
free_port "$WEB_PORT"

# 建临时库并授权给应用账号
if [ -z "$MYSQL_ROOT_PW" ]; then
  bad "未能从 .env 读取 MYSQL_ROOT_PASSWORD，无法创建隔离的临时库"
  exit 2
fi

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

# 前端产物：生产构建才走 CSS 分层与路由分包，与线上形态一致
if [ ! -f web/dist/index.html ]; then
  echo "  ${DIM}未找到构建产物，先构建前端…${RESET}"
  ( cd web && npm run build:only ) >/dev/null 2>&1 || { bad "前端构建失败"; exit 2; }
fi
ok "前端构建产物已就绪（使用 dist，与线上形态一致）"

# ────────────────────────────────────────────────────────────── 起服务

section "1. 启动后端（指向临时库）与前端预览服务"

(
  cd server
  SR_DATABASE_NAME="$E2E_DB" \
  SR_AUTH_BOOTSTRAP_USERNAME="$E2E_ADMIN" \
  SR_AUTH_BOOTSTRAP_PASSWORD="$E2E_ADMIN_PW" \
  SR_SERVER_PORT="$API_PORT" \
  SR_AUTH_LOGIN_RATE_LIMIT=2000 \
  SR_SERVER_CORS_ORIGINS="http://127.0.0.1:${WEB_PORT},http://localhost:${WEB_PORT}" \
  go run ./cmd/api
) > /tmp/sr-e2e-api.log 2>&1 &
SRV_PID=$!

wait_http "http://127.0.0.1:$API_PORT/api/health" "后端" 90 || {
  echo "  ${DIM}后端日志尾部：${RESET}"; tail -20 /tmp/sr-e2e-api.log
  exit 1
}
ok "后端已就绪：http://127.0.0.1:$API_PORT"

# VITE_API_PROXY_TARGET 必须显式传入。vite.config.ts 的 preview 代理有默认值
# `http://127.0.0.1:8080`，而 8080 是本机 dev server 的端口。不覆盖的话，预览页
# 的 /api 会打到**开发后端**上，被它的 CORS 白名单（只认 5173）拒绝，页面表现
# 为「请求来源不被信任」——一个和端口改动看上去毫无关系的症状。
( cd web && VITE_API_PROXY_TARGET="http://127.0.0.1:$API_PORT" npm run preview ) \
  > /tmp/sr-e2e-web.log 2>&1 &
WEB_PID=$!

wait_http "http://127.0.0.1:$WEB_PORT/" "前端预览" 60 || {
  echo "  ${DIM}前端日志尾部：${RESET}"; tail -20 /tmp/sr-e2e-web.log
  exit 1
}
ok "前端预览已就绪：http://127.0.0.1:$WEB_PORT"

# 发一次完整的登录请求做预检。
#
# 注意必须带上 CSRF 令牌：这个接口挂了 CSRF 中间件，不带令牌会一律 403，
# 那样探针就只能证明「CSRF 在拦人」，证明不了「账号能登录」——
# 一个永远返回 403 的探针看着像在工作，实际什么都没测。
WEB_ORIGIN="http://127.0.0.1:${WEB_PORT}"
PROBE_JAR=/tmp/sr-e2e-probe.jar
rm -f "$PROBE_JAR"

CSRF_TOKEN=$(curl -sS --noproxy '*' -c "$PROBE_JAR" -b "$PROBE_JAR" \
  -H "Origin: ${WEB_ORIGIN}" \
  "http://127.0.0.1:${API_PORT}/api/auth/csrf" 2>/dev/null \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["csrf_token"])' 2>/dev/null)

PROBE_CODE=$(curl -sS --noproxy '*' -c "$PROBE_JAR" -b "$PROBE_JAR" \
  -o /tmp/sr-e2e-probe.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:${API_PORT}/api/auth/login" \
  -H 'Content-Type: application/json' \
  -H "Origin: ${WEB_ORIGIN}" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -d "{\"username\":\"${E2E_ADMIN}\",\"password\":\"${E2E_ADMIN_PW}\"}" 2>/dev/null)

if [ "$PROBE_CODE" = "200" ]; then
  ok "预检：临时库引导管理员可登录（账号 ${E2E_ADMIN}）"
else
  bad "预检失败：引导管理员登录返回 HTTP ${PROBE_CODE}，后续浏览器验证无意义"
  echo "  ${DIM}响应：$(head -c 200 /tmp/sr-e2e-probe.json)${RESET}"
  exit 1
fi

# ────────────────────────────────────────────────────────────── 浏览器

section "2. 真实浏览器端到端"
echo "  ${DIM}（Chrome headless + CDP；产物形态与线上一致）${RESET}"

( cd web && node scripts/e2e-smoke.mjs \
    --base "http://127.0.0.1:$WEB_PORT" \
    --username "$E2E_ADMIN" \
    --password "$E2E_ADMIN_PW" )
SMOKE_RC=$?

section "汇总"
if [ "$SMOKE_RC" -eq 0 ]; then
  printf "%s前端端到端冒烟验证全部通过 ✅%s\n" "$GREEN" "$RESET"
  exit 0
else
  printf "%s前端端到端冒烟验证存在失败项 ❌%s\n" "$RED" "$RESET"
  printf "%s后端日志： /tmp/sr-e2e-api.log%s\n" "$DIM" "$RESET"
  exit 1
fi
