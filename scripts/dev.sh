#!/usr/bin/env bash
# ============================================================================
# 本地热重载开发脚本
#
# 做三件事：
#   1. 用 docker 起依赖服务（mysql / docgen / gotenberg）
#   2. 本地跑 Go 主服务（热重载靠手动重启，Go 编译快，无需额外工具）
#   3. 本地跑 Vite dev server（HMR），并把 /api 代理到 Go 服务
#
# 退出时（Ctrl-C）自动清理后台的 Go 进程，不留僵尸。
# ============================================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NODE_BIN="/Users/chunle/.workbuddy/binaries/node/versions/22.22.2-6/bin"
NPM="${NODE_BIN}/npm"
GO="${GO:-go}"

# 本地开发必须叠加这一份：主 compose 里 docgen / gotenberg 只挂在
# internal 网络上（宿主机完全不可达，这是生产的正确姿势），
# 而这里是在宿主机上跑 Go 服务，必须能把端口映射出来。
#
# ⚠️ 叠加文件刻意不叫 docker-compose.override.yml —— 那个名字会被 compose
#    自动加载，等于把「暴露内部服务端口」带到生产部署里去。
COMPOSE_DEV=(docker compose -f docker-compose.yml -f deploy/compose.dev.yml)

SERVER_PID=""

log()  { printf '\033[36m[dev]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[dev]\033[0m %s\n' "$*"; }
err()  { printf '\033[31m[dev]\033[0m %s\n' "$*" >&2; }

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    log "停止后端进程 (pid=${SERVER_PID})"
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- 前置检查
if [[ ! -f .env ]]; then
  warn ".env 不存在，从 .env.example 生成"
  cp .env.example .env
fi

if ! docker info >/dev/null 2>&1; then
  err "Docker 守护进程未运行，请先启动 Docker Desktop"
  exit 1
fi

# ---------------------------------------------------------------- 1. 依赖服务
log "启动依赖服务（mysql / docgen / gotenberg，渲染服务端口映射到回环）…"
"${COMPOSE_DEV[@]}" up -d --build mysql docgen gotenberg

log "等待 MySQL 就绪…"
for i in $(seq 1 60); do
  if docker compose exec -T mysql mysqladmin ping -h 127.0.0.1 -u root \
       -p"${MYSQL_ROOT_PASSWORD:-root_dev_pwd}" --silent >/dev/null 2>&1; then
    log "MySQL 已就绪 ✅"
    break
  fi
  [[ $i -eq 60 ]] && { err "MySQL 等待超时"; exit 1; }
  sleep 2
done

# 渲染服务必须从**宿主机**可达——local Go 进程连的是 127.0.0.1:8090/3000。
#
# 这一检查是刻意加的，不是多余：主 compose 里两个服务挂的是
# `internal: true` 网络，而 Docker 会**静默丢弃** internal 网络上的端口映射
# （不报错、`docker ps` 的 PORTS 列也只是空白）。少了这一道，
# 「配置看起来完全正确、容器也健康、make dev 也不报错，但导出 Word/PDF 是 503」
# 会一直拖到有人点导出才暴露，而那时排查方向会指向 docgen / gotenberg 本身。
# 见 deploy/compose.dev.yml 的说明。
log "等待渲染服务就绪（宿主机 127.0.0.1）…"
DOCGEN_URL="http://127.0.0.1:${DOCGEN_PORT:-8090}"
GOTENBERG_URL="http://127.0.0.1:${GOTENBERG_PORT:-3000}"
for i in $(seq 1 60); do
  if curl -fsS "${DOCGEN_URL}/health" >/dev/null 2>&1 \
     && curl -fsS "${GOTENBERG_URL}/health" >/dev/null 2>&1; then
    log "docgen / gotenberg 已就绪 ✅"
    break
  fi
  if [[ $i -eq 60 ]]; then
    err "渲染服务在宿主机上不可达（docgen=${DOCGEN_URL} gotenberg=${GOTENBERG_URL}）"
    err "请检查端口映射是否真的建立："
    docker port secrisk-docgen 2>/dev/null || err "  secrisk-docgen 没有端口映射"
    docker port secrisk-gotenberg 2>/dev/null || err "  secrisk-gotenberg 没有端口映射"
    err "若两行都是空，说明覆盖文件没生效——确认启动命令带上了 deploy/compose.dev.yml"
    exit 1
  fi
  sleep 2
done

# 本地运行 Go 时，把容器内的服务地址映射回宿主机
export SR_APP_ENV="${SR_APP_ENV:-dev}"
export SR_DATABASE_HOST="${SR_DATABASE_HOST:-127.0.0.1}"
export SR_DATABASE_PORT="${SR_DATABASE_PORT:-13306}"
export SR_DATABASE_USER="${SR_DATABASE_USER:-${MYSQL_USER:-secrisk}}"
export SR_DATABASE_PASSWORD="${SR_DATABASE_PASSWORD:-${MYSQL_PASSWORD:-secrisk_dev_pwd}}"
export SR_DATABASE_NAME="${SR_DATABASE_NAME:-${MYSQL_DATABASE:-sec_risk}}"
export SR_SERVER_HOST="${SR_SERVER_HOST:-127.0.0.1}"
export SR_SERVER_PORT="${SR_SERVER_PORT:-8080}"
# 服务间共享密钥必须与 docgen 容器里的 DOCGEN_INTERNAL_SECRET 一致，
# 否则 docgen 会以 401 拒绝，而表现是「导出 docx 一律 503」。
#
# 取值顺序：已有环境变量（`make dev` 会先把 .env 导出）→ .env 文件本身
# → 内置默认值。单独读一次 .env 是为了「直接 bash scripts/dev.sh」这条路径：
# `docker compose` 会自己读 .env 去填 DOCGEN_INTERNAL_SECRET，而宿主机上的
# Go 进程不会——两边取值不同就会 401，且报错信息完全不指向密钥。
if [[ -z "${SR_INTERNAL_SHARED_SECRET:-}" && -f .env ]]; then
  SR_INTERNAL_SHARED_SECRET="$(grep -E '^SR_INTERNAL_SHARED_SECRET=' .env | tail -1 | cut -d= -f2-)"
fi
export SR_INTERNAL_SHARED_SECRET="${SR_INTERNAL_SHARED_SECRET:-dev-only-shared-secret-please-change-me}"
# 两个渲染上游的地址显式导出：默认值本来与 .env 一致，但把它们挂到
# DOCGEN_PORT / GOTENBERG_PORT 上之后，改端口就不需要再同步改 .env——
# 「改了端口忘了改 URL」的症状同样是 503，却要多花一轮排查。
export SR_INTERNAL_DOCGEN_URL="${SR_INTERNAL_DOCGEN_URL:-${DOCGEN_URL}}"
export SR_INTERNAL_GOTENBERG_URL="${SR_INTERNAL_GOTENBERG_URL:-${GOTENBERG_URL}}"

# ---------------------------------------------------------------- 2. 后端
log "启动 Go 主服务（http://127.0.0.1:${SR_SERVER_PORT}）…"
( cd server && exec "${GO}" run ./cmd/api ) &
SERVER_PID=$!

log "等待后端就绪…"
for i in $(seq 1 45); do
  if curl -fsS "http://127.0.0.1:${SR_SERVER_PORT}/api/health" >/dev/null 2>&1; then
    log "后端已就绪 ✅  /api/health 正常"
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    err "后端进程已退出，请检查上方日志"
    exit 1
  fi
  [[ $i -eq 45 ]] && { err "后端等待超时"; exit 1; }
  sleep 1
done

# ---------------------------------------------------------------- 3. 前端
if [[ ! -d web/node_modules ]]; then
  log "首次运行，安装前端依赖…"
  ( cd web && "${NPM}" install )
fi

log "启动前端 dev server（Vite HMR）…"
log "────────────────────────────────────────────────"
log "  前端界面   http://localhost:5173"
log "  后端接口   http://127.0.0.1:${SR_SERVER_PORT}/api/health"
log "  样式验证页 http://localhost:5173/dev/style-check"
log "  Word 渲染  ${DOCGEN_URL}/health"
log "  PDF 渲染   ${GOTENBERG_URL}/health"
log "  Ctrl-C 退出"
log "────────────────────────────────────────────────"

cd web && exec "${NPM}" run dev
