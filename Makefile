# ============================================================================
# sec-risk-assistant —— 统一构建 / 运行入口
#
# 常用：
#   make setup        首次初始化（生成 .env）
#   make dev          本地热重载开发（docker 起依赖 + 本地跑 Go 与 Vite）
#   make infra        只起依赖服务（mysql / docgen / gotenberg）
#   make up           全栈容器化运行（http://localhost:8000）
#   make down         停止并移除容器
#   make logs         跟踪全部服务日志
#   make test         跑全部测试
#   make lint         跑全部静态检查（含接口契约校验）
#   make api          改完 docs/openapi.yaml 后重新生成前端类型
#   make build        构建全部产物
#   make clean        清理构建产物与容器数据（危险，会删库）
# ============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---------------------------------------------------------------- 变量
# 把 .env 读进来并导出给所有子进程。
# 前提：.env 内**不得有行尾注释**，否则注释会被当成值的一部分。
# 用 -include 而非 include，保证 .env 尚未生成时 make 不报错。
-include .env
export

ROOT        := $(shell pwd)
COMPOSE     := docker compose
# 本地开发用：叠加 deploy/compose.dev.yml，把 docgen / gotenberg 的端口
# 映射到宿主机回环，这样在宿主机上跑的 Go 服务才连得上它们。
#
# ⚠️ 只有 `infra` 与 `scripts/dev.sh` 用它。
#    `up` / `down` / `logs` / `ps` 一律不加 —— 生产部署走的就是 `make up`，
#    而这份叠加文件存在的全部意义正是「它不能在生产生效」。
#    文件也刻意不叫 docker-compose.override.yml（那个名字会被 compose
#    自动加载，等于让这条规则形同虚设）。
COMPOSE_DEV := $(COMPOSE) -f docker-compose.yml -f deploy/compose.dev.yml
ENV_FILE    := .env
VERSION     ?= 0.1.0

# 沙箱/受限环境下 ~/.docker 不可写，把 buildx 状态目录指到项目内。
# 正常环境下此目录只会多出一个小的状态文件，无副作用。
export BUILDX_CONFIG := $(ROOT)/.buildx

# 本地开发时后端读取的数据库连接（指向 docker 暴露的回环端口）
DEV_DB_PORT ?= 13306
DEV_DB_USER ?= secrisk
DEV_DB_PASS ?= secrisk_dev_pwd
DEV_DB_NAME ?= sec_risk

NODE_BIN    := /Users/chunle/.workbuddy/binaries/node/versions/22.22.2-6/bin
NPM         := $(NODE_BIN)/npm
GO          := go

# ---------------------------------------------------------------- 帮助
.PHONY: help
help: ## 显示所有可用目标
	@awk 'BEGIN { \
		print ""; \
		print "  sec-risk-assistant —— 可用命令"; \
		print "  ------------------------------------------------------------"; \
	} \
	/^[a-zA-Z0-9_-]+:.*## / { \
		ci = index($$0, ":"); \
		mi = index($$0, "## "); \
		if (ci > 1 && mi > ci) { \
			printf "  \033[36m%-18s\033[0m %s\n", substr($$0, 1, ci - 1), substr($$0, mi + 3); \
		} \
	} \
	END { print "" }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------- 初始化
.PHONY: setup
setup: ## 首次初始化：生成 .env
	@if [ -f $(ENV_FILE) ]; then \
		echo "✅ $(ENV_FILE) 已存在，跳过"; \
	else \
		cp .env.example $(ENV_FILE); \
		echo "✅ 已从 .env.example 生成 $(ENV_FILE)，请检查其中的密码与密钥"; \
	fi

.PHONY: doctor
doctor: ## 检查本机工具链是否满足要求
	@echo "--- 工具链检查 ---"
	@printf "go         : "; ($(GO) version 2>/dev/null || echo "缺失 ❌")
	@printf "node       : "; ($(NODE_BIN)/node -v 2>/dev/null || echo "缺失 ❌")
	@printf "npm        : "; ($(NPM) -v 2>/dev/null || echo "缺失 ❌")
	@printf "docker     : "; (docker --version 2>/dev/null || echo "缺失 ❌")
	@printf "docker 守护: "; (docker info --format '{{.ServerVersion}}' 2>/dev/null || echo "未运行 ❌")
	@echo "--- 端口占用 ---"
	@for p in 13306 8000 8080 5173; do \
		if lsof -nP -iTCP:$$p -sTCP:LISTEN >/dev/null 2>&1; then \
			echo "  端口 $$p 已被占用（可能与本项目冲突）"; \
		fi; \
	done
	@echo "完成。"

# ---------------------------------------------------------------- 运行
.PHONY: infra
infra: setup ## 只起依赖服务（mysql / docgen / gotenberg，端口映射到回环）
	$(COMPOSE_DEV) up -d --build mysql docgen gotenberg
	@echo "⏳ 等待 MySQL 就绪…"
	@until $(COMPOSE) exec -T mysql mysqladmin ping -h 127.0.0.1 -u root -p"$${MYSQL_ROOT_PASSWORD:-root_dev_pwd}" --silent >/dev/null 2>&1; do \
		printf "."; sleep 2; \
	done; echo " ✅"
	@echo "⏳ 等待渲染服务就绪…"
	@for i in $$(seq 1 40); do \
		if curl -fsS "http://127.0.0.1:$${DOCGEN_PORT:-8090}/health" >/dev/null 2>&1 \
		   && curl -fsS "http://127.0.0.1:$${GOTENBERG_PORT:-3000}/health" >/dev/null 2>&1; then \
			echo " ✅ docgen:$${DOCGEN_PORT:-8090} / gotenberg:$${GOTENBERG_PORT:-3000} 就绪"; exit 0; \
		fi; printf "."; sleep 2; \
	done; \
	echo ""; echo "⚠️  渲染服务未在超时内就绪。P5 的 Word / PDF 导出会返回 503。"; \
	echo "    排查：docker compose ps；docker port secrisk-docgen secrisk-gotenberg"

.PHONY: dev
dev: ## 本地热重载开发（含依赖服务）
	@bash scripts/dev.sh

.PHONY: up
up: setup ## 全栈容器化运行
	$(COMPOSE) up -d --build
	@echo "✅ 已启动：http://localhost:$${WEB_PORT:-8000}"

.PHONY: down
down: ## 停止并移除容器（保留数据卷）
	$(COMPOSE) down

.PHONY: restart
restart: ## 重启全部服务
	$(COMPOSE) restart

.PHONY: logs
logs: ## 跟踪全部服务日志
	$(COMPOSE) logs -f --tail=100

.PHONY: ps
ps: ## 查看服务状态
	$(COMPOSE) ps

# ---------------------------------------------------------------- 后端
.PHONY: server-run
server-run: ## 只跑 Go 主服务（需 infra 已起）
	cd server && $(GO) run ./cmd/api

.PHONY: server-migrate
server-migrate: ## 只执行数据库迁移
	cd server && $(GO) run ./cmd/api --migrate

.PHONY: server-build
server-build: ## 构建 Go 二进制到 server/bin/
	@mkdir -p server/bin
	cd server && CGO_ENABLED=0 $(GO) build -trimpath \
		-ldflags "-s -w -X secrisk/server/internal/version.Version=$(VERSION)" \
		-o bin/api ./cmd/api
	@ls -lh server/bin/api

.PHONY: server-test
server-test: ## 跑 Go 单测（含竞态检测）
	cd server && $(GO) test -race -count=1 ./...

.PHONY: server-tidy
server-tidy: ## 整理 Go 依赖
	cd server && $(GO) mod tidy

# ---------------------------------------------------------------- 前端
.PHONY: web-install
web-install: ## 安装前端依赖
	cd web && $(NPM) install

.PHONY: web-dev
web-dev: ## 只跑前端 dev server
	cd web && $(NPM) run dev

.PHONY: web-build
web-build: ## 构建前端静态产物到 web/dist/
	cd web && $(NPM) run build

.PHONY: web-typecheck
web-typecheck: ## 前端类型检查
	cd web && $(NPM) run typecheck

.PHONY: web-lint
web-lint: ## 前端 ESLint 检查
	cd web && $(NPM) run lint

.PHONY: web-format-check
web-format-check: ## 前端格式检查（Prettier，不修改文件）
	cd web && $(NPM) run format:check

.PHONY: web-verify-css
web-verify-css: ## 校验构建产物的 CSS 分层（需先 web-build）
	cd web && $(NPM) run verify:css

# ---------------------------------------------------------------- 接口契约
# docs/openapi.yaml 是接口契约的唯一真相源，前端类型由它生成。
# 因此契约的变更流程固定为：
#   改 docs/openapi.yaml → make api（重新生成前端类型）→ make api-check（验证对齐）
.PHONY: api
api: api-types ## 由 docs/openapi.yaml 重新生成前端接口类型
	@echo "✅ 前端类型已生成：web/src/api/generated/schema.d.ts"

.PHONY: api-types
api-types: ## 仅重新生成前端接口类型
	cd web && $(NPM) run api:types

.PHONY: api-check
api-check: ## 校验契约：结构无误、与 gin 路由表双向对齐、前端类型未过期
	@echo "--- 契约结构 + 与真实路由表双向对齐 ---"
	cd server && $(GO) test -count=1 ./internal/apidoc/ ./internal/router/
	@echo "--- 前端类型是否与契约同步 ---"
	cd web && $(NPM) run api:check
	@echo "✅ 接口契约校验通过"

# ---------------------------------------------------------------- 守门验证
.PHONY: verify-auth
verify-auth: ## 认证与授权端到端验证（会短暂占用 8080 端口，需 infra 已就绪）
	@bash scripts/verify-auth.sh

.PHONY: verify-web
verify-web: ## 前端端到端冒烟验证：真实浏览器 + 隔离临时库（需 infra 已就绪）
	@bash scripts/verify-web.sh

.PHONY: verify-style
verify-style: ## 前端 CSS 分层共存验证（需先 web-build）
	@bash scripts/verify-style-check.sh

.PHONY: verify-docgen
verify-docgen: ## docgen 文档渲染验证（需 infra 已就绪）
	@bash scripts/verify-docgen.sh

.PHONY: verify-asset
verify-asset: ## 资产 / 字典 / 批量导入端到端验证（用隔离临时库，需 infra 已就绪）
	@bash scripts/verify-asset.sh

.PHONY: verify-file
verify-file: ## 文件上传与漏洞解析端到端验证（用隔离临时库 + 隔离上传目录，需 infra 已就绪）
	@bash scripts/verify-file.sh

.PHONY: verify-assess
verify-assess: ## 风险评估引擎端到端验证：125 组穷举 + 三处一致（用隔离临时库，需 infra 已就绪）
	@bash scripts/verify-assess.sh

.PHONY: verify-report
verify-report: ## 报告导出端到端验证：Word/Excel/PDF 解包断言 + 五方一致（用隔离临时库，需 infra 已就绪）
	@bash scripts/verify-report.sh

.PHONY: verify-remediate
verify-remediate: ## 整改跟踪与仪表盘端到端验证：重算不断链 + 状态机 + 逾期 + 审计（用隔离临时库，需 infra 已就绪）
	@bash scripts/verify-remediate.sh

.PHONY: verify-integration
verify-integration: ## 扩展模块端到端验证：情报拉取 + SSRF 两层防护 + 审计 + MCP Server（用隔离临时库，需 infra 与 mcp/node_modules）
	@bash scripts/verify-integration.sh

.PHONY: mcp-install
mcp-install: ## 安装 MCP Server 依赖（mcp/）
	cd mcp && $(NPM) install

.PHONY: mcp-smoke
mcp-smoke: ## MCP Server 冒烟（不起后端；SR_MCP_LIVE=1 时额外真登录）
	cd mcp && $(NPM) run smoke

# ---------------------------------------------------------------- 聚合
.PHONY: build
build: server-build web-build ## 构建全部产物

.PHONY: test
test: server-test ## 跑全部测试

.PHONY: lint
lint: ## 跑全部静态检查
	@echo "--- Go vet ---"
	cd server && $(GO) vet ./...
	@echo "--- Go 格式检查 ---"
	@cd server && files=$$(gofmt -l . | grep -v '^$$' || true); \
		if [ -n "$$files" ]; then echo "以下文件格式不合规，请运行 make fmt："; echo "$$files"; exit 1; \
		else echo "✅ 通过"; fi
	@echo "--- 前端类型检查 ---"
	cd web && $(NPM) run typecheck
	@echo "--- 前端 ESLint ---"
	cd web && $(NPM) run lint
	@echo "--- 前端格式检查 ---"
	cd web && $(NPM) run format:check
	@echo "--- 接口契约 ---"
	$(MAKE) --no-print-directory api-check
	@echo "✅ 全部通过"

.PHONY: fmt
fmt: ## 格式化全部代码
	cd server && gofmt -w .
	cd web && $(NPM) run format

# ---------------------------------------------------------------- 数据库
# ⚠️ db-shell 必须带 --default-character-set=utf8mb4：
# mysql 客户端默认用 latin1 连接，中文会在**读出来的时候**就变成 ?，
# 而库里数据其实是好的 —— 极易误判成「写入就有问题」。
.PHONY: db-shell
db-shell: ## 进入 MySQL 命令行（已默认 utf8mb4，中文不会显示成 ?）
	$(COMPOSE) exec mysql mysql --default-character-set=utf8mb4 -u$${MYSQL_USER:-secrisk} -p$${MYSQL_PASSWORD:-secrisk_dev_pwd} $${MYSQL_DATABASE:-sec_risk}

.PHONY: db-backup
db-backup: ## 备份数据库到 backups/
	@bash scripts/db-backup.sh

.PHONY: clean
clean: ## 停止服务并删除数据卷（⚠️ 会清空数据库）
	@read -p "⚠️  将删除容器与数据库数据卷，不可恢复。确认请输入 yes: " ok; \
	if [ "$$ok" = "yes" ]; then \
		$(COMPOSE) down -v; \
		rm -rf server/bin web/dist; \
		echo "✅ 已清理"; \
	else \
		echo "已取消"; \
	fi
