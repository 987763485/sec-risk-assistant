# ============================================================================
# 主服务镜像（Go / Gin）—— 多阶段构建
# 产物基于 alpine，非 root 用户运行，体积小且无构建工具链残留
# ============================================================================

# ---------- 构建阶段 ----------
FROM golang:1.25-alpine AS builder

WORKDIR /src

# git 用于部分依赖的 VCS 探测；ca-certificates 供 go mod 拉包
RUN apk add --no-cache git ca-certificates

# 先只拷贝依赖清单，让依赖层可被缓存（改业务代码不会重下依赖）
COPY server/go.mod server/go.sum ./
RUN go mod download

# 再拷贝源码
COPY server/ ./

ARG VERSION=0.1.0
ARG COMMIT=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w \
        -X secrisk/server/internal/version.Version=${VERSION} \
        -X secrisk/server/internal/version.Commit=${COMMIT} \
        -X secrisk/server/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      -o /out/api ./cmd/api

# ---------- 运行阶段 ----------
FROM alpine:3.21

# tzdata：正确解析 Asia/Shanghai；ca-certificates：出网调用需校验证书；
# wget（busybox 内置）供容器 healthcheck 使用
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 -S app \
 && adduser  -u 10001 -S app -G app

ENV TZ=Asia/Shanghai

WORKDIR /app
COPY --from=builder /out/api /app/api

# 非 root 运行：容器逃逸后的影响面显著缩小
USER 10001:10001

EXPOSE 8080

# 存活探针（不依赖数据库，避免 MySQL 抖动导致容器被误重启）
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/api"]
