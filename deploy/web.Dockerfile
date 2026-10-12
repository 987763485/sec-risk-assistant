# ============================================================================
# 前端镜像 —— 多阶段构建：Node 构建静态产物 → Nginx 托管并反向代理 API
# ============================================================================

# ---------- 构建阶段 ----------
FROM node:22-alpine AS builder

WORKDIR /app

# 先装依赖（利用层缓存）
COPY web/package.json web/package-lock.json* ./
RUN npm ci

# 再拷贝源码并构建
COPY web/ ./

ARG APP_VERSION=0.1.0
ENV APP_VERSION=${APP_VERSION}

RUN npm run build

# ---------- 运行阶段 ----------
FROM nginx:1.27-alpine

# 清掉默认站点配置，改用我们自己的
RUN rm -f /etc/nginx/conf.d/default.conf
COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf

# 静态产物
COPY --from=builder /app/dist /usr/share/nginx/html

# 上传与导出目录（compose 中以 volume 覆盖）
RUN mkdir -p /var/www/uploads /var/www/reports \
 && chown -R nginx:nginx /var/www

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
