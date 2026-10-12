package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders 统一安全响应头。
//
// 注意：CSP 不在此处设置——API 响应的 CSP 由前置 Nginx 对 HTML 统一下发
// 更合适（见 deploy/nginx/default.conf）。这里只设置与 API 语义无关、
// 对所有响应都安全的几个头。
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		c.Next()
	}
}

// CORS 跨域配置。
//
// 说明：生产环境前端与 API 同源（Nginx 反代），CORS 实际不触发；此处
// 存在只为本地开发（Vite dev server 跨端口）。因此采用**显式白名单**，
// 不用通配符。
//
// ⚠️ 因为要携带 Cookie 会话，必须配 Access-Control-Allow-Credentials: true；
// 而该头与 Allow-Origin: * 互斥（浏览器会直接拒绝），所以命中白名单时
// 回显具体 Origin。
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o != "" {
			allowed[o] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			if _, ok := allowed[origin]; ok {
				h := c.Writer.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
				h.Set("Access-Control-Allow-Headers",
					"Content-Type,Authorization,X-Request-ID,X-CSRF-Token,Accept,Origin")
				h.Set("Access-Control-Expose-Headers", "X-Request-ID,Content-Disposition")
				h.Set("Access-Control-Max-Age", "600")
			}
		}

		// 预检请求直接放行，不进业务处理链
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
