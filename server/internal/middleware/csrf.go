package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/response"
)

// safeMethods 不改变服务端状态的方法，无需 CSRF 防护。
var safeMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodOptions: {},
}

// CSRFConfig CSRF 双提交令牌配置。
type CSRFConfig struct {
	// TrustedOrigins 允许的请求来源白名单，通常与 CORS 白名单一致。
	TrustedOrigins []string
	// SkipPaths 豁免路径（按 gin 路由模板匹配，如 "/api/auth/csrf"）。
	SkipPaths []string
}

// CSRF 双提交令牌校验。
//
// 工作原理：
//  1. 服务端下发一个随机令牌，同时写进 Cookie（sr_csrf）与响应体
//  2. 前端每次写请求都把它放进 X-CSRF-Token 头
//  3. 服务端比对「Cookie 里的值」与「请求头里的值」是否一致
//
// 为什么这样能防住 CSRF：攻击者虽然能让受害者的浏览器自动带上 Cookie，
// 但受同源策略限制，他**读不到 Cookie 的内容**，也就无法伪造出匹配的请求头。
//
// 本实现额外叠加了一层 Origin 校验，作为纵深防御：即使某个浏览器或代理
// 存在 Cookie 处理缺陷，跨站请求也会因来源不匹配被直接拒绝。
func CSRF(cfg CSRFConfig) gin.HandlerFunc {
	trusted := make(map[string]struct{}, len(cfg.TrustedOrigins))
	for _, o := range cfg.TrustedOrigins {
		if o != "" {
			trusted[o] = struct{}{}
		}
	}

	skip := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skip[p] = struct{}{}
	}

	return func(c *gin.Context) {
		if _, ok := safeMethods[c.Request.Method]; ok {
			c.Next()
			return
		}
		if _, ok := skip[c.FullPath()]; ok {
			c.Next()
			return
		}

		// ① 来源校验。浏览器发起的跨站写请求必然携带 Origin；
		//    注意 "null"（沙箱 iframe / file://）不匹配白名单，会被正确拒绝。
		if origin := c.GetHeader("Origin"); origin != "" {
			if _, ok := trusted[origin]; !ok {
				response.Forbidden(c, errcode.CodeCSRFInvalid, "请求来源不被信任")
				return
			}
		}

		// ② 双提交令牌比对。用常量时间比较，避免通过响应耗时逐字节试探。
		cookieToken, err := c.Cookie(auth.CookieCSRF)
		headerToken := c.GetHeader(auth.CSRFHeaderName)
		if err != nil || cookieToken == "" || headerToken == "" ||
			!auth.SecureCompare(cookieToken, headerToken) {
			response.Forbidden(c, errcode.CodeCSRFInvalid, "CSRF 校验失败，请刷新页面后重试")
			return
		}

		c.Next()
	}
}
