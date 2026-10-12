package middleware

import (
	"context"
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
)

// PrincipalLoader 按用户 ID 加载认证主体。
//
// 用接口而非直接依赖 service 包，让中间件的单测可以注入假实现，
// 也避免中间件层被业务层的演化牵着走。
type PrincipalLoader interface {
	LoadPrincipal(ctx context.Context, userID uint64) (*auth.Principal, error)
}

// Authn 认证中间件：解析访问令牌 Cookie，加载认证主体并写入上下文。
//
// 失败时一律中断请求（response.* 内部调用 Abort）。不提供「匿名放行」模式——
// 需要公开访问的接口应当挂在认证中间件之外，而不是让中间件去猜。
func Authn(tm *auth.TokenManager, loader PrincipalLoader, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := c.Cookie(auth.CookieAccess)
		if err != nil || raw == "" {
			response.Unauthorized(c, errcode.CodeUnauthorized, "未登录，请先登录")
			return
		}

		claims, err := tm.ParseAccess(raw)
		if err != nil {
			// 令牌过期与令牌无效必须用不同错误码：
			// 前端收到 AUTH_TOKEN_EXPIRED 会先尝试静默刷新再重放原请求，
			// 收到 AUTH_TOKEN_INVALID 则直接跳登录页。
			if errors.Is(err, auth.ErrTokenExpired) {
				response.Unauthorized(c, errcode.CodeTokenExpired, "登录状态已过期")
				return
			}
			response.Unauthorized(c, errcode.CodeTokenInvalid, "登录状态无效，请重新登录")
			return
		}

		userID, err := claims.UserID()
		if err != nil {
			response.Unauthorized(c, errcode.CodeTokenInvalid, "登录状态无效，请重新登录")
			return
		}

		principal, err := loader.LoadPrincipal(c.Request.Context(), userID)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrAccountDisabled):
				// 账号被禁用必须立即失效，而不是等令牌过期
				response.Forbidden(c, errcode.CodeAccountDisabled, "账号已被禁用，请联系管理员")
			case errors.Is(err, auth.ErrAccountNotFound):
				response.Unauthorized(c, errcode.CodeTokenInvalid, "账号不存在，请重新登录")
			default:
				logger.Error("加载认证主体失败",
					"user_id", userID,
					"err", err,
					"request_id", reqctx.RequestID(c))
				response.Internal(c)
			}
			return
		}

		reqctx.WithPrincipal(c, principal)

		// 令牌生效下界校验：登出后，此前签发的访问令牌必须立即失效。
		// JWT 是无状态的，没有这一步的话，用户点完登出后旧令牌
		// 还能用满剩余有效期。
		if !principal.TokensValidFrom.IsZero() && claims.IssuedAtMs > 0 &&
			claims.IssuedAtMs < principal.TokensValidFrom.UnixMilli() {
			response.Unauthorized(c, errcode.CodeTokenInvalid, "登录状态已失效，请重新登录")
			return
		}

		c.Next()
	}
}

// OptionalAuthn 尝试解析访问令牌并写入认证主体，失败则静默放行。
//
// 用途：登出接口。用户点登出时访问令牌可能已经过期，但登出本身
// （吊销刷新令牌 + 清 Cookie）必须能够完成——否则用户会陷入
// 「想退出却退不掉」的境地。这里只是「尽力识别调用者」，用于留审计痕迹，
// 不作为访问控制依据。
func OptionalAuthn(tm *auth.TokenManager, loader PrincipalLoader) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := c.Cookie(auth.CookieAccess)
		if err == nil && raw != "" {
			if claims, perr := tm.ParseAccess(raw); perr == nil {
				if userID, uerr := claims.UserID(); uerr == nil {
					if p, lerr := loader.LoadPrincipal(
						c.Request.Context(), userID); lerr == nil {
						reqctx.WithPrincipal(c, p)
					}
				}
			}
		}
		c.Next()
	}
}

// mustChangePasswordAllowlist 「必须改密」状态下仍然允许访问的端点。
//
// 这是个白名单而非黑名单：新增接口若忘记登记，默认会被拦下（安全侧失败），
// 而不是默认放行（危险侧失败）。
var mustChangePasswordAllowlist = map[string]struct{}{
	"/api/auth/me":       {},
	"/api/auth/csrf":     {},
	"/api/auth/password": {},
	"/api/auth/logout":   {},
	"/api/auth/refresh":  {},
}

// RequirePasswordChanged 拦截「首次登录未改密」的账号。
//
// 初始管理员由引导流程创建并带有 must_change_password 标记，
// 在完成改密之前，除改密与登出外的接口全部拒绝。
func RequirePasswordChanged() gin.HandlerFunc {
	return func(c *gin.Context) {
		if p, ok := reqctx.Principal(c); ok && p.MustChangePassword {
			if _, allowed := mustChangePasswordAllowlist[c.FullPath()]; !allowed {
				response.Forbidden(c, errcode.CodeMustChangePassword,
					"首次登录须先修改初始密码")
				return
			}
		}
		c.Next()
	}
}
