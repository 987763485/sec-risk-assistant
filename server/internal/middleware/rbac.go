package middleware

import (
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
)

// Guard 鉴权守卫工厂。
//
// 做成工厂而不是包级函数，是为了把 logger 明确注入进来，
// 避免依赖全局日志器或往上下文里塞 logger 这类隐式约定。
type Guard struct {
	logger *slog.Logger
}

// NewGuard 构建鉴权守卫。
func NewGuard(logger *slog.Logger) *Guard {
	if logger == nil {
		logger = slog.Default()
	}
	return &Guard{logger: logger}
}

// RequirePermission 要求持有给定权限中的任意一个。
//
// 前置条件：必须挂在 Authn 之后。若上下文里没有认证主体，
// 说明路由挂载顺序有误，这里按 401 处理而不是静默放行。
//
// ⚠️ 前端的菜单隐藏只是体验优化，**真正的权限边界在这里**。
// 任何受保护接口都必须显式声明所需权限，不允许出现「忘记加中间件」的裸接口——
// 这一点由 router 包的路由守卫测试兜底。
func (g *Guard) RequirePermission(perms ...auth.Permission) gin.HandlerFunc {
	if len(perms) == 0 {
		panic("middleware: RequirePermission 至少需要一个权限码")
	}

	return func(c *gin.Context) {
		p, ok := reqctx.Principal(c)
		if !ok {
			// 认证中间件未生效，属于装配错误
			response.Unauthorized(c, errcode.CodeUnauthorized, "未登录，请先登录")
			return
		}

		if !p.CanAny(perms...) {
			g.logger.Warn("权限不足，已拒绝",
				"user_id", p.UserID,
				"username", p.Username,
				"roles", strings.Join(p.Roles, ","),
				"required", permissionStrings(perms),
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
				"request_id", reqctx.RequestID(c))
			response.Forbidden(c, errcode.CodeForbidden, "没有执行该操作的权限")
			return
		}
		c.Next()
	}
}

// RequireRole 要求持有指定角色之一。
//
// 使用建议：优先用 RequirePermission。角色是「人的身份」，权限是「能做的事」，
// 接口应当声明后者。这个函数只留给「必须由管理员本人操作」这类语义。
func (g *Guard) RequireRole(codes ...string) gin.HandlerFunc {
	if len(codes) == 0 {
		panic("middleware: RequireRole 至少需要一个角色码")
	}

	return func(c *gin.Context) {
		p, ok := reqctx.Principal(c)
		if !ok {
			response.Unauthorized(c, errcode.CodeUnauthorized, "未登录，请先登录")
			return
		}
		for _, code := range codes {
			if p.HasRole(code) {
				c.Next()
				return
			}
		}
		response.Forbidden(c, errcode.CodeForbidden, "没有执行该操作的权限")
	}
}

func permissionStrings(perms []auth.Permission) string {
	parts := make([]string, 0, len(perms))
	for _, p := range perms {
		parts = append(parts, string(p))
	}
	return strings.Join(parts, "|")
}
