package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/pkg/reqctx"
)

func newRBACRouter(
	hasPrincipal bool, perms []auth.Permission, required ...auth.Permission,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))

	r := gin.New()
	r.GET("/guarded",
		func(c *gin.Context) {
			if hasPrincipal {
				reqctx.WithPrincipal(c, &auth.Principal{
					UserID:      1,
					Username:    "tester",
					Roles:       []string{"assessor"},
					Permissions: auth.NewPermissionSet(perms),
				})
			}
			c.Next()
		},
		g.RequirePermission(required...),
		func(c *gin.Context) { c.String(http.StatusOK, "ok") },
	)
	return r
}

func callGuarded(r *gin.Engine) int {
	req := httptest.NewRequest(http.MethodGet, "/guarded", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// 上下文里没有认证主体时返回 401 而不是 403：
// 403 会误导前端「已登录但没权限」，而实际情况是认证中间件压根没生效，
// 属于路由装配错误，必须能被立刻识别出来。
func TestRequirePermission_NoPrincipalReturns401(t *testing.T) {
	r := newRBACRouter(false, nil, auth.PermAssetRead)
	if code := callGuarded(r); code != http.StatusUnauthorized {
		t.Fatalf("无认证主体时应返回 401，实际 %d", code)
	}
}

func TestRequirePermission_LackingPermissionReturns403(t *testing.T) {
	r := newRBACRouter(true, []auth.Permission{auth.PermAssetRead}, auth.PermUserWrite)
	if code := callGuarded(r); code != http.StatusForbidden {
		t.Fatalf("权限不足时应返回 403，实际 %d", code)
	}
}

func TestRequirePermission_HasPermissionPasses(t *testing.T) {
	r := newRBACRouter(true, []auth.Permission{auth.PermUserWrite}, auth.PermUserWrite)
	if code := callGuarded(r); code != http.StatusOK {
		t.Fatalf("持有权限时应放行，实际 %d", code)
	}
}

func TestRequirePermission_AnyOfPasses(t *testing.T) {
	r := newRBACRouter(true, []auth.Permission{auth.PermRoleRead},
		auth.PermRoleRead, auth.PermUserRead)
	if code := callGuarded(r); code != http.StatusOK {
		t.Fatalf("持有任一权限即应放行，实际 %d", code)
	}
}

func TestRequirePermission_EmptyPermissionSetDenied(t *testing.T) {
	r := newRBACRouter(true, nil, auth.PermUserRead)
	if code := callGuarded(r); code != http.StatusForbidden {
		t.Fatalf("权限集为空时应返回 403，实际 %d", code)
	}
}

// 没有声明权限码属于编程错误，必须在装配阶段就炸掉，
// 而不是退化成一个「谁都能过」的裸接口。
func TestRequirePermission_PanicsWithoutPermission(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("未声明权限码时应 panic")
		}
	}()
	NewGuard(nil).RequirePermission()
}

func TestRequireRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := gin.New()
	r.GET("/admin-only",
		func(c *gin.Context) {
			reqctx.WithPrincipal(c, &auth.Principal{
				UserID: 1, Roles: []string{"assessor"},
			})
			c.Next()
		},
		g.RequireRole("admin"),
		func(c *gin.Context) { c.String(http.StatusOK, "ok") },
	)

	req := httptest.NewRequest(http.MethodGet, "/admin-only", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("角色不匹配时应返回 403，实际 %d", w.Code)
	}
}
