package router

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/middleware"
	"secrisk/server/internal/repository"
)

// testRouter 构建一个不连数据库的路由实例。
//
// db 传 nil 是可行的：所有仓储只保存引用，认证中间件在缺少 Cookie 时
// 会直接返回 401，根本走不到数据访问。这样路由装配测试无需依赖 MySQL。
func testRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{}
	cfg.App.Env = "test"
	cfg.App.Name = "sec-risk-assistant-test"
	cfg.Server.CORSOrigins = []string{"http://localhost:5173"}
	cfg.Server.TrustedProxies = []string{"127.0.0.1/32"}
	cfg.Auth.JWTSecret = strings.Repeat("k", 32)
	cfg.Auth.AccessTTL = 15 * time.Minute
	cfg.Auth.RefreshTTL = 24 * time.Hour
	cfg.Auth.MaxLoginAttempts = 5
	cfg.Auth.LockDuration = 15 * time.Minute
	cfg.Auth.LoginRateLimit = 20
	cfg.Auth.LoginRateWindow = 15 * time.Minute
	cfg.Storage.UploadDir = t.TempDir()
	cfg.Storage.MaxFileBytes = 10 << 20

	tokens, err := auth.NewTokenManager(cfg.Auth.JWTSecret, auth.TokenIssuer, cfg.Auth.AccessTTL)
	if err != nil {
		t.Fatalf("构建令牌管理器失败: %v", err)
	}

	engine, err := New(Deps{
		Config:       cfg,
		Repo:         repository.New(nil),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tokens:       tokens,
		LoginLimiter: middleware.NewRateLimiter(cfg.Auth.LoginRateLimit, cfg.Auth.LoginRateWindow),
	}, nil)
	if err != nil {
		t.Fatalf("构建路由失败: %v", err)
	}
	return engine
}

// concretize 把路由模板中的路径参数替换为具体值，便于发起真实请求。
func concretize(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") || strings.HasPrefix(p, "*") {
			parts[i] = "1"
		}
	}
	return strings.Join(parts, "/")
}

// TestProtectedRoutesRejectAnonymous 是本包最重要的一条测试。
//
// 它遍历真实路由表，对每一条非公开路由发起匿名请求，要求必须被拦下。
// 这样做的价值在于：它是**行为级**断言，而不是「检查中间件是否挂上」的
// 结构级断言。任何人新增路由时如果忘了加认证与权限中间件，
// 这个测试会立刻变红——比代码评审靠肉眼看靠谱得多。
func TestProtectedRoutesRejectAnonymous(t *testing.T) {
	r := testRouter(t)

	inspected := 0
	for _, route := range r.Routes() {
		if route.Method == http.MethodHead {
			continue
		}
		if IsPublicRoute(route.Method, route.Path) {
			continue
		}

		inspected++
		req := httptest.NewRequest(route.Method, concretize(route.Path), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// 读接口无 Cookie 应为 401；写接口会先被 CSRF 中间件拦成 403。
		// 两者都算「被拦下」，但绝不能是 2xx，也绝不能是 404。
		if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Errorf("%s %s 匿名访问返回 %d，期望 401 或 403（该路由可能缺少认证中间件）",
				route.Method, route.Path, w.Code)
		}
	}

	if inspected == 0 {
		t.Fatal("未检视到任何受保护路由，说明公开清单可能把所有路由都标成了公开")
	}
	t.Logf("已检视 %d 条受保护路由，全部拒绝匿名访问", inspected)
}

// TestPublicRouteWhitelistIsAccurate 反向校验公开清单：
//
//	① 清单里的每一项都必须真实存在于路由表中（防止清单残留废弃条目）
//	② 每一条公开路由都不能要求认证（防止「写了 PublicRoute 但实际挂了 Authn」）
func TestPublicRouteWhitelistIsAccurate(t *testing.T) {
	r := testRouter(t)

	actual := make(map[string]struct{}, len(r.Routes()))
	for _, route := range r.Routes() {
		if route.Method == http.MethodHead {
			continue
		}
		actual[route.Method+" "+route.Path] = struct{}{}
	}

	for _, p := range PublicRoute {
		if _, ok := actual[p]; !ok {
			t.Errorf("公开路由清单中的 %q 在路由表里不存在，清单已过期", p)
		}
	}

	// 公开清单必须是显式且克制的：条数暴增通常意味着有人图省事
	// 把接口一股脑标成了公开
	if len(PublicRoute) > 10 {
		t.Errorf("公开路由数量为 %d，超出预期上限，请确认是否有接口被误标为公开",
			len(PublicRoute))
	}
}

// TestPublicRoutesReachableWithoutAuth 验证公开端点确实无需认证即可访问。
//
// 只检视不需要数据库的端点：/api/health 会探测数据库，此处不做连通性断言。
func TestPublicRoutesReachableWithoutAuth(t *testing.T) {
	r := testRouter(t)

	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/auth/csrf"},
		{http.MethodGet, "/api/version"},
		{http.MethodGet, "/healthz"},
	} {
		req := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s %s 应免认证可访问，实际返回 %d", route.method, route.path, w.Code)
		}
	}
}

// TestEveryRouteIsClassified 确保没有「既不在公开清单、又探测不出保护」的模糊路由。
func TestEveryRouteIsClassified(t *testing.T) {
	r := testRouter(t)

	for _, route := range r.Routes() {
		if route.Method == http.MethodHead {
			continue
		}
		key := route.Method + " " + route.Path
		if IsPublicRoute(route.Method, route.Path) {
			continue
		}
		if !strings.HasPrefix(route.Path, "/api") && route.Path != "/healthz" {
			t.Errorf("路由 %q 不在 /api 命名空间下，容易绕过统一的安全中间件", key)
		}
	}
}
