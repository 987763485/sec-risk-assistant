package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
)

const testOrigin = "http://localhost:5173"

func newCSRFRouter(cfg CSRFConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CSRF(cfg))
	r.GET("/read", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.POST("/write", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func doRequest(
	r *gin.Engine, method, path string, headers map[string]string, cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestCSRF_SafeMethodBypasses(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	if w := doRequest(r, http.MethodGet, "/read", nil); w.Code != http.StatusOK {
		t.Fatalf("安全方法不应被 CSRF 拦截，实际 %d", w.Code)
	}
}

func TestCSRF_WriteWithoutTokenRejected(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	if w := doRequest(r, http.MethodPost, "/write", nil); w.Code != http.StatusForbidden {
		t.Fatalf("缺少令牌的写请求应被拒绝，实际 %d", w.Code)
	}
}

// 只带 Cookie 不带请求头时必须拒绝。
// 这正是 CSRF 攻击的实际形状：攻击者能让浏览器自动带上 Cookie，
// 但受同源策略限制读不到它的值，因此无法伪造出匹配的请求头。
func TestCSRF_CookieOnlyRejected(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	ck := &http.Cookie{Name: auth.CookieCSRF, Value: "token-abc"}
	if w := doRequest(r, http.MethodPost, "/write", nil, ck); w.Code != http.StatusForbidden {
		t.Fatalf("仅有 Cookie 的写请求应被拒绝，实际 %d", w.Code)
	}
}

func TestCSRF_HeaderOnlyRejected(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	h := map[string]string{auth.CSRFHeaderName: "token-abc"}
	if w := doRequest(r, http.MethodPost, "/write", h); w.Code != http.StatusForbidden {
		t.Fatalf("仅有请求头的写请求应被拒绝，实际 %d", w.Code)
	}
}

func TestCSRF_MismatchedTokenRejected(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	ck := &http.Cookie{Name: auth.CookieCSRF, Value: "token-abc"}
	h := map[string]string{auth.CSRFHeaderName: "token-xyz"}
	if w := doRequest(r, http.MethodPost, "/write", h, ck); w.Code != http.StatusForbidden {
		t.Fatalf("令牌不匹配的写请求应被拒绝，实际 %d", w.Code)
	}
}

func TestCSRF_MatchedTokenAccepted(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	ck := &http.Cookie{Name: auth.CookieCSRF, Value: "token-abc"}
	h := map[string]string{auth.CSRFHeaderName: "token-abc"}
	if w := doRequest(r, http.MethodPost, "/write", h, ck); w.Code != http.StatusOK {
		t.Fatalf("令牌匹配的写请求应放行，实际 %d", w.Code)
	}
}

func TestCSRF_TrustedOriginWithMatchedTokenAccepted(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	ck := &http.Cookie{Name: auth.CookieCSRF, Value: "token-abc"}
	h := map[string]string{
		auth.CSRFHeaderName: "token-abc",
		"Origin":            testOrigin,
	}
	if w := doRequest(r, http.MethodPost, "/write", h, ck); w.Code != http.StatusOK {
		t.Fatalf("可信来源且令牌匹配时应放行，实际 %d", w.Code)
	}
}

func TestCSRF_UntrustedOriginRejected(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	ck := &http.Cookie{Name: auth.CookieCSRF, Value: "token-abc"}
	h := map[string]string{
		auth.CSRFHeaderName: "token-abc", // 令牌本身是对的，仍必须被来源校验拦下
		"Origin":            "http://evil.example.com",
	}
	if w := doRequest(r, http.MethodPost, "/write", h, ck); w.Code != http.StatusForbidden {
		t.Fatalf("不可信来源应被拒绝，实际 %d", w.Code)
	}
}

// Origin: null 来自沙箱 iframe 与 file:// 页面，是最典型的绕过尝试。
// 它不匹配任何白名单项，必须被拒绝。
func TestCSRF_NullOriginRejected(t *testing.T) {
	r := newCSRFRouter(CSRFConfig{TrustedOrigins: []string{testOrigin}})
	ck := &http.Cookie{Name: auth.CookieCSRF, Value: "token-abc"}
	h := map[string]string{
		auth.CSRFHeaderName: "token-abc",
		"Origin":            "null",
	}
	if w := doRequest(r, http.MethodPost, "/write", h, ck); w.Code != http.StatusForbidden {
		t.Fatalf("Origin: null 应被拒绝，实际 %d", w.Code)
	}
}

func TestCSRF_SkipPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CSRF(CSRFConfig{SkipPaths: []string{"/exempt"}}))
	r.POST("/exempt", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	if w := doRequest(r, http.MethodPost, "/exempt", nil); w.Code != http.StatusOK {
		t.Fatalf("豁免路径不应校验令牌，实际 %d", w.Code)
	}
}
