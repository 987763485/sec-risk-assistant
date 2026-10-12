package auth

import (
	"net/http"
	"time"
)

// Cookie 名称与路径常量。
//
// 三个 Cookie 各司其职，职责边界刻意划清：
//
//	sr_at    Access Token   —— httpOnly，随每个业务请求发送，15 分钟
//	sr_rt    Refresh Token  —— httpOnly，**仅 /api/auth 路径**发送，7 天
//	sr_csrf  CSRF 令牌      —— 非 httpOnly（前端必须能读到它），与会话同寿命
const (
	CookieAccess  = "sr_at"
	CookieRefresh = "sr_rt"
	CookieCSRF    = "sr_csrf"

	// RefreshCookiePath 把刷新令牌限制在认证路径下发送。
	//
	// 收益：访问 /api/assets 这类业务接口时，刷新令牌根本不出现在请求头里，
	// 于是它被 Nginx 访问日志、上游代理、或浏览器扩展读到的概率大幅下降。
	// 代价：跨路径使用时需要显式指定，目前只有 /api/auth/* 会用到它。
	RefreshCookiePath = "/api/auth"

	// CSRFHeaderName 前端回传 CSRF 令牌所用的请求头名称。
	// 与 CORS 白名单中的 X-CSRF-Token 保持一致。
	CSRFHeaderName = "X-CSRF-Token"
)

// CookieOptions Cookie 下发的环境相关选项。
type CookieOptions struct {
	// Secure 生产环境（HTTPS）必须为 true。开发环境走 http://localhost，
	// 置 true 会导致浏览器直接丢弃 Cookie，故按配置注入。
	Secure bool

	// SameSite 默认 Lax：允许顶级导航携带（刷新页面不掉线），
	// 阻止跨站 POST 携带（CSRF 的第一道防线）。
	SameSite http.SameSite
}

func (o CookieOptions) sameSite() http.SameSite {
	if o.SameSite == 0 {
		return http.SameSiteLaxMode
	}
	return o.SameSite
}

func (o CookieOptions) build(name, value, path string, ttl time.Duration, httpOnly bool) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: httpOnly,
		Secure:   o.Secure,
		SameSite: o.sameSite(),
	}
	if ttl > 0 {
		c.MaxAge = int(ttl / time.Second)
		c.Expires = time.Now().Add(ttl)
	}
	return c
}

func (o CookieOptions) expired(name, path string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		HttpOnly: true,
		Secure:   o.Secure,
		SameSite: o.sameSite(),
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	}
}

// Access 下发访问令牌 Cookie。
func (o CookieOptions) Access(value string, ttl time.Duration) *http.Cookie {
	return o.build(CookieAccess, value, "/", ttl, true)
}

// Refresh 下发刷新令牌 Cookie。
func (o CookieOptions) Refresh(value string, ttl time.Duration) *http.Cookie {
	return o.build(CookieRefresh, value, RefreshCookiePath, ttl, true)
}

// CSRF 下发 CSRF 令牌 Cookie。
//
// ⚠️ HttpOnly 必须为 false —— 双提交令牌模式的前提就是「前端 JavaScript
// 能读到它并放进请求头」。它本身不是凭证，泄露它也无法单独发起攻击，
// 因为攻击者还需要能读到 Cookie（同源策略已阻断）。
func (o CookieOptions) CSRF(value string, ttl time.Duration) *http.Cookie {
	return o.build(CookieCSRF, value, "/", ttl, false)
}

// ClearAccess 清除访问令牌。
func (o CookieOptions) ClearAccess() *http.Cookie {
	return o.expired(CookieAccess, "/")
}

// ClearRefresh 清除刷新令牌。
func (o CookieOptions) ClearRefresh() *http.Cookie {
	return o.expired(CookieRefresh, RefreshCookiePath)
}

// ClearCSRF 清除 CSRF 令牌。
func (o CookieOptions) ClearCSRF() *http.Cookie {
	return o.expired(CookieCSRF, "/")
}
