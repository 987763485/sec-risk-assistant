package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// AuthHandler 认证接口。
type AuthHandler struct {
	Base
	svc *service.AuthService
}

// NewAuthHandler 构建认证接口处理器。
func NewAuthHandler(base Base, svc *service.AuthService) *AuthHandler {
	return &AuthHandler{Base: base, svc: svc}
}

// CSRF 下发 CSRF 双提交令牌。
//
// 前端在应用启动时调用一次，token 同时写入 Cookie（sr_csrf）与响应体。
// 之所以两边都给：Cookie 供同源部署直接读取，响应体供跨端口开发时使用
// （开发环境下前端与后端不同源，读 Cookie 会受第三方 Cookie 策略影响）。
func (h *AuthHandler) CSRF(c *gin.Context) {
	token, err := h.svc.NewCSRFToken()
	if err != nil {
		h.fail(c, err)
		return
	}

	ttl := h.svc.RefreshTTL()
	http.SetCookie(c.Writer, h.svc.CookieOptions().CSRF(token, ttl))

	response.OK(c, gin.H{
		"csrf_token":  token,
		"header_name": auth.CSRFHeaderName,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionPayload struct {
	User               *userPayload `json:"user"`
	ExpiresIn          int          `json:"expires_in"`
	MustChangePassword bool         `json:"must_change_password"`
	CSRFToken          string       `json:"csrf_token"`
}

type userPayload struct {
	UserID      uint64   `json:"user_id"`
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// Login 登录。
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}
	if req.Username == "" || req.Password == "" {
		h.invalidParam(c, "请填写登录名与密码")
		return
	}

	session, err := h.svc.Login(c.Request.Context(), req.Username, req.Password, requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	h.setSessionCookies(c, session)
	response.OK(c, h.payloadOf(session))
}

// Refresh 刷新登录状态。
func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(auth.CookieRefresh)
	if err != nil || refreshToken == "" {
		h.clearSessionCookies(c)
		response.Unauthorized(c, errcode.CodeTokenInvalid, "登录状态已失效，请重新登录")
		return
	}

	session, err := h.svc.Refresh(c.Request.Context(), refreshToken, requestMeta(c))
	if err != nil {
		// 刷新失败必须一并清掉 Cookie。否则前端会拿着一个已经作废的
		// 刷新令牌反复重试，陷入「刷新 → 失败 → 再刷新」的死循环。
		h.clearSessionCookies(c)
		h.fail(c, err)
		return
	}

	h.setSessionCookies(c, session)
	response.OK(c, h.payloadOf(session))
}

// Logout 登出。
//
// 挂在「可选认证」之下：访问令牌过期时也应能正常登出。
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, _ := c.Cookie(auth.CookieRefresh)

	var principal *auth.Principal
	if p, ok := reqctx.Principal(c); ok {
		principal = p
	}

	if err := h.svc.Logout(c.Request.Context(), refreshToken, principal, requestMeta(c)); err != nil {
		h.fail(c, err)
		return
	}

	h.clearSessionCookies(c)
	response.OK(c, gin.H{"logged_out": true})
}

// Me 返回当前登录者信息。
func (h *AuthHandler) Me(c *gin.Context) {
	p, ok := reqctx.Principal(c)
	if !ok {
		response.Unauthorized(c, errcode.CodeUnauthorized, "未登录，请先登录")
		return
	}

	result, err := h.svc.Me(c.Request.Context(), p.UserID)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, result)
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ChangePassword 修改本人密码。
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	p, ok := reqctx.Principal(c)
	if !ok {
		response.Unauthorized(c, errcode.CodeUnauthorized, "未登录，请先登录")
		return
	}

	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		h.invalidParam(c, "请填写原密码与新密码")
		return
	}

	refreshToken, _ := c.Cookie(auth.CookieRefresh)

	err := h.svc.ChangePassword(c.Request.Context(), p.UserID, service.ChangePasswordInput{
		OldPassword:         req.OldPassword,
		NewPassword:         req.NewPassword,
		CurrentRefreshToken: refreshToken,
		Meta:                requestMeta(c),
	})
	if err != nil {
		h.fail(c, err)
		return
	}

	response.OK(c, gin.H{"changed": true})
}

// ------------------------------------------------------------------ 内部

// setSessionCookies 下发三枚会话 Cookie。
func (h *AuthHandler) setSessionCookies(c *gin.Context, s *service.Session) {
	opts := h.svc.CookieOptions()
	w := c.Writer

	http.SetCookie(w, opts.Access(s.AccessToken, h.svc.AccessTTL()))
	http.SetCookie(w, opts.Refresh(s.RefreshToken, h.svc.RefreshTTL()))
	// CSRF 令牌与会话同寿命：会话在，令牌就在
	http.SetCookie(w, opts.CSRF(s.CSRFToken, h.svc.RefreshTTL()))
}

// clearSessionCookies 清除三枚会话 Cookie。
func (h *AuthHandler) clearSessionCookies(c *gin.Context) {
	opts := h.svc.CookieOptions()
	w := c.Writer

	http.SetCookie(w, opts.ClearAccess())
	http.SetCookie(w, opts.ClearRefresh())
	http.SetCookie(w, opts.ClearCSRF())
}

func (h *AuthHandler) payloadOf(s *service.Session) sessionPayload {
	return sessionPayload{
		User: &userPayload{
			UserID:      s.Principal.UserID,
			Username:    s.Principal.Username,
			DisplayName: s.Principal.DisplayName,
			Roles:       s.Principal.Roles,
			Permissions: s.Principal.PermissionCodes(),
		},
		ExpiresIn:          s.ExpiresIn,
		MustChangePassword: s.MustChangePassword,
		CSRFToken:          s.CSRFToken,
	}
}
