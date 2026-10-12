// Package middleware 提供 HTTP 中间件：请求追踪、日志、恢复、安全响应头、
// CORS，以及 P1 引入的认证 / 鉴权 / CSRF / 审计 / 登录限流。
package middleware

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
)

// gin.Context 上的键名。值与 reqctx 共用同一份常量定义，
// 避免出现「写入用一个字符串、读取用另一个」这类难查的错位。
const (
	// ContextKeyRequestID 请求 ID，贯穿访问日志与响应头
	ContextKeyRequestID = reqctx.KeyRequestID
	// ContextKeyPrincipal 认证主体，由 Authn 中间件写入
	ContextKeyPrincipal = reqctx.KeyPrincipal
	// ContextKeyAuditMark 审计标注，由 handler 写入
	ContextKeyAuditMark = reqctx.KeyAuditMark
)

// GetRequestID 读取请求 ID。
//
// 保留这个函数是为了兼容 P0 已落地的调用点（router、accesslog）；
// 新代码可以直接使用 reqctx.RequestID。
func GetRequestID(c *gin.Context) string {
	return reqctx.RequestID(c)
}
