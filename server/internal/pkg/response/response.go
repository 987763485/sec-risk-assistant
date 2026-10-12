// Package response 统一 HTTP 响应封包。
//
// 全系统所有 JSON 响应都遵循同一个信封：
//
//	{ "code": "...", "message": "...", "data": {...}, "request_id": "..." }
//
// 保持单一形状的收益：前端只需要在拦截器里写一次错误分支，
// 而不是每个接口都判断一次响应结构。
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/reqctx"
)

// Envelope 统一响应信封。
type Envelope struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Data      any    `json:"data,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Page 分页数据载体。
type Page[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

// NewPage 构建分页结果。items 为 nil 时替换为空切片，
// 保证 JSON 里是 [] 而不是 null，前端少写一处空值判断。
func NewPage[T any](items []T, total int64, page, pageSize int) Page[T] {
	if items == nil {
		items = []T{}
	}
	return Page[T]{Items: items, Total: total, Page: page, PageSize: pageSize}
}

// OK 返回成功响应。
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Envelope{
		Code:      errcode.CodeOK,
		Message:   "success",
		Data:      data,
		RequestID: reqctx.RequestID(c),
	})
}

// Created 返回 201。
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Envelope{
		Code:      errcode.CodeOK,
		Message:   "created",
		Data:      data,
		RequestID: reqctx.RequestID(c),
	})
}

// NoContent 返回 204（无响应体）。
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Fail 返回错误响应。
//
// 只透出预定义的 message，绝不把 err.Error() 直接回显——
// 数据库错误信息会泄漏表结构与 SQL 片段。
func Fail(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, Envelope{
		Code:      code,
		Message:   message,
		RequestID: reqctx.RequestID(c),
	})
}

// FailWith 返回带结构化明细的错误响应。
//
// 只有极少数错误码需要它——典型场景是批量导入：错误响应必须把
// 「第几行、哪一列、什么值、为什么不合法」一并带回去，前端才能渲染
// 出一张可定位的错误表。把这些塞进 message 会变成一段没法解析的散文。
//
// 注意：带 data 的错误响应在 OpenAPI 契约里由 ErrorDetailEnvelope 描述，
// 普通的 ErrorEnvelope 仍然不含 data —— 不让绝大多数接口的响应形状
// 因为一个特例而变宽。
func FailWith(c *gin.Context, status int, code, message string, data any) {
	c.AbortWithStatusJSON(status, Envelope{
		Code:      code,
		Message:   message,
		Data:      data,
		RequestID: reqctx.RequestID(c),
	})
}

// 以下是高频错误的快捷方法，避免各处重复写状态码与默认文案。

// BadRequest 400
func BadRequest(c *gin.Context, code, message string) {
	Fail(c, http.StatusBadRequest, code, message)
}

// Unauthorized 401
func Unauthorized(c *gin.Context, code, message string) {
	Fail(c, http.StatusUnauthorized, code, message)
}

// Forbidden 403
func Forbidden(c *gin.Context, code, message string) {
	Fail(c, http.StatusForbidden, code, message)
}

// NotFound 404
func NotFound(c *gin.Context, code, message string) {
	Fail(c, http.StatusNotFound, code, message)
}

// Conflict 409
func Conflict(c *gin.Context, code, message string) {
	Fail(c, http.StatusConflict, code, message)
}

// TooManyRequests 429
func TooManyRequests(c *gin.Context, code, message string) {
	Fail(c, http.StatusTooManyRequests, code, message)
}

// Internal 500
func Internal(c *gin.Context) {
	Fail(c, http.StatusInternalServerError, errcode.CodeInternal, "服务器内部错误，请稍后重试")
}
