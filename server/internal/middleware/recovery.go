package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// Recovery 捕获 panic，记录堆栈并返回统一错误结构。
//
// 关键点：响应体里**不回传 panic 详情**（可能含 SQL、路径等敏感信息），
// 只回传 request_id，让运维凭 request_id 到日志里查完整堆栈。
func Recovery(logger *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, recovered any) {
		logger.Error("捕获 panic 并已恢复",
			slog.String("request_id", GetRequestID(c)),
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Any("panic", recovered),
			slog.String("stack", string(debug.Stack())),
		)

		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"code":       "INTERNAL_ERROR",
			"message":    "服务器内部错误",
			"request_id": GetRequestID(c),
		})
	})
}
