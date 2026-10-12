package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// HeaderRequestID 请求 ID 的透传响应头。
const HeaderRequestID = "X-Request-ID"

// RequestID 为每个请求分配唯一 ID。
//
// 上游（Nginx / 调用方）已带 X-Request-ID 时沿用，否则生成。
// 作用：一次用户操作若涉及 server → docgen → gotenberg 多个服务，
// 可以用同一个 request_id 串起全部日志。
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader(HeaderRequestID)
		if rid == "" {
			rid = uuid.NewString()
		}
		c.Set(ContextKeyRequestID, rid)
		c.Writer.Header().Set(HeaderRequestID, rid)
		c.Next()
	}
}
