// Package handler 负责 HTTP 层：参数绑定、调用 service、写响应。
//
// 三条约束：
//  1. 不做业务判断——「最后一个管理员不能移除」这类规则属于 service
//  2. 不碰数据库——一切数据访问经 service → repository
//  3. 不泄漏内部错误——非业务错误统一折叠为 500 与通用文案
package handler

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// 分页参数的默认值与上限。
const (
	defaultPage     = 1
	defaultPageSize = 20
	// maxPageSize 限制单页上限，避免 ?pageSize=100000 这类请求
	// 变成一次计划外的全表导出
	maxPageSize = 100
)

// Base 所有 handler 的公共依赖。
type Base struct {
	Logger *slog.Logger
}

// logger 返回可用日志器。
func (b *Base) logger() *slog.Logger {
	if b.Logger == nil {
		return slog.Default()
	}
	return b.Logger
}

// fail 把 service 错误写成统一响应。
//
// 5xx 时记录完整错误（含底层原因）供排查，但对客户端只返回通用文案——
// 数据库错误信息会泄漏表结构与 SQL 片段。
func (b *Base) fail(c *gin.Context, err error) {
	e := service.AsError(err)

	if e.HTTPStatus >= 500 {
		b.logger().Error("请求处理失败",
			"code", e.Code,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
			"user_id", reqctx.UserID(c),
			"err", e.Err,
			"request_id", reqctx.RequestID(c))
	}

	// 带结构化明细的错误（目前只有批量导入）走另一条写响应路径。
	// 判据是 Data 非 nil 而不是按错误码列举——这样新增一个带明细的错误
	// 不需要回来改这里。
	if e.Data != nil {
		response.FailWith(c, e.HTTPStatus, e.Code, e.Message, e.Data)
		return
	}

	response.Fail(c, e.HTTPStatus, e.Code, e.Message)
}

// requestMeta 收集请求元信息，用于审计与会话记录。
func requestMeta(c *gin.Context) service.RequestMeta {
	return service.RequestMeta{
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		RequestID: reqctx.RequestID(c),
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
	}
}

// pagination 解析分页参数，越界值自动收敛而不是报错。
//
// 选择「自动收敛」而非「返回 400」：分页参数写错不值得打断用户，
// 但也不能让它穿透到 SQL 层造成全表扫描。
func pagination(c *gin.Context) (page, pageSize int) {
	page = clampInt(c.Query("page"), defaultPage, 1, 1_000_000)
	pageSize = clampInt(c.Query("pageSize"), defaultPageSize, 1, maxPageSize)
	return page, pageSize
}

func clampInt(raw string, def, min, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// parseUintQuery 解析无符号整数查询参数，非法值返回 0。
func parseUintQuery(raw string) uint64 {
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// parseBoolQuery 解析布尔查询参数。
//
// 同时接受 1/true/yes 三种写法：查询串是给人手敲的（curl、浏览器地址栏），
// 而「?enabled=1」与「?enabled=true」在不同人手里都会出现。
// 无法识别时返回 false 而不是报错——查询参数写错不值得打断一次列表查询。
func parseBoolQuery(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// parseUint8Query 解析 0–255 的整数查询参数，非法返回 nil（即「不限」）。
func parseUint8Query(raw string) *uint8 {
	n := parseUintQuery(raw)
	if n == 0 || n > 255 {
		return nil
	}
	v := uint8(n)
	return &v
}

// parseTimeQuery 解析时间查询参数。
//
// 同时接受 RFC3339 与 "2006-01-02 15:04:05"，后者是前端日期控件与
// 运维手敲 curl 都更常用的写法。
func parseTimeQuery(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return &t
		}
	}
	return nil
}

// invalidParam 统一的参数错误响应。
func (b *Base) invalidParam(c *gin.Context, message string) {
	response.BadRequest(c, errcode.CodeInvalidParam, message)
}

// principal 返回当前认证主体。
//
// 归一化到认证守卫可拦截的 401：路由装配正确时不会走到这里，
// 但显式处理能让「忘记挂认证中间件」立刻暴露，而不是静默地
// 以匿名身份执行写操作并留下没有操作人的审计记录。
func (b *Base) principal(c *gin.Context) *auth.Principal {
	if p, ok := reqctx.Principal(c); ok {
		return p
	}
	response.Unauthorized(c, errcode.CodeUnauthorized, "未登录，请先登录")
	return nil
}

// idParam 解析路径上的资源 ID。
//
// resource 是给用户看的名词（「资产」「字典项」）。写死成「ID 非法」的话，
// 用户在前端只会看到一句没有主语的提示，不知道是哪个东西的 ID 有问题。
func (b *Base) idParam(c *gin.Context, resource string) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		b.invalidParam(c, resource+" ID 非法")
		return 0, false
	}
	return id, true
}
