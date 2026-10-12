package handler

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/repository"
)

// auditLogView 审计日志的对外视图。
//
// 单独定义而不是直接返回模型，有两个理由：
//  1. 模型字段不带 json tag，直接序列化会输出 Go 风格的 PascalCase 字段名；
//  2. 对外契约应由接口层决定，模型结构调整不应自动改变 API 响应形状。
type auditLogView struct {
	ID         uint64  `json:"id"`
	UserID     *uint64 `json:"user_id"`
	Username   string  `json:"username"`
	Action     string  `json:"action"`
	Resource   string  `json:"resource"`
	ResourceID string  `json:"resource_id"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	StatusCode int     `json:"status_code"`
	ClientIP   string  `json:"client_ip"`
	UserAgent  string  `json:"user_agent"`
	// Detail 直接透出为 JSON 对象而非字符串，前端无需再 parse 一次
	Detail    json.RawMessage `json:"detail"`
	RequestID string          `json:"request_id"`
	CreatedAt time.Time       `json:"created_at"`
}

func toAuditViews(rows []model.AuditLog) []auditLogView {
	out := make([]auditLogView, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		v := auditLogView{
			ID:         r.ID,
			UserID:     r.UserID,
			Username:   r.Username,
			Action:     r.Action,
			Resource:   r.Resource,
			ResourceID: r.ResourceID,
			Method:     r.Method,
			Path:       r.Path,
			StatusCode: r.StatusCode,
			ClientIP:   r.ClientIP,
			UserAgent:  r.UserAgent,
			RequestID:  r.RequestID,
			CreatedAt:  r.CreatedAt,
		}
		if r.Detail != nil {
			v.Detail = json.RawMessage(*r.Detail)
		}
		out = append(out, v)
	}
	return out
}

// AuditHandler 审计日志查询接口。
//
// 只提供读取，不提供写入与删除：
// 审计记录的写入由中间件与 service 完成，而「可被删除的审计日志」
// 在合规意义上等同于没有审计。
type AuditHandler struct {
	Base
	repo *repository.Repository
}

// NewAuditHandler 构建审计日志接口处理器。
func NewAuditHandler(base Base, repo *repository.Repository) *AuditHandler {
	return &AuditHandler{Base: base, repo: repo}
}

// List 分页查询审计日志。
func (h *AuditHandler) List(c *gin.Context) {
	page, pageSize := pagination(c)

	rows, total, err := h.repo.Audit.List(c.Request.Context(), repository.AuditListQuery{
		Action:   c.Query("action"),
		Resource: c.Query("resource"),
		UserID:   parseUintQuery(c.Query("user_id")),
		StartAt:  parseTimeQuery(c.Query("start_at")),
		EndAt:    parseTimeQuery(c.Query("end_at")),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		// 仓储错误是内部细节，不回显给客户端
		h.fail(c, err)
		return
	}

	response.OK(c, response.NewPage(toAuditViews(rows), total, page, pageSize))
}
