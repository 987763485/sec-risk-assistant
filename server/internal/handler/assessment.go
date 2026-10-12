package handler

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/pkg/riskengine"
	"secrisk/server/internal/service"
)

// AssessmentHandler 风险评估接口。
type AssessmentHandler struct {
	Base
	svc *service.AssessmentService
}

// NewAssessmentHandler 构建评估接口处理器。
func NewAssessmentHandler(base Base, svc *service.AssessmentService) *AssessmentHandler {
	return &AssessmentHandler{Base: base, svc: svc}
}

// List 评估任务列表。
func (h *AssessmentHandler) List(c *gin.Context) {
	page, pageSize := pagination(c)
	q := service.AssessmentListQuery{
		Keyword:  c.Query("keyword"),
		Page:     page,
		PageSize: pageSize,
	}
	if raw := c.Query("status"); raw != "" {
		status := raw
		q.Status = &status
	}

	views, total, err := h.svc.List(c.Request.Context(), q)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, gin.H{"items": views, "total": total})
}

// Get 评估任务详情。
func (h *AssessmentHandler) Get(c *gin.Context) {
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}
	view, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, view)
}

// Create 新建评估任务。
func (h *AssessmentHandler) Create(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	var req struct {
		Name              string   `json:"name"`
		Description       string   `json:"description"`
		ScopeType         string   `json:"scope_type"`
		ScopeRef          []uint64 `json:"scope_ref"`
		DefaultThreatCode string   `json:"default_threat_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Create(c.Request.Context(), p, requestMeta(c), service.CreateAssessmentInput{
		Name:              req.Name,
		Description:       req.Description,
		ScopeType:         req.ScopeType,
		ScopeRef:          req.ScopeRef,
		DefaultThreatCode: req.DefaultThreatCode,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	// 201 Created：资源的创建接口一律 201（同 assets / dictionaries /
	// asset-groups），创建成功后响应体里就是完整可读的评估任务。
	response.Created(c, view)
}

// Update 编辑评估任务。
func (h *AssessmentHandler) Update(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}

	var req struct {
		Name              *string   `json:"name"`
		Description       *string   `json:"description"`
		ScopeType         *string   `json:"scope_type"`
		ScopeRef          *[]uint64 `json:"scope_ref"`
		DefaultThreatCode *string   `json:"default_threat_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Update(c.Request.Context(), p, requestMeta(c), id, service.UpdateAssessmentInput{
		Name:              req.Name,
		Description:       req.Description,
		ScopeType:         req.ScopeType,
		ScopeRef:          req.ScopeRef,
		DefaultThreatCode: req.DefaultThreatCode,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// Delete 删除评估任务。
func (h *AssessmentHandler) Delete(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), p, requestMeta(c), id); err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, nil)
}

// Preview 试算。
//
// 是 POST 但**只读**——用 POST 是因为范围明细是一组 ID，塞进查询串会很长。
// 既然不改任何状态，就不该留下审计记录，否则审计页会被「用户拖动范围
// 试看了三十次」灌满，真正需要留痕的操作反而被淹没。
func (h *AssessmentHandler) Preview(c *gin.Context) {
	var req struct {
		AssessmentID      *uint64                `json:"assessment_id"`
		ScopeType         string                 `json:"scope_type"`
		ScopeRef          []uint64               `json:"scope_ref"`
		DefaultThreatCode string                 `json:"default_threat_code"`
		AssetWeight       *float64               `json:"asset_weight"`
		Thresholds        *riskengine.Thresholds `json:"thresholds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Preview(c.Request.Context(), service.PreviewInput{
		AssessmentID:      req.AssessmentID,
		ScopeType:         req.ScopeType,
		ScopeRef:          req.ScopeRef,
		DefaultThreatCode: req.DefaultThreatCode,
		AssetWeight:       req.AssetWeight,
		Thresholds:        req.Thresholds,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditSkipped(c)
	response.OK(c, view)
}

// Calculate 计算并落库。
func (h *AssessmentHandler) Calculate(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}
	view, err := h.svc.Calculate(c.Request.Context(), p, requestMeta(c), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// RiskItems 风险项分页（矩阵下钻）。
func (h *AssessmentHandler) RiskItems(c *gin.Context) {
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}
	page, pageSize := pagination(c)
	q := service.RiskItemListQuery{
		Keyword:  c.Query("keyword"),
		Page:     page,
		PageSize: pageSize,
	}
	if raw := c.Query("importance"); raw != "" {
		q.Importance = parseUint8Query(raw)
	}
	if raw := c.Query("severity"); raw != "" {
		q.Severity = parseUint8Query(raw)
	}
	if raw := c.Query("level"); raw != "" {
		level := raw
		q.Level = &level
	}

	items, total, err := h.svc.ListRiskItems(c.Request.Context(), id, q)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, gin.H{"items": items, "total": total})
}

// Matrix 风险矩阵。
func (h *AssessmentHandler) Matrix(c *gin.Context) {
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}
	view, err := h.svc.Matrix(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, view)
}

// ExportData 导出报告数据。
func (h *AssessmentHandler) ExportData(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}
	view, err := h.svc.ExportData(c.Request.Context(), p, requestMeta(c), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// SetRiskItemThreat 逐项覆盖风险项的威胁。
func (h *AssessmentHandler) SetRiskItemThreat(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "评估任务")
	if !ok {
		return
	}
	itemID, err := strconv.ParseUint(c.Param("itemId"), 10, 64)
	if err != nil || itemID == 0 {
		h.invalidParam(c, "风险项 ID 非法")
		return
	}

	var req struct {
		ThreatCode string `json:"threat_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.SetRiskItemThreat(c.Request.Context(), p, requestMeta(c),
		id, itemID, req.ThreatCode)
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}
