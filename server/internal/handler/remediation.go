package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/optional"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// RemediationHandler 整改跟踪接口。
//
// 八个操作里最需要说明的是两个「看起来像同义词」的端点：
//
//	PATCH /remediations/:id             改字段（标题/说明/结论/负责人/期限）
//	POST  /remediations/:id/transition  状态流转（含必填说明）
//
// 把状态从 PATCH 里拆出来，是因为它们**不是同一件事**：前者改的是
// 「这张单子长什么样」，后者改的是「这张单子走到哪一步了」，且后者写两张表
// （单子 + 流转记录）。混在一起的话审计里只能看到一个 update，
// 「改了个期限」与「把单子打回」再也分不清（见 service/remediation.go）。
type RemediationHandler struct {
	Base
	svc *service.RemediationService
}

// NewRemediationHandler 构建整改跟踪接口处理器。
func NewRemediationHandler(base Base, svc *service.RemediationService) *RemediationHandler {
	return &RemediationHandler{Base: base, svc: svc}
}

// List 整改单列表。
//
// 查询参数的三态约定：
//
//	active=true    只看未闭环（pending / in_progress / resolved）
//	status=closed  只看某一个状态（与 active 同时给出时 active 优先，见下）
//	overdue=true   只看已逾期
//
// active 与 status 同时给出时**以 status 为准**（下面显式把 ActiveOnly 清掉）。
// 两者是「集合」与「元素」的关系：status 已经指名了一个具体状态，
// 再叠一个集合级条件就是自相矛盾（例如 status=accepted 又 active=true）。
// 遇到矛盾条件时无论保留哪一个都会让用户看到「不是他要的结果」而查不出原因，
// 而 status 更精确 —— 就以它为准。
// 前端也据此在选出状态后禁用「未闭环」开关（见 RemediationListView），
// 因此这个组合不会从界面产生，只有直接调接口才会遇到。
func (h *RemediationHandler) List(c *gin.Context) {
	page, pageSize := pagination(c)

	// ActiveOnly 只在显式写了真值时才置位。刻意不写成
	// 「c.Query("active") != "false"」式的默认开启：那会让
	// 「不传」与「传 false」在列表页产生两种默认口径。
	q := service.ListRemediationQuery{
		Keyword:    c.Query("keyword"),
		ActiveOnly: parseBoolQuery(c.Query("active")),
		Overdue:    parseBoolQuery(c.Query("overdue")),
		Page:       page,
		PageSize:   pageSize,
	}
	if raw := c.Query("status"); raw != "" {
		status := raw
		q.Status = &status
		q.ActiveOnly = false
	}
	if raw := c.Query("assignee_id"); raw != "" {
		n := parseUintQuery(raw)
		q.AssigneeID = &n
	}
	if raw := c.Query("level"); raw != "" {
		level := raw
		q.Level = &level
	}
	if raw := c.Query("assessment_id"); raw != "" {
		n := parseUintQuery(raw)
		q.AssessmentID = &n
	}

	views, total, err := h.svc.List(c.Request.Context(), q)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, gin.H{"items": views, "total": total})
}

// Get 整改单详情（含完整流转时间线）。
func (h *RemediationHandler) Get(c *gin.Context) {
	id, ok := h.idParam(c, "整改单")
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

// Create 建单。
//
// risk_item_id 必填而不是 asset_id + vuln_id：整改单要有风险等级与风险值，
// 而这两者只有风险项才有。原因详见 service.CreateRemediationInput 的注释。
func (h *RemediationHandler) Create(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	var req struct {
		RiskItemID  uint64  `json:"risk_item_id"`
		Title       string  `json:"title"`
		Description string  `json:"description"`
		AssigneeID  *uint64 `json:"assignee_id"`
		// DueDate 形如 2026-11-01；空串 = 不设期限（不是「清空」，
		// 新建时两者等价，因此这里不复用 optional.Value）。
		DueDate string `json:"due_date"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Create(c.Request.Context(), p, requestMeta(c), service.CreateRemediationInput{
		RiskItemID:  req.RiskItemID,
		Title:       req.Title,
		Description: req.Description,
		AssigneeID:  req.AssigneeID,
		DueDate:     req.DueDate,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.Created(c, view)
}

// BatchCreate 按评估任务批量建单。
//
// 与单张建单是**两种不同语义**：单张重复建单返回 409，批量则静默跳过
// 已有未闭环单的条数（结果里的 skipped）。理由是批量建单的典型用法是
// 「算完一次评估后把高风险的都开一次单」，用户会在评估重算后再点一次——
// 若那时整批失败，这个功能就没法用了。
func (h *RemediationHandler) BatchCreate(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	var req struct {
		AssessmentID uint64   `json:"assessment_id"`
		Levels       []string `json:"levels"`
		DueInDays    *int     `json:"due_in_days"`
		AssigneeID   *uint64  `json:"assignee_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	result, err := h.svc.BatchCreate(c.Request.Context(), p, requestMeta(c),
		service.BatchCreateRemediationInput{
			AssessmentID: req.AssessmentID,
			Levels:       req.Levels,
			DueInDays:    req.DueInDays,
			AssigneeID:   req.AssigneeID,
		})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, result)
}

// Update 改字段（不含状态）。
//
// assignee_id 与 due_date 用 optional.Value 表达三态：
//
//	不传   不动
//	null   清空（取消分派 / 去掉期限）
//	有值   改为该值
//
// 用 *uint64 / *string 只能表达两态，「取消分派」与「不修改」在 Go 里
// 都是 nil，于是清空操作怎么点都不生效而接口看起来一切正常。
func (h *RemediationHandler) Update(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "整改单")
	if !ok {
		return
	}

	var req struct {
		Title       *string                `json:"title"`
		Description *string                `json:"description"`
		Resolution  *string                `json:"resolution"`
		AssigneeID  optional.Value[uint64] `json:"assignee_id"`
		DueDate     optional.Value[string] `json:"due_date"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Update(c.Request.Context(), p, requestMeta(c), id,
		service.UpdateRemediationInput{
			Title:       req.Title,
			Description: req.Description,
			Resolution:  req.Resolution,
			AssigneeID:  req.AssigneeID,
			DueDate:     req.DueDate,
		})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// Transition 状态流转。
//
// 这里**不做任何状态机判断**：合法目标、必填说明全部由 service 决定。
// 前端要渲染哪些按钮，走详情/列表视图里的 transitions 字段（后端投影），
// 因此「界面允许但接口拒绝」在结构上不可能出现。
func (h *RemediationHandler) Transition(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "整改单")
	if !ok {
		return
	}

	var req struct {
		ToStatus string `json:"to_status"`
		Note     string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Transition(c.Request.Context(), p, requestMeta(c), id,
		service.TransitionRemediationInput{
			ToStatus: req.ToStatus,
			Note:     req.Note,
		})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// Delete 删除整改单。
//
// 限制（只有「待处理」且从未流转过的单子可删）由 service 判断并返回 409，
// 文案里会给出替代动作（改成「风险接受」）。
func (h *RemediationHandler) Delete(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "整改单")
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
