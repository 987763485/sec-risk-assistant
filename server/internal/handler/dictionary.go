package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// DictionaryHandler 业务字典维护接口。
type DictionaryHandler struct {
	Base
	svc *service.DictionaryService
}

// NewDictionaryHandler 构建字典维护接口处理器。
func NewDictionaryHandler(base Base, svc *service.DictionaryService) *DictionaryHandler {
	return &DictionaryHandler{Base: base, svc: svc}
}

// List 查询字典项。
//
// 两个查询参数：
//
//	category  类别，空表示全部（asset_type / threat / vulnerability / measure）
//	enabled   传 1/true 只返回启用项
//
// **默认返回含停用项的全部**，这一点是刻意的：字典维护页必须看得到停用项，
// 否则一个被停用的类型会从界面上凭空消失，用户既看不到它、也无法重新启用，
// 会以为数据丢了。资产表单则显式传 enabled=1 —— 让「多显示了一条停用项」
// （保存时会被明确拒绝）比「少显示了一条本该有的项」（无从察觉）安全。
func (h *DictionaryHandler) List(c *gin.Context) {
	enabledOnly := parseBoolQuery(c.Query("enabled"))

	items, err := h.svc.List(c.Request.Context(), c.Query("category"), enabledOnly)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, gin.H{"items": items})
}

type createDictionaryRequest struct {
	Category    string   `json:"category"`
	Code        string   `json:"code"`
	Name        string   `json:"name"`
	Weight      *float64 `json:"weight"`
	Description string   `json:"description"`
	SortOrder   *int     `json:"sort_order"`
}

// Create 新建字典项。
func (h *DictionaryHandler) Create(c *gin.Context) {
	var req createDictionaryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Create(c.Request.Context(), service.CreateDictionaryInput{
		Category:    req.Category,
		Code:        req.Code,
		Name:        req.Name,
		Weight:      req.Weight,
		Description: req.Description,
		SortOrder:   req.SortOrder,
	}, h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.Created(c, view)
}

type updateDictionaryRequest struct {
	// Code 允许原样回传（前端编辑表单会带着它提交）；传了不同的值会被明确
	// 拒绝，而不是静默忽略——静默忽略会让用户以为改成功了。
	Code        *string  `json:"code"`
	Name        *string  `json:"name"`
	Weight      *float64 `json:"weight"`
	Description *string  `json:"description"`
	Enabled     *bool    `json:"enabled"`
	SortOrder   *int     `json:"sort_order"`
}

// Update 编辑字典项的名称、权重、说明、启用状态与排序。
func (h *DictionaryHandler) Update(c *gin.Context) {
	id, ok := h.idParam(c, "字典项")
	if !ok {
		return
	}

	var req updateDictionaryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Update(c.Request.Context(), id, service.UpdateDictionaryInput{
		Code:        req.Code,
		Name:        req.Name,
		Weight:      req.Weight,
		Description: req.Description,
		Enabled:     req.Enabled,
		SortOrder:   req.SortOrder,
	}, h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// Delete 删除字典项。
//
// 内置项与仍被资产引用的资产类型会被拒绝，错误提示里指向「停用」这个
// 正确的替代动作。
func (h *DictionaryHandler) Delete(c *gin.Context) {
	id, ok := h.idParam(c, "字典项")
	if !ok {
		return
	}

	if err := h.svc.Delete(c.Request.Context(), id,
		h.principal(c), requestMeta(c)); err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.NoContent(c)
}
