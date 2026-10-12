package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// AssetGroupHandler 资产分组接口。
type AssetGroupHandler struct {
	Base
	svc *service.AssetGroupService
}

// NewAssetGroupHandler 构建资产分组接口处理器。
func NewAssetGroupHandler(base Base, svc *service.AssetGroupService) *AssetGroupHandler {
	return &AssetGroupHandler{Base: base, svc: svc}
}

// Tree 返回完整的资产组树。
//
// 一次返回整棵树（接口里没有分页参数，也不打算有）：资产组的规模是
// 「一个企业的组织架构」，几十到几百个节点；而界面上的树控件、分组下拉、
// 移动对话框三处都需要完整的父子关系，懒加载只会让这三处各写一遍
// 「展开时再拉一层」的逻辑。真正可能变多的是资产，那个走分页。
func (h *AssetGroupHandler) Tree(c *gin.Context) {
	items, err := h.svc.Tree(c.Request.Context())
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, gin.H{"items": items})
}

type createAssetGroupRequest struct {
	ParentID    *uint64 `json:"parent_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	SortOrder   *int    `json:"sort_order"`
}

// Create 新建资产组。
func (h *AssetGroupHandler) Create(c *gin.Context) {
	var req createAssetGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Create(c.Request.Context(), service.CreateAssetGroupInput{
		ParentID:    req.ParentID,
		Name:        req.Name,
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

type updateAssetGroupRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	SortOrder   *int    `json:"sort_order"`
}

// Update 编辑资产组的名称、说明与排序。
//
// 这里**不能**改 parent_id：移动是独立端点（POST /asset-groups/{id}/move）。
// 混在一起的话，「把组移到根」与「不移动」在 JSON 里都是 parent_id 缺失，
// 无法区分——除非引入 0 这个需要额外解释的魔法值。
func (h *AssetGroupHandler) Update(c *gin.Context) {
	id, ok := h.idParam(c, "资产组")
	if !ok {
		return
	}

	var req updateAssetGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Update(c.Request.Context(), id, service.UpdateAssetGroupInput{
		Name:        req.Name,
		Description: req.Description,
		SortOrder:   req.SortOrder,
	}, h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

type moveAssetGroupRequest struct {
	// ParentID 目标父组。null（或字段缺失）表示移到根。
	//
	// 这里不需要三态：对「移动」这个动作来说，「没说移到哪」与
	// 「移到根」是同一件事，不存在「不修改父组」这个选项。
	ParentID *uint64 `json:"parent_id"`
}

// Move 移动资产组到新的父组下。
func (h *AssetGroupHandler) Move(c *gin.Context) {
	id, ok := h.idParam(c, "资产组")
	if !ok {
		return
	}

	var req moveAssetGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Move(c.Request.Context(), id, req.ParentID,
		h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// Delete 删除资产组。
//
// 仍有子组或（含子树的）资产时会被拒绝——错误响应里会带上具体数量，
// 前端据此告诉用户「先挪走 12 条资产」，而不是只报「删除失败」。
func (h *AssetGroupHandler) Delete(c *gin.Context) {
	id, ok := h.idParam(c, "资产组")
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
