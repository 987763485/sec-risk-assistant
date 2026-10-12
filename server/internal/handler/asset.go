package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/optional"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/repository"
	"secrisk/server/internal/service"
)

// AssetHandler 资产台账接口。
type AssetHandler struct {
	Base
	svc    *service.AssetService
	groups *service.AssetGroupService
}

// NewAssetHandler 构建资产台账接口处理器。
//
// 依赖 AssetGroupService 是因为「按资产组筛选」要把选中的组展开成
// 「自身 + 全部后代」，而那是分组服务的领域规则。
func NewAssetHandler(
	base Base, svc *service.AssetService, groups *service.AssetGroupService,
) *AssetHandler {
	return &AssetHandler{Base: base, svc: svc, groups: groups}
}

// List 分页查询资产。
//
// 查询参数：
//
//	keyword            关键字，匹配名称 / 编号 / IP / 主机名 / 负责人
//	asset_type         资产类型码，精确匹配
//	status             状态码（in_use / idle / offline / scrapped）
//	importance         重要性 1–5
//	group_id           资产组 ID
//	include_children   与 group_id 搭配，是否连子组的资产一起看（默认 true）
//	page / pageSize    分页
func (h *AssetHandler) List(c *gin.Context) {
	page, pageSize := pagination(c)

	status := model.AssetStatus(c.Query("status"))
	if status != "" && !status.Valid() {
		h.invalidParam(c, "status 取值非法，只能是 in_use / idle / offline / scrapped")
		return
	}

	importance := parseUint8Query(c.Query("importance"))
	if importance != nil && !model.ValidImportance(*importance) {
		h.invalidParam(c, "importance 取值非法，只能是 1–5")
		return
	}

	groupID := parseUintQuery(c.Query("group_id"))
	// 默认含子树：用户点中「华东区」时期望看到它下面所有机房的资产。
	// 想要「只看直接挂在这一层」的要显式传 include_children=0。
	includeChildren := true
	if raw := c.Query("include_children"); raw != "" {
		includeChildren = parseBoolQuery(raw)
	}

	groupIDs, err := h.groups.ResolveGroupFilter(c.Request.Context(), groupID, includeChildren)
	if err != nil {
		h.fail(c, err)
		return
	}

	result, err := h.svc.List(c.Request.Context(), repository.AssetListQuery{
		Keyword:    c.Query("keyword"),
		AssetType:  c.Query("asset_type"),
		Status:     status,
		GroupIDs:   groupIDs,
		Importance: importance,
		Page:       page,
		PageSize:   pageSize,
	})
	if err != nil {
		h.fail(c, err)
		return
	}

	response.OK(c, response.NewPage(result.Items, result.Total, result.Page, result.PageSize))
}

// Get 查询单个资产。
func (h *AssetHandler) Get(c *gin.Context) {
	id, ok := h.idParam(c, "资产")
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

type createAssetRequest struct {
	AssetNo     string   `json:"asset_no"`
	Name        string   `json:"name"`
	AssetType   string   `json:"asset_type"`
	GroupID     *uint64  `json:"group_id"`
	IPAddress   string   `json:"ip_address"`
	Port        *uint16  `json:"port"`
	Hostname    string   `json:"hostname"`
	OSType      string   `json:"os_type"`
	Importance  *uint8   `json:"importance"`
	Owner       string   `json:"owner"`
	Department  string   `json:"department"`
	Status      string   `json:"status"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
}

// Create 新建资产。
func (h *AssetHandler) Create(c *gin.Context) {
	var req createAssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Create(c.Request.Context(), service.CreateAssetInput{
		AssetNo:     req.AssetNo,
		Name:        req.Name,
		AssetType:   req.AssetType,
		GroupID:     req.GroupID,
		IPAddress:   req.IPAddress,
		Port:        req.Port,
		Hostname:    req.Hostname,
		OSType:      req.OSType,
		Importance:  req.Importance,
		Owner:       req.Owner,
		Department:  req.Department,
		Status:      req.Status,
		Tags:        req.Tags,
		Description: req.Description,
	}, h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.Created(c, view)
}

// updateAssetRequest 编辑资产入参。
//
// 三个可空字段（资产编号 / 所属资产组 / 端口）用 optional.Value 表达三态：
// 字段缺失 = 不修改，显式 null = 清空，给值 = 设值。用 *T 的话后两者在 Go
// 里都是 nil，「清空端口」就会静默失效——接口一切正常，但用户怎么点都清不掉。
//
// 其余字符串字段用 *string：对它们来说空串天然就是「清空」，没有第三种状态。
type updateAssetRequest struct {
	AssetNo     optional.Value[string] `json:"asset_no"`
	Name        *string                `json:"name"`
	AssetType   *string                `json:"asset_type"`
	GroupID     optional.Value[uint64] `json:"group_id"`
	IPAddress   *string                `json:"ip_address"`
	Port        optional.Value[uint16] `json:"port"`
	Hostname    *string                `json:"hostname"`
	OSType      *string                `json:"os_type"`
	Importance  *uint8                 `json:"importance"`
	Owner       *string                `json:"owner"`
	Department  *string                `json:"department"`
	Status      *string                `json:"status"`
	Tags        *[]string              `json:"tags"`
	Description *string                `json:"description"`
}

// Update 编辑资产。
func (h *AssetHandler) Update(c *gin.Context) {
	id, ok := h.idParam(c, "资产")
	if !ok {
		return
	}

	var req updateAssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Update(c.Request.Context(), id, service.UpdateAssetInput{
		AssetNo:     req.AssetNo,
		Name:        req.Name,
		AssetType:   req.AssetType,
		GroupID:     req.GroupID,
		IPAddress:   req.IPAddress,
		Port:        req.Port,
		Hostname:    req.Hostname,
		OSType:      req.OSType,
		Importance:  req.Importance,
		Owner:       req.Owner,
		Department:  req.Department,
		Status:      req.Status,
		Tags:        req.Tags,
		Description: req.Description,
	}, h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// Delete 删除资产。
//
// 语义是「修正误录入」。资产退役请把状态改成 scrapped —— 台账需要留下
// 「这台机器曾经存在、已于某时退役」这个事实，删掉就丢掉了一段历史。
func (h *AssetHandler) Delete(c *gin.Context) {
	id, ok := h.idParam(c, "资产")
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
