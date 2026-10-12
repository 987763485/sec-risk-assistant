package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/optional"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// IntegrationHandler 三方情报源接口。
//
// 五个操作里最需要说明的是权限的分工（见 router 的挂载点）：
//
//	GET   /integrations            读配置       integration:read
//	POST  /integrations            建配置       system:write
//	GET   /integrations/:id        读单个       integration:read
//	PATCH /integrations/:id        改配置       system:write
//	POST  /integrations/:id/fetch  触发拉取     integration:write
//
// 建与改挂 system:write 而**不是** integration:write，是本模块的核心决策：
// 改 base_url 决定的是「这台服务器接下来会向哪里发起请求」，
// 那是系统设置（与改风险模型阈值同级），不是业务动作。
// 若把它挂在 integration:write 上，那么「给评估员开拉取权限」
// 就等于同时把「指定出站目标」的能力交给了他——那正是 SSRF 的入口。
type IntegrationHandler struct {
	Base
	svc *service.IntegrationService
}

// NewIntegrationHandler 构建情报源接口处理器。
func NewIntegrationHandler(base Base, svc *service.IntegrationService) *IntegrationHandler {
	return &IntegrationHandler{Base: base, svc: svc}
}

// List 集成列表。
//
// 不分页：集成是运维配置，数量以个数计（现实里几十条已属很多），
// 而配置页需要一次看到全部才能判断「有没有配重」。
// 响应里一并下发 supported_types 与 credential_env_prefix，
// 前端据此渲染下拉框与前缀提示——避免在前端硬编码这两份后端事实。
func (h *IntegrationHandler) List(c *gin.Context) {
	view, err := h.svc.List(c.Request.Context())
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, view)
}

// Get 单个集成的详情。
func (h *IntegrationHandler) Get(c *gin.Context) {
	id, ok := h.idParam(c, "集成")
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

// Create 新建集成。
func (h *IntegrationHandler) Create(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	var req struct {
		Name          string `json:"name"`
		Type          string `json:"type"`
		BaseURL       string `json:"base_url"`
		CredentialEnv string `json:"credential_env"`
		Enabled       *bool  `json:"enabled"`
		TimeoutMS     *int   `json:"timeout_ms"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Create(c.Request.Context(), p, requestMeta(c), service.CreateIntegrationInput{
		Name:          req.Name,
		Type:          req.Type,
		BaseURL:       req.BaseURL,
		CredentialEnv: req.CredentialEnv,
		Enabled:       req.Enabled,
		TimeoutMS:     req.TimeoutMS,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.Created(c, view)
}

// Update 修改集成配置。
//
// credential_env 用 optional.Value 表达三态：
//
//	不传   不动
//	null   清空（不再使用凭据）
//	有值   改为该变量名
//
// 「清空凭据」是一个真实且常见的操作（换用免凭据的上游），
// 用 *string 时它与「不修改」在 Go 里都是 nil，于是怎么点都不生效。
func (h *IntegrationHandler) Update(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "集成")
	if !ok {
		return
	}

	var req struct {
		Name          *string                `json:"name"`
		Type          *string                `json:"type"`
		BaseURL       *string                `json:"base_url"`
		CredentialEnv optional.Value[string] `json:"credential_env"`
		Enabled       *bool                  `json:"enabled"`
		TimeoutMS     *int                   `json:"timeout_ms"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	view, err := h.svc.Update(c.Request.Context(), p, requestMeta(c), id,
		service.UpdateIntegrationInput{
			Name:          req.Name,
			Type:          req.Type,
			BaseURL:       req.BaseURL,
			CredentialEnv: req.CredentialEnv,
			Enabled:       req.Enabled,
			TimeoutMS:     req.TimeoutMS,
		})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

// FetchIntel 对一个漏洞触发一次情报拉取（P7 的验收标志所在）。
//
// 这里**不做任何业务判断**：是否启用、类型是否支持、CVE 是否属于该漏洞、
// 出站地址是否允许、凭据是否就位，全部由 service 决定。
// handler 只负责把请求体解出来。
func (h *IntegrationHandler) FetchIntel(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "集成")
	if !ok {
		return
	}

	var req struct {
		VulnID uint64 `json:"vuln_id"`
		// CVEID 可选。留空表示拉取该漏洞挂的全部 CVE（受单次上限约束）。
		CVEID string `json:"cve_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}
	if req.VulnID == 0 {
		h.invalidParam(c, "vuln_id 不能为空")
		return
	}

	result, err := h.svc.FetchIntel(c.Request.Context(), p, requestMeta(c), id,
		service.FetchIntelInput{VulnID: req.VulnID, CVEID: req.CVEID})
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	// ⚠️ 恒定 200，包括「全部失败」的情况：拉取天生是部分成功的，
	// 调用方必须读 succeeded / failed，不能只看状态码（见 FetchIntelResult）。
	response.OK(c, result)
}
