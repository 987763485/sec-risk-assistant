package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// SystemConfigHandler 系统配置接口。
//
// 当前只暴露风险模型相关的配置项（权重与阈值）。做成 /system/configs 而不是
// /system/risk-config：配置表接下来还会承载别的设置，接口形状先按资源的
// 真实边界定，将来加配置项时不需要新增一条路径。
type SystemConfigHandler struct {
	Base
	svc *service.RiskConfigService
}

// NewSystemConfigHandler 构建系统配置接口处理器。
func NewSystemConfigHandler(base Base, svc *service.RiskConfigService) *SystemConfigHandler {
	return &SystemConfigHandler{Base: base, svc: svc}
}

// Get 读取风险模型配置。
func (h *SystemConfigHandler) Get(c *gin.Context) {
	view, err := h.svc.Get(c.Request.Context())
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, view)
}

// Update 更新风险模型配置。
//
// 请求体用嵌套的 thresholds 而不是四个平铺字段：判定「阈值必须严格递减」
// 是一个整体约束，把它们放在同一个对象里，前端在渲染时也更自然地把
// 它们当成一组（同一张卡片里的四个输入框）。
func (h *SystemConfigHandler) Update(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	var req struct {
		AssetWeight *float64 `json:"asset_weight"`
		Thresholds  *struct {
			VeryHigh *int `json:"very_high"`
			High     *int `json:"high"`
			Medium   *int `json:"medium"`
			Low      *int `json:"low"`
		} `json:"thresholds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}

	in := service.UpdateRiskConfigInput{AssetWeight: req.AssetWeight}
	if req.Thresholds != nil {
		in.VeryHigh = req.Thresholds.VeryHigh
		in.High = req.Thresholds.High
		in.Medium = req.Thresholds.Medium
		in.Low = req.Thresholds.Low
	}

	view, err := h.svc.Update(c.Request.Context(), p, requestMeta(c), in)
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}
