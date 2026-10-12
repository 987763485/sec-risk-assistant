package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// DashboardHandler 首页统计接口。
//
// 只有读操作，因此没有审计标注（GET 不进审计），也不取认证主体。
type DashboardHandler struct {
	Base
	svc *service.DashboardService
}

// NewDashboardHandler 构建首页统计处理器。
func NewDashboardHandler(base Base, svc *service.DashboardService) *DashboardHandler {
	return &DashboardHandler{Base: base, svc: svc}
}

// Summary 首页汇总统计。
//
// assessment_id 的三态（刻意用 0 表示「不传」而不是 optional.Value）：
//
//	不传 / 0   取最近一次**已计算**的评估（按 calculated_at 排序，不是 id）
//	>0         取该评估；不存在返回 404；是草稿则风险区块按「尚未计算」返回
//
// 用 0 而非三态类型：这个参数是查询串里的（不是 JSON 体），
// 「不传」天然可以表达成空串，而 0 从来不是合法评估 ID，
// 因此不存在「0 与不传含义不同」的歧义。返回体里会回传实际采用的
// assessments.latest（ID / 名称 / 计算时间），界面必须显示它——
// 同一句「很高风险有多少条」在不同评估口径下是四个不同的数字。
func (h *DashboardHandler) Summary(c *gin.Context) {
	assessmentID := parseUintQuery(c.Query("assessment_id"))

	summary, err := h.svc.Summary(c.Request.Context(), assessmentID)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, summary)
}
