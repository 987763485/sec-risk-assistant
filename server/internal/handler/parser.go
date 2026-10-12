package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// ParseHandler 解析接口：模板下载、预览、入库。
type ParseHandler struct {
	Base
	svc *service.FileService
}

// NewParseHandler 构建解析接口处理器。
func NewParseHandler(base Base, svc *service.FileService) *ParseHandler {
	return &ParseHandler{Base: base, svc: svc}
}

// Template 下载漏洞导入模板（通用表格格式的配套）。
func (h *ParseHandler) Template(c *gin.Context) {
	data, err := service.VulnImportTemplate()
	if err != nil {
		h.fail(c, err)
		return
	}
	// 模板是静态内容（列定义编译期固定），可以短缓存；
	// 但 no-store 更省心——模板很小，缓存收益趋近于零。
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition",
		contentDisposition("漏洞导入模板.xlsx", "vuln-import-template.xlsx"))
	c.Data(200, xlsxContentType, data)
}

// Preview 解析文件，不写入任何数据。
//
// 只读操作却必须用 POST（file_id 在请求体里），与资产导入的 preview
// 同属「按设计不该有审计」的第三种情况——不声明的话每次预览都会
// 打一条「未记录审计」告警。
func (h *ParseHandler) Preview(c *gin.Context) {
	reqctx.MarkAuditSkipped(c)

	var req struct {
		FileID uint64 `json:"file_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}
	if req.FileID == 0 {
		h.invalidParam(c, "file_id 不能为空")
		return
	}

	preview, err := h.svc.PreviewParse(c.Request.Context(), req.FileID)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, preview)
}

// Commit 解析入库。
//
// 与 preview 的一个关键差异：commit **不**声明 MarkAuditRecorded——
// 审计由 service 层在事务成功后落库（需要带结果明细），这里什么都不标，
// 审计中间件会看到「已由服务层记录」。
func (h *ParseHandler) Commit(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	var req struct {
		FileID uint64 `json:"file_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}
	if req.FileID == 0 {
		h.invalidParam(c, "file_id 不能为空")
		return
	}

	result, err := h.svc.CommitParse(c.Request.Context(), req.FileID, p, requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, result)
}
