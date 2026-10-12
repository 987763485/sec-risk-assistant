package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/report"
	"secrisk/server/internal/service"
)

// ReportHandler 报告导出接口。
type ReportHandler struct {
	Base
	svc *service.ReportService
}

// NewReportHandler 构建报告接口处理器。
func NewReportHandler(base Base, svc *service.ReportService) *ReportHandler {
	return &ReportHandler{Base: base, svc: svc}
}

// Export 渲染并下载报告文件（word / excel / pdf）。
//
// ▍为什么是 POST + JSON body，而不是 GET + query
//
// 这里下载的是一份**会离开系统边界**的文件，它必须留审计。而用 GET 的话：
//
//   - 浏览器（或聊天软件）里的一个 `<a href=".../reports/export?...">` 链接
//     就能触发一次导出。顶层导航会带上 Cookie（SameSite=Lax 不拦导航），
//     于是一次「点了个不明链接」就变成一条 report.export 审计——而审计里
//     出现没发生过的动作，比漏记一条更糟，它会让人怀疑整套审计的可信度。
//   - CSRF 中间件只保护非安全方法，GET 天然绕过它。
//   - 导出是重操作（起 .NET / Chromium 进程），不该能被预取器、爬虫、
//     浏览器预加载这类东西随手触发。
//
// 换成 POST 后这三件事一起消失：CSRF 中间件生效、链接点不出来、
// 预取器不会发 POST。
func (h *ReportHandler) Export(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	var req struct {
		AssessmentID uint64 `json:"assessment_id"`
		Format       string `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求体格式不正确")
		return
	}
	if req.AssessmentID == 0 {
		h.invalidParam(c, "请指定要导出的评估任务")
		return
	}

	result, err := h.svc.Export(c.Request.Context(), p, requestMeta(c),
		req.AssessmentID, req.Format)
	if err != nil {
		// ⚠️ 这里返回的是 JSON 错误信封，而这个接口成功时返回的是二进制。
		// 前端用 responseType:'blob' 收响应，于是失败时拿到的也是 Blob。
		// 把 Blob 读回 JSON 这件事由 client.ts 的响应拦截器统一做掉
		// （见 parseBlobEnvelope），所以 api 层不用再处理一次 ——
		// 见 web/src/api/reports.ts。
		// 服务端不做「失败时改回 JSON 类型」的特殊处理：Content-Type 由
		// 调用方按状态码判断，比服务端两副面孔更容易处理。
		h.fail(c, err)
		return
	}
	// 审计在 service 层落库（报告导出要记的明细只有那里有），
	// 标注一句以免审计中间件把这次 POST 当成「未记录审计的写操作」告警。
	reqctx.MarkAuditRecorded(c)

	// 文件名走 RFC 5987 的 filename*，并带一个纯 ASCII 兜底名：
	// 评估名称是中文（甚至是用户随手敲的任意字符），而 HTTP 头按规范
	// 只能是 Latin-1。不带 filename* 的话中文名会被各浏览器按自己的
	// 猜测解码，用户下载到的常常是一个叫 "download" 的文件。
	c.Header("Content-Disposition",
		contentDisposition(result.FileName, asciiReportName(result.Format)))

	// 直接写字节而不是 DataFromReader：Content 已在内存里（见 ReportResult），
	// 再包一层 Reader 只是多一次拷贝。
	c.Data(http.StatusOK, result.ContentType, result.Content)
}

// asciiReportName 生成报告下载的 ASCII 兜底名。
//
// 不带评估名（那是中文）也不带时间戳（那不是给人读的）：
// 兜底路径只在浏览器不支持 filename* 时生效，此时唯一重要的是
// 「扩展名对」——操作系统靠它决定用什么程序打开。
func asciiReportName(format report.Format) string {
	switch format {
	case report.FormatWord:
		return "security-assessment-report.docx"
	case report.FormatExcel:
		return "security-assessment-report.xlsx"
	case report.FormatPDF:
		return "security-assessment-report.pdf"
	default:
		return "security-assessment-report.bin"
	}
}
