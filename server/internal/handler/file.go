package handler

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// FileHandler 扫描文件接口：上传、列表、详情、下载、删除。
type FileHandler struct {
	Base
	svc *service.FileService
}

// NewFileHandler 构建文件接口处理器。
func NewFileHandler(base Base, svc *service.FileService) *FileHandler {
	return &FileHandler{Base: base, svc: svc}
}

// fileUploadLimit multipart 请求体总量上限：文件上限 + 1 MB 分隔符余量
// （理由见 assetimport.go 的 importUploadLimit）。
const fileUploadLimit = service.UploadMaxFileBytes + (1 << 20)

// Upload 上传扫描报告。
//
// 审计由服务层落库（file.upload / file.upload_duplicate —— 两种情况分开记，
// 才能回答「这份报告被谁传过几次」）。这里必须**声明**这一点，否则审计
// 中间件会把这次成功的写操作当成「没有任何审计路径」并打 WARN。
func (h *FileHandler) Upload(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}

	if c.Request.ContentLength > fileUploadLimit {
		h.fail(c, service.ErrFileTooLarge())
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, fileUploadLimit)

	fh, err := c.FormFile("file")
	if err != nil {
		h.failUpload(c, err)
		return
	}
	src, err := fh.Open()
	if err != nil {
		h.fail(c, fmt.Errorf("打开上传文件失败: %w", err))
		return
	}
	defer func() { _ = src.Close() }()

	view, duplicate, err := h.svc.Upload(
		c.Request.Context(), p, requestMeta(c),
		uploadFileName(fh.Filename), fh.Header.Get("Content-Type"), src,
	)
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, gin.H{
		"file":      view,
		"duplicate": duplicate,
	})
}

// List 文件列表。
func (h *FileHandler) List(c *gin.Context) {
	page, pageSize := pagination(c)
	views, total, err := h.svc.List(c.Request.Context(),
		c.Query("keyword"), model.ScanParseStatus(c.Query("parse_status")),
		page, pageSize)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, gin.H{"items": views, "total": total})
}

// Get 文件详情。
func (h *FileHandler) Get(c *gin.Context) {
	id, ok := h.idParam(c, "文件")
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

// Download 下载文件内容。
//
// 这是全系统第二个二进制响应端点（第一个是导入模板）。响应头三件套
// 是下载安全的关键：octet-stream 阻止浏览器按内容嗅探执行、attachment
// 强制下载而不是内联渲染、nosniff 关掉 MIME 嗅探。
func (h *FileHandler) Download(c *gin.Context) {
	id, ok := h.idParam(c, "文件")
	if !ok {
		return
	}
	payload, err := h.svc.Download(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	defer func() { _ = payload.Open.Close() }()

	c.Header("Content-Disposition",
		contentDisposition(payload.View.OriginalName, asciiDownloadName(payload.View.OriginalName)))
	c.Header("X-Content-Type-Options", "nosniff")
	c.DataFromReader(http.StatusOK, int64(payload.View.SizeBytes),
		"application/octet-stream", payload.Open, nil)
}

// asciiDownloadName 由原始文件名派生一个纯 ASCII 的兜底下载名。
//
// 保留扩展名：filename* 被忽略时（老浏览器、部分下载工具），
// 兜底名是用户拿到的**唯一**名字，丢掉扩展名会让一个 .nessus 报告
// 变成没有后缀的文件，双击打不开也认不出类型。
//
// 扩展名必须先验再说：这个串要进 HTTP 响应头，而 original_name 是
// 用户上传时提供的。一个叫 `x."\r\nSet-Cookie: a=b` 的文件名里的
// 「扩展名」就是一段攻击载荷。因此只放行「点 + 1..10 位 ASCII 字母数字」，
// 其余一律退回不带扩展名的 download。
func asciiDownloadName(original string) string {
	ext := strings.ToLower(filepath.Ext(original))
	if len(ext) < 2 || len(ext) > 11 {
		return "download"
	}
	for i := 1; i < len(ext); i++ {
		c := ext[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return "download"
		}
	}
	return "download" + ext
}

// Delete 删除文件。
//
// 删除是写操作且会级联删漏洞（force 时），必须落审计——但审计中间件
// 只记录「有标注的路由」，删除动作本身在 service 层落库（与资产删除同构），
// 这里标注「已由服务层记录」以免审计中间件告警。
func (h *FileHandler) Delete(c *gin.Context) {
	p := h.principal(c)
	if p == nil {
		return
	}
	id, ok := h.idParam(c, "文件")
	if !ok {
		return
	}
	force := parseBoolQuery(c.Query("force"))

	if err := h.svc.Delete(c.Request.Context(), p, requestMeta(c), id, force); err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, nil)
}

// failUpload 把 multipart 读取错误翻译成响应（与资产导入的语义一致，
// 但错误码体系换成 file.* 那组——同一个「没选文件」在两个业务里
// 各有各的码，契约才能分别描述）。
func (h *FileHandler) failUpload(c *gin.Context, err error) {
	switch err.(type) {
	case *http.MaxBytesError:
		h.fail(c, service.ErrFileTooLarge())
	default:
		h.fail(c, service.ErrFileMissing())
	}
}
