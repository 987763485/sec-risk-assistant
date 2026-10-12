package handler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/service"
)

// AssetImportHandler 资产批量导入接口。
//
// 三个端点构成一条完整链路：下载模板 → 预览 → 确认导入。
type AssetImportHandler struct {
	Base
	svc *service.AssetService
}

// NewAssetImportHandler 构建资产批量导入接口处理器。
func NewAssetImportHandler(base Base, svc *service.AssetService) *AssetImportHandler {
	return &AssetImportHandler{Base: base, svc: svc}
}

// 上传相关的常量。
const (
	// importUploadLimit multipart 请求体的总量上限。
	//
	// 比文件上限多留 1 MB：multipart 的分隔符与各部分头部会额外占用字节，
	// 卡在文件上限上的话，一个正好 10 MB 的文件会被拦下来，
	// 而用户无法理解「文件明明没超限为什么被拒」。
	importUploadLimit = service.ImportMaxFileBytes + (1 << 20)

	// importFileNameMaxRunes 传给服务层与审计的文件名长度上限。
	// 文件名会进审计明细，不该让一个超长名字撑坏那一格。
	importFileNameMaxRunes = 200

	// xlsxContentType xlsx 的标准 MIME。
	xlsxContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

// Template 下载导入模板。
//
// 这个端点是全系统唯一的**二进制响应**：把 xlsx 塞进统一 JSON 信封的
// data 字段、再让前端 base64 解码，会让「下载一个文件」多绕一大圈，
// 而且契约里也无法表达真实的响应形状。因此契约里这个操作声明的是
// application/vnd.openxmlformats-officedocument.spreadsheetml.sheet。
func (h *AssetImportHandler) Template(c *gin.Context) {
	data, err := h.svc.ImportTemplate(c.Request.Context())
	if err != nil {
		h.fail(c, err)
		return
	}

	// 不缓存：模板里带着当前启用的资产类型清单，字典一改就该跟着变。
	// 缓存住的话，用户会拿着一个引用了已停用类型的旧模板反复导入失败。
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition",
		contentDisposition(service.ImportTemplateFileName, "asset-import-template.xlsx"))
	c.Data(http.StatusOK, xlsxContentType, data)
}

// Preview 解析并校验上传的文件，不写入任何数据。
//
// 声明「不需要审计」：这个接口只能用 POST（要传文件），但它既不落库、
// 也不改变任何状态，因此没有可审计的事件。不声明的话，每一次预览都会
// 被审计中间件当成「漏审计」打一条告警 —— 而那会把真正的漏审计淹掉。
func (h *AssetImportHandler) Preview(c *gin.Context) {
	reqctx.MarkAuditSkipped(c)

	fileName, data, ok := h.readUpload(c)
	if !ok {
		return
	}

	preview, err := h.svc.PreviewImport(c.Request.Context(), fileName, data,
		parseBoolQuery(c.PostForm("create_missing_groups")))
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, preview)
}

// Commit 校验并写入上传的文件。
//
// 任一行不合格时返回 409 且**一条都不写**，错误响应体里带完整的预览结果
// （行号 / 列名 / 原值 / 原因），前端可以直接渲染出与预览阶段一样的错误表。
// 半成功的导入会留下一个无法回答的问题——「台账里现在这批数据到底导完了没」。
func (h *AssetImportHandler) Commit(c *gin.Context) {
	fileName, data, ok := h.readUpload(c)
	if !ok {
		return
	}

	result, err := h.svc.CommitImport(c.Request.Context(), fileName, data,
		parseBoolQuery(c.PostForm("create_missing_groups")),
		h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.OK(c, result)
}

// ------------------------------------------------------------------ 上传读取

// readUpload 从 multipart 请求里取出文件。
//
// 返回 (文件名, 内容, 是否成功)。失败时已经写过响应，调用方直接返回。
//
// 三道防线缺一不可，且它们的顺序是有意的：Content-Length 检查最省事
// （不读字节）但可被伪造；MaxBytesReader 是硬防线；最后那次 LimitReader
// 兜的是「multipart 请求体没超、但文件部分超了」这一种情况。
func (h *AssetImportHandler) readUpload(c *gin.Context) (string, []byte, bool) {
	// 先看 Content-Length：浏览器上传时一定会带，能在读取任何字节之前
	// 就把明显超限的请求挡掉。Attacker 可以不发这个头，因此它只是优化，
	// 真正的防线是下面的 MaxBytesReader。
	if c.Request.ContentLength > importUploadLimit {
		h.fail(c, service.ErrImportFileTooLarge())
		return "", nil, false
	}

	// 真正的防线：在**读取阶段**就设上限。等 io.ReadAll 读完再判断体积时，
	// 内存已经吃掉了——一个几 GB 的上传足以把进程打挂，而这完全取决于
	// 客户端的行为，服务端必须自己兜住。
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, importUploadLimit)

	fh, err := c.FormFile("file")
	if err != nil {
		h.failUpload(c, err)
		return "", nil, false
	}

	src, err := fh.Open()
	if err != nil {
		h.fail(c, fmt.Errorf("打开上传文件失败: %w", err))
		return "", nil, false
	}
	defer func() { _ = src.Close() }()

	// 多读 1 字节：这样「恰好等于上限」与「超过上限」能区分开，
	// 而不会把正好 10 MB 的文件误判成超限。
	data, err := io.ReadAll(io.LimitReader(src, service.ImportMaxFileBytes+1))
	if err != nil {
		h.fail(c, fmt.Errorf("读取上传文件失败: %w", err))
		return "", nil, false
	}
	if int64(len(data)) > service.ImportMaxFileBytes {
		h.fail(c, service.ErrImportFileTooLarge())
		return "", nil, false
	}

	return uploadFileName(fh.Filename), data, true
}

// failUpload 把 multipart 的读取错误翻译成响应。
//
// 「没选文件」与「文件太大」必须分开：前者要用户去选一个文件，后者要用户
// 换一个小一点的文件。两种情况（加上真正的 multipart 损坏）在底层都是
// 一个 FormFile 错误，把用户引向错误方向的提示比没有提示更糟。
func (h *AssetImportHandler) failUpload(c *gin.Context, err error) {
	switch {
	case errors.Is(err, http.ErrMissingFile):
		h.fail(c, service.ErrImportFileMissing())
	case errors.As(err, new(*http.MaxBytesError)):
		h.fail(c, service.ErrImportFileTooLarge())
	default:
		h.invalidParam(c, "上传内容无法解析，请重新选择文件")
	}
}

// uploadFileName 规整上传来的文件名。
//
// 必须取 Base：某些客户端会把整个本地路径放进 filename（旧版 IE 是
// C:\Users\x\资产.xlsx），而这个名字会进预览结果与审计明细——
// 把用户的工作目录写进审计日志没有任何收益。
func uploadFileName(raw string) string {
	name := strings.TrimSpace(filepath.Base(strings.ReplaceAll(raw, "\\", "/")))
	if name == "" || name == "." || name == ".." {
		return "未命名文件"
	}
	if runes := []rune(name); len(runes) > importFileNameMaxRunes {
		return string(runes[:importFileNameMaxRunes])
	}
	return name
}

// contentDisposition 构造能正确传递中文文件名的 Content-Disposition。
//
// 只写 filename="资产导入模板.xlsx" 的话，HTTP 头按规范只能是 Latin-1，
// 中文会被各个浏览器按自己的猜测解码，实际下载下来常常是一串乱码或
// 一个叫 "download" 的文件。因此同时给出 RFC 5987 的 filename*（UTF-8
// 百分号编码），并保留一个纯 ASCII 的 filename 作兜底。
//
// asciiFallback 由调用方给出而不是写死在这里：同一个函数被模板下载、
// 原始文件下载、报告导出三处使用，它们该有的兜底名完全不同。
// 写死过的代价是「下载 Nessus 报告，兜底名却是 asset-import-template.xlsx」——
// 只有在浏览器忽略 filename* 时才会暴露，而那种浏览器越来越少，
// 于是这个错误可以静静地待很久。
func contentDisposition(name, asciiFallback string) string {
	if strings.TrimSpace(asciiFallback) == "" {
		asciiFallback = "download"
	}
	return fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s",
		asciiFallback, rfc5987Encode(name))
}

// rfc5987Encode 按 RFC 5987 的 ext-value 规则做百分号编码。
//
// 不直接用 url.PathEscape：它对子分隔符的处理规则与 RFC 5987 的 attr-char
// 并不一致，结果是否正确要靠查规范才能确认。这里只放行规范的 attr-char，
// 其余一律编码 —— 规则单一、可读，漏编码的后果也只是文件名更长。
//
// 注意按**字节**遍历而不是按 rune：非 ASCII 字符的 UTF-8 编码每个字节
// 都要单独编码成 %XX，这本来就是 filename* 的规则。
func rfc5987Encode(s string) string {
	const attrChar = "!#$&+-.^_`|~"

	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case strings.IndexByte(attrChar, c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
