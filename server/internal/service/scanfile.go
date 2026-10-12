package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/filestore"
	"secrisk/server/internal/pkg/reportparser"
	"secrisk/server/internal/repository"
)

// 上传校验的常量。
const (
	// uploadFileNameMaxRunes 文件名长度上限（进审计与预览）。
	uploadFileNameMaxRunes = 200

	// UploadMaxFileBytes 上传文件体积上限（传输层事实，handler 需要在
	// 读字节之前引用它设置 MaxBytesReader，因此必须是可导出常量）。
	// 默认值与 config storage.max_file_bytes 一致；运行时以 store 的
	// 配置为准，这里只是 handler 的第一道粗筛。
	UploadMaxFileBytes = 10 << 20
)

// allowedExtensions 上传的扩展名白名单。
//
// 白名单而不是黑名单：黑名单永远追不完（.php → .php5 → .phtml），
// 而这里支持的业务格式就四种，多一个都不该收。
var allowedExtensions = map[string]struct{}{
	".nessus": {},
	".xml":    {},
	".xlsx":   {},
	".csv":    {},
}

// mimeWhitelist 上传时允许的 Content-Type。
//
// 这只是三重校验的**第二道**，不是最终裁决：浏览器的 MIME 上报五花八门
// （xlsx 常被报成 application/octet-stream），所以它只要求「不在明显
// 危险的集合里」，真正的格式判定交给魔数。空串也在白名单里——
// 部分客户端不发 Content-Type。
var mimeWhitelist = map[string]struct{}{
	"application/xml":          {},
	"text/xml":                 {},
	"text/plain":               {},
	"text/csv":                 {},
	"application/csv":          {},
	"application/octet-stream": {},
	"application/vnd.ms-excel": {},
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {},
	"application/zip":      {},
	"application/download": {},
	"":                     {},
}

// ScanFileView 扫描文件的对外视图。
type ScanFileView struct {
	ID           uint64  `json:"id"`
	OriginalName string  `json:"original_name"`
	SHA256       string  `json:"sha256"`
	SizeBytes    uint64  `json:"size_bytes"`
	MimeType     string  `json:"mime_type"`
	Format       string  `json:"format"`
	ParseStatus  string  `json:"parse_status"`
	ParsedAt     *string `json:"parsed_at"`
	VulnCount    uint32  `json:"vuln_count"`
	UploadedBy   *uint64 `json:"uploaded_by"`
	UploadedName string  `json:"uploaded_name"`
	CreatedAt    string  `json:"created_at"`
}

// FileService 扫描文件服务：上传、列表、下载、删除。
//
// 解析（preview/commit）也在这个服务上（见 vulnparse.go）：文件与
// 「对文件的解析」是同一个聚合，拆成两个服务只会让两者互相摸对方的内部。
type FileService struct {
	cfg    *config.Config
	repo   *repository.Repository
	store  *filestore.Store
	audit  *auditor
	logger *slog.Logger
}

// NewFileService 构建文件服务。
func NewFileService(
	cfg *config.Config, repo *repository.Repository,
	store *filestore.Store, logger *slog.Logger,
) *FileService {
	if logger == nil {
		logger = slog.Default()
	}
	return &FileService{
		cfg: cfg, repo: repo, store: store,
		audit: newAuditor(repo, logger), logger: logger,
	}
}

// Upload 接收并存储一个上传文件，返回文件记录。
//
// 返回值第二个是 duplicate：同一内容重复上传时返回**已有记录**（幂等），
// 哈希去重的收益是磁盘上同一份报告永远只有一份；「又传了一次」与
// 「查到了同一个文件」对调用方没有区别——拿到 id 后照常进入解析预览。
// 审计里两种情况分开记（file.upload / file.upload_duplicate）。
func (s *FileService) Upload(
	ctx context.Context, principal *auth.Principal, meta RequestMeta,
	fileName, mimeType string, r io.Reader,
) (*ScanFileView, bool, error) {
	saved, err := s.store.Save(r)
	if err != nil {
		if errors.Is(err, filestore.ErrTooLarge) {
			return nil, false, errFileTooLarge(s.store.MaxBytes())
		}
		return nil, false, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "保存上传文件失败", err)
	}

	// 哈希命中：删掉刚落的盘，复用已有记录。
	// 先查再删的顺序不能反——先删后查的中间态里「同一文件不存在任何记录」。
	existing, err := s.repo.ScanFile.FindBySHA256(ctx, saved.SHA256)
	if err == nil {
		_ = s.store.Remove(saved.RelPath)
		view := s.toView(ctx, existing)
		s.audit.record(ctx, auditEntryFor(principal, meta,
			model.ActionFileUploadDuplicate, "scan_file",
			fmt.Sprintf("%d", existing.ID),
			map[string]any{
				"file_name": fileName,
				"sha256":    saved.SHA256,
				"duplicate": true,
			}))
		return view, true, nil
	}
	if !errors.Is(err, repository.ErrScanFileNotFound) {
		return nil, false, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询文件指纹失败", err)
	}

	// 三重校验在这里做：扩展名 → MIME → 魔数，从「最容易被用户理解」
	// 到「最权威」排序。魔数需要内容，此时文件已在磁盘上，读头部即可。
	if err := s.validateUpload(fileName, mimeType, saved.RelPath); err != nil {
		_ = s.store.Remove(saved.RelPath)
		return nil, false, err
	}

	// 格式提前嗅探：只读回前 1 MB，失败不阻塞上传——format 只是
	// 提示信息，解析阶段还会重新判定。
	record := &model.ScanFile{
		SHA256:       saved.SHA256,
		OriginalName: fileName,
		StoragePath:  saved.RelPath,
		SizeBytes:    uint64(saved.Size),
		MimeType:     mimeType,
		Format:       reportparser.DetectFormat(s.peek(saved.RelPath)),
		ParseStatus:  model.ScanParseUnparsed,
	}
	if principal != nil {
		record.UploadedBy = &principal.UserID
	}
	if err := s.repo.ScanFile.Create(ctx, record); err != nil {
		_ = s.store.Remove(saved.RelPath)
		return nil, false, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "写入文件记录失败", err)
	}

	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionFileUpload, "scan_file",
		fmt.Sprintf("%d", record.ID),
		map[string]any{
			"file_name":  fileName,
			"size_bytes": saved.Size,
			"sha256":     saved.SHA256,
		}))

	return s.toView(ctx, record), false, nil
}

// validateUpload 三重校验的编排。
func (s *FileService) validateUpload(fileName, mimeType, relPath string) error {
	ext := strings.ToLower(path.Ext(fileName))
	if _, ok := allowedExtensions[ext]; !ok {
		return errFileTypeRejected(fmt.Sprintf("不支持的文件类型 %q，允许 .nessus / .xml / .xlsx / .csv", ext))
	}
	if _, ok := mimeWhitelist[mimeType]; !ok {
		return errFileTypeRejected(fmt.Sprintf("不允许的内容类型 %q", mimeType))
	}
	return s.validateMagic(relPath, ext)
}

// validateMagic 魔数校验：内容必须与扩展名声明的大类一致。
//
// 不要求「.nessus 的内容一定是合法 Nessus 报告」——那是解析阶段的事；
// 这里只拦「.xlsx 后缀其实是可执行文件」这种伪装。
func (s *FileService) validateMagic(relPath, ext string) error {
	f, err := s.store.Open(relPath)
	if err != nil {
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取上传内容失败", err)
	}
	defer func() { _ = f.Close() }()

	head := make([]byte, 8)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	switch ext {
	case ".xlsx":
		// xlsx 本质是 zip：头四字节 PK\x03\x04。
		if len(head) < 4 || !bytes.Equal(head[:4], []byte{'P', 'K', 0x03, 0x04}) {
			return errFileTypeRejected("文件内容与 .xlsx 不符（不是合法的 Office 工作簿）")
		}
	case ".nessus", ".xml":
		// \uFEFF：部分 Windows 编辑器会在文件头加 BOM。
		trimmed := bytes.TrimLeft(head, " \t\r\n\uFEFF")
		if len(trimmed) == 0 || trimmed[0] != '<' {
			return errFileTypeRejected("文件内容与 XML 不符")
		}
	case ".csv":
		// CSV 是文本：出现 NUL 字节即认定是二进制伪装。
		// 只查头部足够拦住 PE / ELF / zip；全量校验交给解析阶段。
		if bytes.IndexByte(head, 0x00) >= 0 {
			return errFileTypeRejected("文件内容与 CSV 不符（检测到二进制内容）")
		}
	}
	return nil
}

// peek 读回已落盘内容的前 1 MB（供格式嗅探）。
func (s *FileService) peek(relPath string) []byte {
	f, err := s.store.Open(relPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil
	}
	return data
}

// List 分页查询文件。
func (s *FileService) List(
	ctx context.Context, keyword string, parseStatus model.ScanParseStatus,
	page, pageSize int,
) ([]ScanFileView, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	files, total, err := s.repo.ScanFile.List(ctx, repository.ScanFileListQuery{
		Keyword:     keyword,
		ParseStatus: parseStatus,
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		return nil, 0, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询文件列表失败", err)
	}
	views := make([]ScanFileView, 0, len(files))
	for i := range files {
		views = append(views, *s.toView(ctx, &files[i]))
	}
	return views, total, nil
}

// Get 查询单个文件记录。
func (s *FileService) Get(ctx context.Context, id uint64) (*ScanFileView, error) {
	f, err := s.findFile(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.toView(ctx, f), nil
}

// DownloadPayload 下载所需的全部信息。
type DownloadPayload struct {
	View *ScanFileView
	Open io.ReadCloser
}

// Download 打开文件供流式下载。
//
// 响应头（octet-stream / attachment / nosniff）由 handler 设置：
// 那是 HTTP 语义，不是业务规则。
func (s *FileService) Download(ctx context.Context, id uint64) (*DownloadPayload, error) {
	f, err := s.findFile(ctx, id)
	if err != nil {
		return nil, err
	}
	rc, err := s.store.Open(f.StoragePath)
	if err != nil {
		if errors.Is(err, filestore.ErrNotFound) {
			// 记录在、文件不在：残留状态。给用户可行动的错误，
			// 同时把问题暴露在日志里（这种状态不该发生）。
			s.logger.Error("文件记录存在但物理文件缺失",
				"scan_file_id", id, "storage_path", f.StoragePath)
			return nil, newError(http.StatusNotFound, errcode.CodeFileNotFound,
				"文件内容已不存在，请联系管理员清理该记录")
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "打开文件失败", err)
	}
	return &DownloadPayload{View: s.toView(ctx, f), Open: rc}, nil
}

// Delete 删除文件记录与物理文件。
//
// 默认拒绝删除仍有漏洞引用的文件（409 FILE_IN_USE）——漏洞是 P4 评估
// 的输入，文件一删「这些漏洞从哪来」就断了线。force=true 时在一个事务里
// 级联删除该文件解析出的全部漏洞（关联随数据库 CASCADE 清理）。
// 物理文件最后删：数据库回滚时磁盘上多留一份文件无害，反过来则是死链。
func (s *FileService) Delete(
	ctx context.Context, principal *auth.Principal, meta RequestMeta,
	id uint64, force bool,
) error {
	f, err := s.findFile(ctx, id)
	if err != nil {
		return err
	}

	vulnCount, err := s.repo.Vuln.CountByFile(ctx, id)
	if err != nil {
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询文件引用失败", err)
	}
	if vulnCount > 0 && !force {
		return errFileInUse(vulnCount)
	}

	txErr := s.repo.Transaction(ctx, func(tx *repository.Repository) error {
		if vulnCount > 0 {
			if err := tx.DB().WithContext(ctx).
				Where("source_file_id = ?", id).
				Delete(&model.Vulnerability{}).Error; err != nil {
				return fmt.Errorf("删除文件漏洞失败: %w", err)
			}
		}
		return tx.ScanFile.Delete(ctx, id)
	})
	if txErr != nil {
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal, "删除文件失败", txErr)
	}

	if err := s.store.Remove(f.StoragePath); err != nil {
		// 记录已删、文件残留：无害（无人能再引用它），但要留痕。
		s.logger.Error("删除物理文件失败（记录已删，文件残留）",
			"scan_file_id", id, "storage_path", f.StoragePath, "err", err)
	}

	detail := map[string]any{"file_name": f.OriginalName}
	if vulnCount > 0 {
		detail["deleted_vulns"] = vulnCount
		detail["force"] = true
	}
	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionFileDelete, "scan_file", fmt.Sprintf("%d", id), detail))
	return nil
}

// ------------------------------------------------------------------ 内部工具

// findFile 按主键查文件，仓储错误翻译成业务错误。
func (s *FileService) findFile(ctx context.Context, id uint64) (*model.ScanFile, error) {
	f, err := s.repo.ScanFile.FindByID(ctx, id)
	if errors.Is(err, repository.ErrScanFileNotFound) {
		return nil, errFileNotFound()
	}
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询文件失败", err)
	}
	return f, nil
}

// toView 拼装视图（含上传者显示名，便于列表页直接渲染）。
func (s *FileService) toView(ctx context.Context, f *model.ScanFile) *ScanFileView {
	view := &ScanFileView{
		ID:           f.ID,
		OriginalName: f.OriginalName,
		SHA256:       f.SHA256,
		SizeBytes:    f.SizeBytes,
		MimeType:     f.MimeType,
		Format:       string(f.Format),
		ParseStatus:  string(f.ParseStatus),
		VulnCount:    f.VulnCount,
		UploadedBy:   f.UploadedBy,
	}
	if f.ParsedAt != nil {
		t := f.ParsedAt.Format("2006-01-02 15:04:05")
		view.ParsedAt = &t
	}
	view.CreatedAt = f.CreatedAt.Format("2006-01-02 15:04:05")
	if f.UploadedBy != nil {
		if user, err := s.repo.User.FindByID(ctx, *f.UploadedBy); err == nil {
			view.UploadedName = user.DisplayName
		}
	}
	return view
}
