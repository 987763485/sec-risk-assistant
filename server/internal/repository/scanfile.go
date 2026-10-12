package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrScanFileNotFound 扫描文件不存在。
var ErrScanFileNotFound = errors.New("repository: 扫描文件不存在")

// ScanFileListQuery 文件列表查询条件。
type ScanFileListQuery struct {
	Keyword     string // 匹配原始文件名
	ParseStatus model.ScanParseStatus
	Page        int
	PageSize    int
}

// ScanFileRepository 扫描文件仓储。
type ScanFileRepository struct{ db *gorm.DB }

// NewScanFileRepository 构建扫描文件仓储。
func NewScanFileRepository(db *gorm.DB) *ScanFileRepository {
	return &ScanFileRepository{db: db}
}

// FindBySHA256 按内容哈希查询。上传去重的判据：命中即幂等返回已有记录。
func (r *ScanFileRepository) FindBySHA256(ctx context.Context, hash string) (*model.ScanFile, error) {
	var f model.ScanFile
	err := r.db.WithContext(ctx).Where("sha256 = ?", hash).Take(&f).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrScanFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按哈希查询文件失败: %w", err)
	}
	return &f, nil
}

// FindByID 按主键查询。
func (r *ScanFileRepository) FindByID(ctx context.Context, id uint64) (*model.ScanFile, error) {
	var f model.ScanFile
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&f).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrScanFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按 ID 查询文件失败: %w", err)
	}
	return &f, nil
}

// Create 新建文件记录。
func (r *ScanFileRepository) Create(ctx context.Context, f *model.ScanFile) error {
	if err := r.db.WithContext(ctx).Create(f).Error; err != nil {
		return fmt.Errorf("创建文件记录失败: %w", err)
	}
	return nil
}

// List 分页查询文件。过滤全部下推 SQL。
func (r *ScanFileRepository) List(ctx context.Context, q ScanFileListQuery) ([]model.ScanFile, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.ScanFile{})

	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		base = base.Where("original_name LIKE ?", "%"+escapeLike(kw)+"%")
	}
	if q.ParseStatus != "" {
		base = base.Where("parse_status = ?", q.ParseStatus)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计文件总数失败: %w", err)
	}

	var files []model.ScanFile
	err := base.Order("id DESC").
		Limit(q.PageSize).
		Offset((q.Page - 1) * q.PageSize).
		Find(&files).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查询文件列表失败: %w", err)
	}
	return files, total, nil
}

// MarkParsed 在事务内更新解析结果：format、状态、条数一次写入。
//
// 单独提供而不是让 service 拿着 *ScanFile 全量 Save：commit 的并发
// 防护依赖这条 UPDATE 的 WHERE parse_status = 'unparsed' 条件——
// 两个并发 commit 只有一个能把状态从 unparsed 改走，后到者影响行数为 0。
func (r *ScanFileRepository) MarkParsed(ctx context.Context, id uint64, format model.ScanFileFormat, vulnCount uint32) (int64, error) {
	now := gorm.Expr("CURRENT_TIMESTAMP(3)")
	res := r.db.WithContext(ctx).Model(&model.ScanFile{}).
		Where("id = ? AND parse_status = ?", id, model.ScanParseUnparsed).
		Updates(map[string]any{
			"format":       string(format),
			"parse_status": string(model.ScanParseParsed),
			"parsed_at":    now,
			"vuln_count":   vulnCount,
		})
	return res.RowsAffected, res.Error
}

// MarkFailed 标记解析失败。
func (r *ScanFileRepository) MarkFailed(ctx context.Context, id uint64, format model.ScanFileFormat) error {
	err := r.db.WithContext(ctx).Model(&model.ScanFile{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"format":       string(format),
			"parse_status": string(model.ScanParseFailed),
		}).Error
	if err != nil {
		return fmt.Errorf("标记解析失败状态失败: %w", err)
	}
	return nil
}

// Delete 删除文件记录。
func (r *ScanFileRepository) Delete(ctx context.Context, id uint64) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.ScanFile{}).Error; err != nil {
		return fmt.Errorf("删除文件记录失败: %w", err)
	}
	return nil
}
