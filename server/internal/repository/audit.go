package repository

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// AuditListQuery 审计日志查询条件。
type AuditListQuery struct {
	Action   string
	Resource string
	UserID   uint64
	StartAt  *time.Time
	EndAt    *time.Time
	Page     int
	PageSize int
}

// AuditRepository 审计日志仓储。
type AuditRepository struct{ db *gorm.DB }

// NewAuditRepository 构建审计日志仓储。
func NewAuditRepository(db *gorm.DB) *AuditRepository { return &AuditRepository{db: db} }

// Create 写入一条审计记录。
func (r *AuditRepository) Create(ctx context.Context, log *model.AuditLog) error {
	if err := r.db.WithContext(ctx).Create(log).Error; err != nil {
		return fmt.Errorf("写入审计日志失败: %w", err)
	}
	return nil
}

// Record 将审计条目落库。实现 middleware.AuditRecorder 与
// service 层共用的写入入口。
func (r *AuditRepository) Record(ctx context.Context, e model.AuditEntry) error {
	log := &model.AuditLog{
		Username:   e.Username,
		Action:     e.Action,
		Resource:   e.Resource,
		ResourceID: e.ResourceID,
		Method:     e.Method,
		Path:       e.Path,
		StatusCode: e.StatusCode,
		ClientIP:   e.ClientIP,
		UserAgent:  e.UserAgent,
		RequestID:  e.RequestID,
	}
	// 匿名操作（UserID=0）必须存 NULL，不能被当作「ID 为 0 的用户」
	if e.UserID > 0 {
		uid := e.UserID
		log.UserID = &uid
	}
	if len(e.Detail) > 0 {
		detail := string(e.Detail)
		log.Detail = &detail
	}

	return r.Create(ctx, log)
}

// BatchCreate 批量写入审计记录。
func (r *AuditRepository) BatchCreate(ctx context.Context, logs []model.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	if err := r.db.WithContext(ctx).CreateInBatches(&logs, 100).Error; err != nil {
		return fmt.Errorf("批量写入审计日志失败: %w", err)
	}
	return nil
}

// List 分页查询审计日志，按时间倒序。
func (r *AuditRepository) List(ctx context.Context, q AuditListQuery) ([]model.AuditLog, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.AuditLog{})

	if q.Action != "" {
		base = base.Where("action = ?", q.Action)
	}
	if q.Resource != "" {
		base = base.Where("resource = ?", q.Resource)
	}
	if q.UserID > 0 {
		base = base.Where("user_id = ?", q.UserID)
	}
	// 时间范围过滤下推 SQL，并走 idx_audit_logs_created_at 索引
	if q.StartAt != nil {
		base = base.Where("created_at >= ?", *q.StartAt)
	}
	if q.EndAt != nil {
		base = base.Where("created_at < ?", *q.EndAt)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计审计日志总数失败: %w", err)
	}

	var rows []model.AuditLog
	err := base.Order("id DESC").
		Limit(q.PageSize).
		Offset((q.Page - 1) * q.PageSize).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查询审计日志失败: %w", err)
	}
	return rows, total, nil
}
