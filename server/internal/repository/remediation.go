package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrRemediationNotFound 整改单不存在。
var ErrRemediationNotFound = errors.New("repository: 整改单不存在")

// TargetKey 整改单的业务身份：资产 × 漏洞（见迁移 000007 约束 1）。
type TargetKey struct {
	AssetID uint64
	VulnID  uint64
}

// RemediationListQuery 整改单列表查询条件。
type RemediationListQuery struct {
	Keyword string
	// Status 精确匹配单个状态；Statuses 匹配多个（列表页的「未闭环」= 三个状态）。
	// 两者同时给出时 Statuses 优先——用 Statuses 表达「多个」比让调用方
	// 自己拼 SQL 片段安全得多。
	Status     *string
	Statuses   []string
	AssigneeID *uint64
	Level      *string
	// AssessmentID 按**发现出处**过滤（「这次评估发现的问题整改得怎么样了」）。
	AssessmentID *uint64
	// Overdue=true 只返回逾期单：due_date 非空且早于 Today，且未闭环。
	Overdue bool
	// Today 是「逾期」判定的唯一时间基准，由 service 层给出。
	//
	// ⚠️ 刻意不用 SQL 的 CURDATE()：那会让「今天」有两个来源
	// （Go 进程时区 vs MySQL 会话时区），两者不一致时同一个单子在
	// 列表页与仪表盘上会一个「逾期」一个「不逾期」——而两个页面各自
	// 都自洽，只有对着看才发现对不上。
	Today    time.Time
	Page     int
	PageSize int
}

// StatusCount 按状态聚合的结果。
type StatusCount struct {
	Status string `gorm:"column:status"`
	Count  int64  `gorm:"column:cnt"`
}

// RemediationRepository 整改单仓储。
type RemediationRepository struct{ db *gorm.DB }

// NewRemediationRepository 构建整改单仓储。
func NewRemediationRepository(db *gorm.DB) *RemediationRepository {
	return &RemediationRepository{db: db}
}

// ---------------------------------------------------------------- 整改单

// Create 新建整改单。
//
// 可能返回唯一索引冲突（同一 (资产, 漏洞) 已存在未闭环单）——
// 这里**不**翻译成业务错误，因为「重复」在不同调用点含义不同：
// 单张建单要报 409，批量建单要跳过。翻译交给 service 层。
func (r *RemediationRepository) Create(ctx context.Context, m *model.Remediation) error {
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("创建整改单失败: %w", err)
	}
	return nil
}

// FindByID 按主键查询整改单。
func (r *RemediationRepository) FindByID(ctx context.Context, id uint64) (*model.Remediation, error) {
	var m model.Remediation
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRemediationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询整改单失败: %w", err)
	}
	return &m, nil
}

// FindActiveByTarget 查询某 (资产, 漏洞) 当前**未闭环**的整改单。
//
// 未找到时返回 ErrRemediationNotFound —— 对调用方而言
// 「没有未闭环的单」与「单子不存在」是同一件事。
func (r *RemediationRepository) FindActiveByTarget(
	ctx context.Context, assetID, vulnID uint64,
) (*model.Remediation, error) {
	var m model.Remediation
	err := r.db.WithContext(ctx).
		Where("asset_id = ? AND vuln_id = ? AND status IN ?",
			assetID, vulnID, remediationStatusStrings(model.RemediationActiveStatuses)).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRemediationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询未闭环整改单失败: %w", err)
	}
	return &m, nil
}

// ActiveByTargets 批量查询给定 (资产, 漏洞) 对里**已有未闭环单**的那些。
//
// 批量建单要用它做「已建单则跳过」的幂等判断，一次查询解决，
// 而不是对每一对都查一次（5000 条风险项就是 5000 次往返）。
//
// 过滤条件仍然下推到 SQL（asset_id IN ? + status IN ?，两者都有索引），
// 不在应用层捞全表再筛。
func (r *RemediationRepository) ActiveByTargets(
	ctx context.Context, assetIDs []uint64,
) (map[TargetKey]model.Remediation, error) {
	out := make(map[TargetKey]model.Remediation)
	if len(assetIDs) == 0 {
		return out, nil
	}

	for _, batch := range chunkUint64(assetIDs, inBatchSize) {
		var rows []model.Remediation
		err := r.db.WithContext(ctx).
			Where("asset_id IN ? AND status IN ?",
				batch, remediationStatusStrings(model.RemediationActiveStatuses)).
			Find(&rows).Error
		if err != nil {
			return nil, fmt.Errorf("批量查询未闭环整改单失败: %w", err)
		}
		for _, row := range rows {
			out[TargetKey{AssetID: row.AssetID, VulnID: row.VulnID}] = row
		}
	}
	return out, nil
}

// List 分页查询整改单。
//
// 排序：**期限近的排前面，未设期限的排最后**，同一天按 ID 倒序。
//
// 为什么不按创建时间倒序：整改单列表是一个**工作清单**，用户打开它
// 是为了知道「先处理哪个」。按创建时间排会让三个月前逾期的单子沉到底下，
// 而它恰恰是最该被看见的那一条。
func (r *RemediationRepository) List(
	ctx context.Context, q RemediationListQuery,
) ([]model.Remediation, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.Remediation{})

	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		like := "%" + escapeLike(kw) + "%"
		base = base.Where(
			"(title LIKE ? OR asset_name LIKE ? OR asset_ip LIKE ? OR vuln_title LIKE ? OR vuln_cve_ids LIKE ?)",
			like, like, like, like, like)
	}
	base = applyStatusFilter(base, q.Status, q.Statuses)
	if q.AssigneeID != nil {
		base = base.Where("assignee_id = ?", *q.AssigneeID)
	}
	if q.Level != nil {
		base = base.Where("risk_level = ?", *q.Level)
	}
	if q.AssessmentID != nil {
		base = base.Where("assessment_id = ?", *q.AssessmentID)
	}
	if q.Overdue {
		base = base.Where("due_date IS NOT NULL AND due_date < ? AND status IN ?",
			startOfDay(q.Today), remediationStatusStrings(model.RemediationActiveStatuses))
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计整改单总数失败: %w", err)
	}

	var rows []model.Remediation
	err := base.Order("(due_date IS NULL) ASC, due_date ASC, id DESC").
		Limit(q.PageSize).
		Offset((q.Page - 1) * q.PageSize).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查询整改单列表失败: %w", err)
	}
	return rows, total, nil
}

// Update 更新整改单的指定列。
func (r *RemediationRepository) Update(ctx context.Context, id uint64, fields map[string]any) error {
	err := r.db.WithContext(ctx).Model(&model.Remediation{}).
		Where("id = ?", id).Updates(fields).Error
	if err != nil {
		return fmt.Errorf("更新整改单失败: %w", err)
	}
	return nil
}

// Delete 删除整改单。remediation_logs 由外键 CASCADE 清理。
func (r *RemediationRepository) Delete(ctx context.Context, id uint64) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).
		Delete(&model.Remediation{}).Error; err != nil {
		return fmt.Errorf("删除整改单失败: %w", err)
	}
	return nil
}

// ------------------------------------------------------------ 流转记录

// CreateLog 追加一条整改单记录。
func (r *RemediationRepository) CreateLog(ctx context.Context, l *model.RemediationLog) error {
	if err := r.db.WithContext(ctx).Create(l).Error; err != nil {
		return fmt.Errorf("写入整改单记录失败: %w", err)
	}
	return nil
}

// ListLogs 取某整改单的全部记录，按时间正序（时间线读法）。
//
// 排序键用 id 而不是 created_at：同一事务里写入的多条记录可能落在
// 同一毫秒，时间戳相同时顺序不定，而时间线必须有**全序**。
func (r *RemediationRepository) ListLogs(
	ctx context.Context, remediationID uint64,
) ([]model.RemediationLog, error) {
	var rows []model.RemediationLog
	err := r.db.WithContext(ctx).Model(&model.RemediationLog{}).
		Where("remediation_id = ?", remediationID).
		Order("id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询整改单记录失败: %w", err)
	}
	return rows, nil
}

// CountTransitionLogs 统计某整改单的**状态流转**记录条数。
//
// 用来判断「能否删除」：一次都没流转过的单子才允许删（见 docs/13 D7）。
// 只数字段变更（update）不算流转——改错了负责人不该让单子变成删不掉的。
func (r *RemediationRepository) CountTransitionLogs(
	ctx context.Context, remediationID uint64,
) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&model.RemediationLog{}).
		Where("remediation_id = ? AND action = ?", remediationID, model.RemediationLogTransition).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("统计整改单流转记录失败: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------- 统计

// StatusCounts 按状态统计整改单数量（仪表盘用）。
//
// 返回**只含出现的状态**；补零由 service 层做——仪表盘的固定形状
// 属于「怎么展示」，不是数据访问的职责。
func (r *RemediationRepository) StatusCounts(ctx context.Context) ([]StatusCount, error) {
	var rows []StatusCount
	err := r.db.WithContext(ctx).Model(&model.Remediation{}).
		Select("status, COUNT(*) AS cnt").
		Group("status").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("统计整改单状态分布失败: %w", err)
	}
	return rows, nil
}

// CountOverdue 统计逾期未闭环的整改单数量。
func (r *RemediationRepository) CountOverdue(ctx context.Context, today time.Time) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&model.Remediation{}).
		Where("due_date IS NOT NULL AND due_date < ? AND status IN ?",
			startOfDay(today), remediationStatusStrings(model.RemediationActiveStatuses)).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("统计逾期整改单失败: %w", err)
	}
	return n, nil
}

// CountDueWithin 统计未来 days 天内到期（含今天）且未闭环的整改单数量。
//
// 区间是闭区间 [today, today+days]：**今天到期**属于「即将到期」，
// 不属于「已逾期」（逾期的判据是严格早于今天）。两个口径贴在一天的两侧，
// 不能重叠，否则同一个单子会同时出现在「逾期」与「即将到期」两个数字里，
// 而用户会以为有两张单子。
func (r *RemediationRepository) CountDueWithin(
	ctx context.Context, today time.Time, days int,
) (int64, error) {
	from := startOfDay(today)
	to := from.AddDate(0, 0, days)

	var n int64
	err := r.db.WithContext(ctx).Model(&model.Remediation{}).
		Where("due_date IS NOT NULL AND due_date >= ? AND due_date <= ? AND status IN ?",
			from, to, remediationStatusStrings(model.RemediationActiveStatuses)).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("统计即将到期整改单失败: %w", err)
	}
	return n, nil
}

// ListRecent 取最近变动的整改单（仪表盘「最近动态」用）。
func (r *RemediationRepository) ListRecent(ctx context.Context, limit int) ([]model.Remediation, error) {
	var rows []model.Remediation
	err := r.db.WithContext(ctx).Model(&model.Remediation{}).
		Order("updated_at DESC, id DESC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询最近整改动态失败: %w", err)
	}
	return rows, nil
}

// ------------------------------------------------------------------ 辅助

// applyStatusFilter 套用单状态 / 多状态过滤。
func applyStatusFilter(base *gorm.DB, status *string, statuses []string) *gorm.DB {
	if len(statuses) > 0 {
		return base.Where("status IN ?", statuses)
	}
	if status != nil {
		return base.Where("status = ?", *status)
	}
	return base
}

// remediationStatusStrings 把状态集合转成字符串切片（供 IN 查询）。
func remediationStatusStrings(ss []model.RemediationStatus) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

// startOfDay 取某时刻当天的零点（本地时区）。
//
// 存在的理由：due_date 是 DATE，与它比较的必须是日期而不是时刻。
// 直接拿 time.Time 去比，MySQL 会把 "2026-10-11 20:24:57" 与
// "2026-10-11" 补齐后比较，于是**今天到期**的单子在今天 00:00:01
// 就已经算「逾期」——而正确语义是「今天之内还不算逾期」。
func startOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}
