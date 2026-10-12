package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"secrisk/server/internal/model"
)

// ErrIntegrationNotFound 情报源集成不存在。
var ErrIntegrationNotFound = errors.New("repository: 集成不存在")

// IntegrationListQuery 集成列表查询条件。
type IntegrationListQuery struct {
	// Keyword 匹配名称与上游地址。
	Keyword string
	// Type 精确匹配适配器类型，nil 表示不限。
	Type *string
	// Enabled 过滤启用状态，nil 表示不限。
	Enabled *bool
}

// IntegrationRepository 情报源集成仓储。
type IntegrationRepository struct{ db *gorm.DB }

// NewIntegrationRepository 构建集成仓储。
func NewIntegrationRepository(db *gorm.DB) *IntegrationRepository {
	return &IntegrationRepository{db: db}
}

// List 查询集成列表。
//
// 不分页：集成是**运维配置**，数量以个数计（现实里几十条已属很多），
// 而配置页需要一次看到全部才能判断「有没有配重」。这与业务列表
// （资产、漏洞）必须分页的立场不同——那里数据量无上界。
func (r *IntegrationRepository) List(ctx context.Context, q IntegrationListQuery) ([]model.Integration, error) {
	base := r.db.WithContext(ctx).Model(&model.Integration{})

	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		like := "%" + escapeLike(kw) + "%"
		base = base.Where("(name LIKE ? OR base_url LIKE ?)", like, like)
	}
	if q.Type != nil {
		base = base.Where("type = ?", *q.Type)
	}
	if q.Enabled != nil {
		base = base.Where("enabled = ?", *q.Enabled)
	}

	var rows []model.Integration
	// 按类型再按 id：同类集成排在一起，便于一眼看出「同一个适配器配了几个入口」。
	if err := base.Order("type ASC, id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查询集成列表失败: %w", err)
	}
	return rows, nil
}

// FindByID 按主键查询。
func (r *IntegrationRepository) FindByID(ctx context.Context, id uint64) (*model.Integration, error) {
	var m model.Integration
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrIntegrationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按 ID 查询集成失败: %w", err)
	}
	return &m, nil
}

// FindByName 按名称查询，用于「重名」的友好提示。
//
// 名称唯一由数据库索引兜底（迁移 000008），这里先查一次只是为了
// 给出 409 + 人话，而不是让用户看到一次 INTERNAL_ERROR。
// 并发下先查后插仍有竞态窗口，那时会由唯一索引拒绝——可接受：
// 结果是「罕见情况下报 500 而不是 409」，而不是「产生了重名」。
func (r *IntegrationRepository) FindByName(ctx context.Context, name string) (*model.Integration, error) {
	var m model.Integration
	err := r.db.WithContext(ctx).Where("name = ?", name).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrIntegrationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按名称查询集成失败: %w", err)
	}
	return &m, nil
}

// Create 新建集成。
func (r *IntegrationRepository) Create(ctx context.Context, m *model.Integration) error {
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("创建集成失败: %w", err)
	}
	return nil
}

// UpdateConfig 更新配置字段。
//
// ⚠️ 用 map 而不是 struct：GORM 的 Updates(struct) 会跳过零值字段，
// 于是「把 enabled 改成 false」「把 timeout_ms 改成 0」这类操作
// 会静默不生效，而接口返回成功（见项目约定「仓储层更新一律用 map」）。
// 调用方（service）负责决定本次要写哪几列。
func (r *IntegrationRepository) UpdateConfig(ctx context.Context, id uint64, cols map[string]any) error {
	if len(cols) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Model(&model.Integration{}).
		Where("id = ?", id).Updates(cols).Error
	if err != nil {
		return fmt.Errorf("更新集成配置失败: %w", err)
	}
	return nil
}

// UpdateRunState 写回运行态（last_run_at / last_status / last_error / last_latency_ms）。
//
// 与 UpdateConfig 分成两个方法而不是合成一个「Update」：它们改的是
// **同一行里两个语义完全不同的区域**——一个是人配的，一个是系统写的。
// 合成一个之后，调用方很容易在一次「拉取」里顺手把配置列也写回去，
// 而那正是「拉取失败了却把 base_url 改回默认值」这类事故的起点。
//
// ⚠️ 副作用：这次写入会刷新 updated_at（列上是 ON UPDATE CURRENT_TIMESTAMP）。
// 见迁移 000008 约束 5 —— 界面不得把 updated_at 当作「配置最后修改时间」。
func (r *IntegrationRepository) UpdateRunState(
	ctx context.Context, id uint64, runAt time.Time, status, lastError string, latencyMS int,
) error {
	err := r.db.WithContext(ctx).Model(&model.Integration{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"last_run_at":     runAt,
			"last_status":     status,
			"last_error":      lastError,
			"last_latency_ms": latencyMS,
		}).Error
	if err != nil {
		return fmt.Errorf("写回集成运行态失败: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- 情报快照

// ListIntelByVuln 查询某漏洞的全部情报快照。
//
// 排序确定：先按来源，再按 CVE 编号。不定序会让详情页每次刷新时
// 情报条目的顺序抖动，用户会以为是内容变了。
func (r *IntegrationRepository) ListIntelByVuln(ctx context.Context, vulnID uint64) ([]model.VulnIntel, error) {
	var rows []model.VulnIntel
	err := r.db.WithContext(ctx).
		Where("vuln_id = ?", vulnID).
		Order("source ASC, cve_id ASC").Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询漏洞情报失败: %w", err)
	}
	return rows, nil
}

// CountIntelByVulns 统计多个漏洞各自的情报条数（列表页标记用）。
//
// 一次 GROUP BY 而不是按漏洞逐个 COUNT——后者是 N+1 查询的典型形状，
// 20 条一页的列表会变成 21 次往返。
func (r *IntegrationRepository) CountIntelByVulns(ctx context.Context, vulnIDs []uint64) (map[uint64]int64, error) {
	out := make(map[uint64]int64)
	if len(vulnIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		VulnID uint64 `gorm:"column:vuln_id"`
		Cnt    int64  `gorm:"column:cnt"`
	}
	err := r.db.WithContext(ctx).Model(&model.VulnIntel{}).
		Select("vuln_id, COUNT(*) AS cnt").
		Where("vuln_id IN ?", vulnIDs).
		Group("vuln_id").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("统计漏洞情报条数失败: %w", err)
	}
	for _, row := range rows {
		out[row.VulnID] = row.Cnt
	}
	return out, nil
}

// IntelUpsertResult 一次情报写入的结果。
//
// 区分 inserted / updated 不是为了统计好看：界面要提示「本次拉取
// 新增 2 条、更新 1 条」，用户据此判断「这次有没有拿到新东西」。
// 只报「写入 3 条」在重复拉取时与首次拉取长得一模一样。
type IntelUpsertResult struct {
	Inserted int
	Updated  int
}

// UpsertIntel 按 (vuln_id, source, cve_id) 写入或更新情报快照。
//
// 用 ON DUPLICATE KEY UPDATE 而不是「先删后插」：先删会把该漏洞该来源下
// **本次没有拉到的** CVE 记录一并抹掉。而「本次没拉到」的原因常常是
// 上游暂时不可达或限流，不是「这条 CVE 不该有情报」——
// 一次失败的拉取不应该成为一次静默的数据删除。
//
// DoUpdates 里刻意不含 created_at：它是「首次入库时间」，重拉一次
// 不应该把它刷新成现在，否则「这条情报是什么时候第一次进来的」就丢了。
func (r *IntegrationRepository) UpsertIntel(ctx context.Context, records []model.VulnIntel) (IntelUpsertResult, error) {
	var res IntelUpsertResult
	if len(records) == 0 {
		return res, nil
	}

	// 先查已有键，用于区分新增 / 更新。这一步与下面的写入不在同一事务里，
	// 因此并发下统计可能偏保守——但**不会影响数据正确性**：
	// 唯一键保证最终只有一条，统计数字只用于提示语。
	existing, err := r.existingIntelKeys(ctx, records[0].VulnID, records[0].Source)
	if err != nil {
		return res, err
	}

	err = r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "vuln_id"}, {Name: "source"}, {Name: "cve_id"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"title", "description", "severity", "cvss_score", "cvss_vector",
			"published_at", "references_json", "raw_json", "fetched_at",
		}),
	}).Create(&records).Error
	if err != nil {
		return res, fmt.Errorf("写入漏洞情报失败: %w", err)
	}

	for _, rec := range records {
		if _, ok := existing[rec.CVEID]; ok {
			res.Updated++
		} else {
			res.Inserted++
		}
	}
	return res, nil
}

// existingIntelKeys 返回某漏洞某来源下已存在的 CVE 编号集合。
func (r *IntegrationRepository) existingIntelKeys(
	ctx context.Context, vulnID uint64, source string,
) (map[string]struct{}, error) {
	var keys []string
	err := r.db.WithContext(ctx).Model(&model.VulnIntel{}).
		Where("vuln_id = ? AND source = ?", vulnID, source).
		Pluck("cve_id", &keys).Error
	if err != nil {
		return nil, fmt.Errorf("查询已有情报键失败: %w", err)
	}
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		out[k] = struct{}{}
	}
	return out, nil
}
