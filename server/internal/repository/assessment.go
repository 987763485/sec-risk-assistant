package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrAssessmentNotFound 评估任务不存在。
var ErrAssessmentNotFound = errors.New("repository: 评估任务不存在")

// ErrRiskItemNotFound 风险项不存在。
var ErrRiskItemNotFound = errors.New("repository: 风险项不存在")

// inBatchSize 单条 IN 查询的最大元素个数。
//
// 一份「全部资产」的评估可能有上万台资产，直接拼进 IN (...) 会撞上
// max_allowed_packet，而且报的错是「SQL 语法错误」——离真正的原因很远。
// 分批没有性能损失：每批都是一次索引扫描，批与批之间彼此独立。
const inBatchSize = 1000

// AssessmentListQuery 评估任务列表查询条件。
type AssessmentListQuery struct {
	Keyword  string
	Status   *string
	Page     int
	PageSize int
}

// RiskItemQuery 风险项分页查询条件。
type RiskItemQuery struct {
	AssessmentID uint64
	// Importance / Severity 是矩阵下钻的过滤条件（矩阵的横纵轴）。
	// nil 表示该维度不限。
	Importance *uint8
	Severity   *uint8
	Level      *string
	Keyword    string
	Page       int
	PageSize   int
}

// ItemKey 风险项的业务主键（资产 × 漏洞），用于「逐项威胁覆盖」的查找。
type ItemKey struct {
	AssetID uint64
	VulnID  uint64
}

// VulnAssetPair 一条「资产 × 漏洞」对。
type VulnAssetPair struct {
	AssetID uint64 `gorm:"column:asset_id"`
	VulnID  uint64 `gorm:"column:vuln_id"`
}

// LevelAgg 按等级聚合的结果。
type LevelAgg struct {
	Level   string  `gorm:"column:level"`
	Count   int64   `gorm:"column:cnt"`
	MaxRisk float64 `gorm:"column:max_risk"`
}

// MatrixCell 矩阵中一个格子的聚合结果。
type MatrixCell struct {
	Importance uint8   `gorm:"column:importance"`
	Severity   uint8   `gorm:"column:severity"`
	Count      int64   `gorm:"column:cnt"`
	MaxRisk    float64 `gorm:"column:max_risk"`
}

// AssessmentRepository 评估任务与结果仓储。
type AssessmentRepository struct{ db *gorm.DB }

// NewAssessmentRepository 构建评估仓储。
func NewAssessmentRepository(db *gorm.DB) *AssessmentRepository {
	return &AssessmentRepository{db: db}
}

// ---------------------------------------------------------------- 评估任务

// Create 新建评估任务。
func (r *AssessmentRepository) Create(ctx context.Context, a *model.Assessment) error {
	if err := r.db.WithContext(ctx).Create(a).Error; err != nil {
		return fmt.Errorf("创建评估任务失败: %w", err)
	}
	return nil
}

// FindByID 按主键查询评估任务。
func (r *AssessmentRepository) FindByID(ctx context.Context, id uint64) (*model.Assessment, error) {
	var a model.Assessment
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAssessmentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询评估任务失败: %w", err)
	}
	return &a, nil
}

// List 分页查询评估任务。
func (r *AssessmentRepository) List(ctx context.Context, q AssessmentListQuery) ([]model.Assessment, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.Assessment{})

	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		like := "%" + escapeLike(kw) + "%"
		base = base.Where("(name LIKE ? OR description LIKE ?)", like, like)
	}
	if q.Status != nil {
		base = base.Where("status = ?", *q.Status)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计评估任务总数失败: %w", err)
	}

	var rows []model.Assessment
	err := base.Order("id DESC").
		Limit(q.PageSize).
		Offset((q.Page - 1) * q.PageSize).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查询评估任务列表失败: %w", err)
	}
	return rows, total, nil
}

// Update 更新评估任务的允许编辑字段。
func (r *AssessmentRepository) Update(ctx context.Context, id uint64, fields map[string]any) error {
	err := r.db.WithContext(ctx).Model(&model.Assessment{}).
		Where("id = ?", id).Updates(fields).Error
	if err != nil {
		return fmt.Errorf("更新评估任务失败: %w", err)
	}
	return nil
}

// Delete 删除评估任务。risk_items / assessment_assets 由外键 CASCADE 清理。
func (r *AssessmentRepository) Delete(ctx context.Context, id uint64) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Assessment{}).Error; err != nil {
		return fmt.Errorf("删除评估任务失败: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- 资产范围

// AssetsByScope 按评估范围取资产。
//
// 三种范围的处理：
//   - all    全表，排除已报废（scrapped）——评估一台已经报废的机器没有意义，
//     而报废资产仍留在台账里（见 000004 约束 5）会污染评估口径；
//   - group  先展开组子树（物化路径 LIKE），再取这些组下的资产；
//   - custom 直接用给定的资产 ID。
//
// 三种范围**都**排除 scrapped。理由一致：范围决定「评哪些」，
// 状态决定「还值不值得评」，把它们混在一起会让同一个资产在 all 与 custom
// 下得到不同结论，而这解释不通。
func (r *AssessmentRepository) AssetsByScope(
	ctx context.Context, scopeType string, groupIDs, assetIDs []uint64,
) ([]model.Asset, error) {
	q := r.db.WithContext(ctx).Model(&model.Asset{})

	switch scopeType {
	case string(model.ScopeAll):
		// 无需附加条件

	case string(model.ScopeGroup):
		if len(groupIDs) == 0 {
			return nil, nil
		}
		subIDs, err := r.subtreeGroupIDs(ctx, groupIDs)
		if err != nil {
			return nil, err
		}
		if len(subIDs) == 0 {
			return nil, nil
		}
		q = q.Where("group_id IN ?", subIDs)

	case string(model.ScopeCustom):
		if len(assetIDs) == 0 {
			return nil, nil
		}
		q = q.Where("id IN ?", assetIDs)

	default:
		return nil, fmt.Errorf("未知的评估范围类型: %s", scopeType)
	}

	var assets []model.Asset
	err := q.Where("status <> ?", model.AssetStatusScrapped).
		Order("id ASC").Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("按范围查询资产失败: %w", err)
	}
	return assets, nil
}

// subtreeGroupIDs 展开给定资产组及其全部子孙组的 ID。
//
// 用物化路径做前缀匹配（`path LIKE '/1/4/%'`），一次查询拿全子树，
// 不需要递归——这正是 000004 约束 1 选物化路径的原因。
func (r *AssessmentRepository) subtreeGroupIDs(ctx context.Context, groupIDs []uint64) ([]uint64, error) {
	var groups []model.AssetGroup
	if err := r.db.WithContext(ctx).Model(&model.AssetGroup{}).
		Where("id IN ?", groupIDs).Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("查询资产组失败: %w", err)
	}
	if len(groups) == 0 {
		return nil, nil
	}

	conds := make([]string, 0, len(groups))
	args := make([]any, 0, len(groups))
	for _, g := range groups {
		conds = append(conds, "path LIKE ?")
		args = append(args, escapeLike(g.Path)+"%")
	}

	var ids []uint64
	err := r.db.WithContext(ctx).Model(&model.AssetGroup{}).
		Where(strings.Join(conds, " OR "), args...).
		Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("展开资产组子树失败: %w", err)
	}
	return ids, nil
}

// ------------------------------------------------------------ 漏洞-资产对

// VulnPairsByAssets 取出给定资产下的全部「资产 × 漏洞」对。
//
// 这是 D1 决策的落点：风险项粒度 = 资产 × 漏洞，每个 vuln_asset_link 一条。
// **只取有链接的对**——没有挂到任何资产的漏洞不参与评估，也不该在评估结果
// 里出现一条「无主机的风险」，那会让报告读起来莫名其妙。
func (r *AssessmentRepository) VulnPairsByAssets(ctx context.Context, assetIDs []uint64) ([]VulnAssetPair, error) {
	out := make([]VulnAssetPair, 0)
	for _, batch := range chunkUint64(assetIDs, inBatchSize) {
		var rows []VulnAssetPair
		err := r.db.WithContext(ctx).Model(&model.VulnAssetLink{}).
			Select("asset_id, vuln_id").
			Where("asset_id IN ?", batch).
			Order("asset_id ASC, vuln_id ASC").
			Find(&rows).Error
		if err != nil {
			return nil, fmt.Errorf("查询漏洞-资产关联失败: %w", err)
		}
		out = append(out, rows...)
	}
	return out, nil
}

// VulnsByIDs 批量取漏洞，返回「ID → 漏洞」映射。
//
// 分批时不保证批间顺序，用 map 返回而不是切片：调用方按 (asset, vuln)
// 查表，不依赖顺序。
func (r *AssessmentRepository) VulnsByIDs(ctx context.Context, ids []uint64) (map[uint64]model.Vulnerability, error) {
	out := make(map[uint64]model.Vulnerability, len(ids))
	for _, batch := range chunkUint64(ids, inBatchSize) {
		var rows []model.Vulnerability
		if err := r.db.WithContext(ctx).Where("id IN ?", batch).Find(&rows).Error; err != nil {
			return nil, fmt.Errorf("批量查询漏洞失败: %w", err)
		}
		for _, v := range rows {
			out[v.ID] = v
		}
	}
	return out, nil
}

// ------------------------------------------------------------------ 结果

// DeleteResults 清空某评估的全部结果行（重算前的第一步）。
//
// 只删结果、不删任务：calculate 是幂等的「重算覆盖」，
// 重复点击不应该堆出第二份风险项。
func (r *AssessmentRepository) DeleteResults(ctx context.Context, assessmentID uint64) error {
	if err := r.db.WithContext(ctx).
		Where("assessment_id = ?", assessmentID).Delete(&model.AssessmentAsset{}).Error; err != nil {
		return fmt.Errorf("清空资产汇总失败: %w", err)
	}
	if err := r.db.WithContext(ctx).
		Where("assessment_id = ?", assessmentID).Delete(&model.RiskItem{}).Error; err != nil {
		return fmt.Errorf("清空风险项失败: %w", err)
	}
	return nil
}

// CreateRiskItems 批量写入风险项。GORM 会回填自增主键，写完后 items 元素
// 上就带着 ID —— assessment_assets.top_item_id 需要它。
func (r *AssessmentRepository) CreateRiskItems(ctx context.Context, items []model.RiskItem) error {
	if len(items) == 0 {
		return nil
	}
	if err := r.db.WithContext(ctx).CreateInBatches(items, 200).Error; err != nil {
		return fmt.Errorf("写入风险项失败: %w", err)
	}
	return nil
}

// CreateAssessmentAssets 批量写入资产级汇总。
func (r *AssessmentRepository) CreateAssessmentAssets(ctx context.Context, rows []model.AssessmentAsset) error {
	if len(rows) == 0 {
		return nil
	}
	if err := r.db.WithContext(ctx).CreateInBatches(rows, 200).Error; err != nil {
		return fmt.Errorf("写入资产汇总失败: %w", err)
	}
	return nil
}

// ManualThreatOverrides 取出某评估里**被逐项覆盖过威胁**的风险项。
//
// calculate 重算时据此保留人工指定值：重算只应该刷新「算出来的部分」，
// 不应该把用户逐条调整过的威胁选择一并抹掉。
func (r *AssessmentRepository) ManualThreatOverrides(ctx context.Context, assessmentID uint64) (map[ItemKey]string, error) {
	var rows []model.RiskItem
	err := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Select("asset_id, vuln_id, threat_code").
		Where("assessment_id = ? AND threat_source = ?", assessmentID, model.ThreatSourceManual).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询逐项威胁覆盖失败: %w", err)
	}
	out := make(map[ItemKey]string, len(rows))
	for _, row := range rows {
		out[ItemKey{AssetID: row.AssetID, VulnID: row.VulnID}] = row.ThreatCode
	}
	return out, nil
}

// ListRiskItems 分页查询风险项（含矩阵下钻过滤）。
func (r *AssessmentRepository) ListRiskItems(ctx context.Context, q RiskItemQuery) ([]model.RiskItem, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Where("assessment_id = ?", q.AssessmentID)

	if q.Importance != nil {
		base = base.Where("importance = ?", *q.Importance)
	}
	if q.Severity != nil {
		base = base.Where("severity = ?", *q.Severity)
	}
	if q.Level != nil {
		base = base.Where("risk_level = ?", *q.Level)
	}
	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		like := "%" + escapeLike(kw) + "%"
		base = base.Where("(asset_name LIKE ? OR asset_ip LIKE ? OR vuln_title LIKE ? OR vuln_cve_ids LIKE ?)",
			like, like, like, like)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计风险项总数失败: %w", err)
	}

	var rows []model.RiskItem
	err := base.Order("risk_value_r DESC, id ASC").
		Limit(q.PageSize).
		Offset((q.Page - 1) * q.PageSize).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查询风险项失败: %w", err)
	}
	return rows, total, nil
}

// ListAllRiskItems 取某评估的全部风险项（导出报告数据用）。
//
// 带上限：报告是「一次导出」，没有分页，若不设上限，一个 5 万条的评估
// 会在内存里拼出一份几十 MB 的 JSON。超限时由服务层返回可读的错误，
// 而不是让响应悄悄截断——截断的报告比报错的报告危险得多。
func (r *AssessmentRepository) ListAllRiskItems(ctx context.Context, assessmentID uint64, limit int) ([]model.RiskItem, error) {
	var rows []model.RiskItem
	err := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Where("assessment_id = ?", assessmentID).
		Order("risk_value_r DESC, id ASC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询全部风险项失败: %w", err)
	}
	return rows, nil
}

// ListAssessmentAssets 取某评估的资产级汇总。
func (r *AssessmentRepository) ListAssessmentAssets(ctx context.Context, assessmentID uint64) ([]model.AssessmentAsset, error) {
	var rows []model.AssessmentAsset
	err := r.db.WithContext(ctx).Model(&model.AssessmentAsset{}).
		Where("assessment_id = ?", assessmentID).
		Order("risk_value DESC, id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询资产汇总失败: %w", err)
	}
	return rows, nil
}

// FindRiskItemByID 按主键查询风险项。
func (r *AssessmentRepository) FindRiskItemByID(ctx context.Context, id uint64) (*model.RiskItem, error) {
	var item model.RiskItem
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRiskItemNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询风险项失败: %w", err)
	}
	return &item, nil
}

// UpdateRiskItem 更新风险项的指定列。
func (r *AssessmentRepository) UpdateRiskItem(ctx context.Context, id uint64, fields map[string]any) error {
	err := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Where("id = ?", id).Updates(fields).Error
	if err != nil {
		return fmt.Errorf("更新风险项失败: %w", err)
	}
	return nil
}

// LevelAggregate 按等级聚合风险项（重算汇总列用）。
func (r *AssessmentRepository) LevelAggregate(ctx context.Context, assessmentID uint64) ([]LevelAgg, error) {
	var rows []LevelAgg
	err := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Select("risk_level AS level, COUNT(*) AS cnt, MAX(risk_value_r) AS max_risk").
		Where("assessment_id = ?", assessmentID).
		Group("risk_level").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("按等级聚合风险项失败: %w", err)
	}
	return rows, nil
}

// Matrix 取矩阵的格子聚合（横轴资产重要性、纵轴漏洞严重程度）。
func (r *AssessmentRepository) Matrix(ctx context.Context, assessmentID uint64) ([]MatrixCell, error) {
	var rows []MatrixCell
	err := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Select("importance, severity, COUNT(*) AS cnt, MAX(risk_value_r) AS max_risk").
		Where("assessment_id = ?", assessmentID).
		Group("importance, severity").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("聚合风险矩阵失败: %w", err)
	}
	return rows, nil
}

// RebuildAssetSummaries 由 risk_items 整体重建资产级汇总。
//
// 用于「逐项覆盖威胁」之后：一条风险项的 R 变了，它所在资产的最大风险
// 也可能跟着变。选整体重建而不是增量更新，是因为增量要专门处理「原来
// 最大的那条被调低了」——那正是最容易写漏、且漏了不报错的分支；
// 而整体重建只需要一次 5000 行以内的内存聚合（导出上限本就是 5000）。
func (r *AssessmentRepository) RebuildAssetSummaries(
	ctx context.Context, assessmentID uint64, limit int,
) error {
	items, err := r.ListAllRiskItems(ctx, assessmentID, limit)
	if err != nil {
		return err
	}

	type agg struct {
		row  model.AssessmentAsset
		top  float64
		hits int
	}
	order := make([]uint64, 0)
	byAsset := make(map[uint64]*agg)

	for i := range items {
		it := &items[i]
		g, ok := byAsset[it.AssetID]
		if !ok {
			g = &agg{row: model.AssessmentAsset{
				AssessmentID: assessmentID,
				AssetID:      it.AssetID,
				AssetName:    it.AssetName,
				AssetIP:      it.AssetIP,
				Importance:   it.Importance,
				AssetValueA:  it.AssetValueA,
			}}
			byAsset[it.AssetID] = g
			order = append(order, it.AssetID)
		}
		g.hits++
		if g.hits == 1 || it.RiskValue > g.top {
			g.top = it.RiskValue
			g.row.RiskValue = it.RiskValue
			g.row.RiskLevel = it.RiskLevel
			id := it.ID
			g.row.TopItemID = &id
		}
	}

	if err := r.db.WithContext(ctx).Where("assessment_id = ?", assessmentID).
		Delete(&model.AssessmentAsset{}).Error; err != nil {
		return fmt.Errorf("清空资产汇总失败: %w", err)
	}

	rows := make([]model.AssessmentAsset, 0, len(order))
	for _, id := range order {
		g := byAsset[id]
		g.row.RiskItemsCount = uint32(g.hits)
		rows = append(rows, g.row)
	}
	return r.CreateAssessmentAssets(ctx, rows)
}

// CountAssetSummary 统计资产级汇总的行数。
func (r *AssessmentRepository) CountAssetSummary(ctx context.Context, assessmentID uint64) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&model.AssessmentAsset{}).
		Where("assessment_id = ?", assessmentID).Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("统计资产汇总行数失败: %w", err)
	}
	return n, nil
}

// CountRiskItemsByLevels 统计某评估下指定等级的风险项条数。
//
// 与 ListRiskItemsByLevels 配对：先数后取。批量建单要用「精确条数」
// 来决定是报「超过上限 500 条」还是照常执行 —— 只靠「取 501 条看够不够」
// 无法报出真实的条数，而错误文案里写「≥501 条」对用户没有帮助。
func (r *AssessmentRepository) CountRiskItemsByLevels(
	ctx context.Context, assessmentID uint64, levels []string,
) (int64, error) {
	if len(levels) == 0 {
		return 0, nil
	}
	var n int64
	err := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Where("assessment_id = ? AND risk_level IN ?", assessmentID, levels).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("统计风险项条数失败: %w", err)
	}
	return n, nil
}

// ListRiskItemsByLevels 取某评估下指定等级的风险项，按风险值降序。
//
// 等级过滤下推到 SQL（risk_level 有 `idx_risk_items_level` 索引），
// 而不是把该评估的全部风险项取回来在 Go 里筛 —— 一次「全部资产」的
// 评估可能有几万条，为了建 200 张单子把几万行读进内存是没必要的。
//
// ⚠️ limit 必须为正数：GORM 的 `Limit(0)` 生成的是 `LIMIT 0`（返回空集），
// 而不是「不限制」—— 传 0 会让这个方法静默返回 nil，调用方看到的是
// 「一条都没有」，与真正的空集无从区分。
func (r *AssessmentRepository) ListRiskItemsByLevels(
	ctx context.Context, assessmentID uint64, levels []string, limit int,
) ([]model.RiskItem, error) {
	if len(levels) == 0 || limit <= 0 {
		return nil, nil
	}
	var rows []model.RiskItem
	err := r.db.WithContext(ctx).Model(&model.RiskItem{}).
		Where("assessment_id = ? AND risk_level IN ?", assessmentID, levels).
		Order("risk_value_r DESC, id ASC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("按等级查询风险项失败: %w", err)
	}
	return rows, nil
}

// ------------------------------------------------------- 仪表盘聚合（P6）

// CountAll 评估任务总数。
func (r *AssessmentRepository) CountAll(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.WithContext(ctx).Model(&model.Assessment{}).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("统计评估任务总数失败: %w", err)
	}
	return n, nil
}

// StatusCounts 统计各状态的评估任务数量（draft / calculated）。
func (r *AssessmentRepository) StatusCounts(ctx context.Context) (map[string]int64, error) {
	var rows []GroupCount
	err := r.db.WithContext(ctx).Model(&model.Assessment{}).
		Select("status AS k, COUNT(*) AS cnt").
		Group("status").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("统计评估任务状态分布失败: %w", err)
	}

	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		out[row.Key] = row.Count
	}
	return out, nil
}

// FindLatestCalculated 取**最近一次已计算**的评估任务。
//
// 仪表盘的风险分布以它为基准（见 docs/13 D6）。返回 ErrAssessmentNotFound
// 表示库里一次都没算过 —— 这是**正常状态**（刚初始化完的系统），
// 调用方必须把「没有评估」当成一个合法的空场景处理，而不是 500。
//
// 排序键用 calculated_at 而不是 id：手工补算过的老任务会拿到更大的 id，
// 但它的结论并不是「最新的一次评估」。
func (r *AssessmentRepository) FindLatestCalculated(ctx context.Context) (*model.Assessment, error) {
	var a model.Assessment
	err := r.db.WithContext(ctx).
		Where("status = ? AND calculated_at IS NOT NULL", model.AssessmentCalculated).
		Order("calculated_at DESC, id DESC").
		Take(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAssessmentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询最近一次评估失败: %w", err)
	}
	return &a, nil
}

// TopRiskAssets 取某评估下风险值最高的若干台资产（仪表盘「最危险的资产」）。
//
// 单独开一个有 LIMIT 的方法，而不是复用 ListAssessmentAssets 再在内存里截断：
// 一次「全部资产」的评估可能有上万台，为了显示 5 行把整张汇总表拉回来，
// 是仪表盘最常见的性能事故——而且它在小数据量的测试环境里完全看不出来。
func (r *AssessmentRepository) TopRiskAssets(
	ctx context.Context, assessmentID uint64, limit int,
) ([]model.AssessmentAsset, error) {
	var rows []model.AssessmentAsset
	err := r.db.WithContext(ctx).Model(&model.AssessmentAsset{}).
		Where("assessment_id = ?", assessmentID).
		Order("risk_value DESC, id ASC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询高风险资产失败: %w", err)
	}
	return rows, nil
}

// chunkUint64 把切片按固定大小切块。
func chunkUint64(ids []uint64, size int) [][]uint64 {
	if len(ids) == 0 {
		return nil
	}
	out := make([][]uint64, 0, (len(ids)+size-1)/size)
	for start := 0; start < len(ids); start += size {
		end := start + size
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, ids[start:end])
	}
	return out
}
