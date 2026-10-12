package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrAssetNotFound 资产不存在。
var ErrAssetNotFound = errors.New("repository: 资产不存在")

// AssetListQuery 资产列表查询条件。
type AssetListQuery struct {
	Keyword   string            // 匹配名称 / 编号 / IP / 主机名 / 负责人
	AssetType string            // 精确匹配类型码，空串表示不限
	Status    model.AssetStatus // 精确匹配状态，空串表示不限
	// GroupIDs 已展开的资产组集合（含子组）。
	// **nil 表示不限分组**；非 nil 时按 IN 过滤。
	// 服务层负责把单个 group_id 展开成「自身 + 全部后代」，
	// 仓储层不解释分组语义——那是业务规则，不是数据访问细节。
	GroupIDs   []uint64
	Importance *uint8
	Page       int
	PageSize   int
}

// AssetRepository 资产台账仓储。
type AssetRepository struct{ db *gorm.DB }

// NewAssetRepository 构建资产仓储。
func NewAssetRepository(db *gorm.DB) *AssetRepository { return &AssetRepository{db: db} }

// AssetIdentityKey 资产的身份键：名称 + IP。
//
// 批量导入用它判重。取这两个字段而不是只看名称，是因为台账里
// 「同名不同机」很常见（比如十台都叫「应用服务器」）；只看 IP 也不行
// （同一台机器上跑多个应用，IP 相同名称不同）。
//
// 用 \x00 而不是 '-' 之类的可见字符做分隔符：名称与 IP 里都不可能
// 出现 NUL（前者来自 Excel 单元格，后者是地址），因此这个拼接不会
// 出现「('a-b','c') 与 ('a','b-c') 撞成同一个键」的经典缺陷。
func AssetIdentityKey(name, ip string) string {
	return name + "\x00" + ip
}

// List 分页查询资产。
//
// 过滤条件全部下推 SQL，总数与当页数据各查一次。关键字检索覆盖
// 名称/编号/IP/主机名/负责人五个字段——台账里「按 IP 找机器」和
// 「按人找资产」都是高频动作，只支持名称检索等于逼用户导出到 Excel 里筛。
func (r *AssetRepository) List(ctx context.Context, q AssetListQuery) ([]model.Asset, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.Asset{})

	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		like := "%" + escapeLike(kw) + "%"
		base = base.Where(
			"(name LIKE ? OR asset_no LIKE ? OR ip_address LIKE ? OR hostname LIKE ? OR owner LIKE ?)",
			like, like, like, like, like,
		)
	}
	if q.AssetType != "" {
		base = base.Where("asset_type = ?", q.AssetType)
	}
	if q.Status != "" {
		base = base.Where("status = ?", q.Status)
	}
	if q.Importance != nil {
		base = base.Where("importance = ?", *q.Importance)
	}
	if q.GroupIDs != nil {
		// 传了空切片说明「筛选了一个没有任何子树的空集合」，
		// 用 1=0 明确表达「匹配不到」，而不是退化成不加条件（那会返回全部）。
		if len(q.GroupIDs) == 0 {
			base = base.Where("1 = 0")
		} else {
			base = base.Where("group_id IN ?", q.GroupIDs)
		}
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计资产总数失败: %w", err)
	}

	var assets []model.Asset
	err := base.Order("id DESC").
		Limit(q.PageSize).
		Offset((q.Page - 1) * q.PageSize).
		Find(&assets).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查询资产列表失败: %w", err)
	}
	return assets, total, nil
}

// FindByID 按主键查询。
func (r *AssetRepository) FindByID(ctx context.Context, id uint64) (*model.Asset, error) {
	var a model.Asset
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAssetNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按 ID 查询资产失败: %w", err)
	}
	return &a, nil
}

// ListByIDs 按 ID 集合批量查询（存在性校验与关联视图用）。
// 顺序按 id 升序，调用方自行做存在性判断——查不到的不是错误。
func (r *AssetRepository) ListByIDs(ctx context.Context, ids []uint64) ([]model.Asset, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var assets []model.Asset
	err := r.db.WithContext(ctx).
		Where("id IN ?", ids).
		Order("id ASC").
		Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("批量查询资产失败: %w", err)
	}
	return assets, nil
}

// Create 新建资产。
func (r *AssetRepository) Create(ctx context.Context, a *model.Asset) error {
	if err := r.db.WithContext(ctx).Create(a).Error; err != nil {
		return fmt.Errorf("创建资产失败: %w", err)
	}
	return nil
}

// BatchCreate 批量写入资产，供导入使用。
//
// 分批提交（每批 200 行）而不是一条大 INSERT：500 行拼成单条语句会
// 撞上 max_allowed_packet，而逐行插入又慢一个数量级。200 是两者之间的
// 经验值——单条语句约几十 KB，远离任何上限。
func (r *AssetRepository) BatchCreate(ctx context.Context, assets []model.Asset) error {
	if len(assets) == 0 {
		return nil
	}
	if err := r.db.WithContext(ctx).CreateInBatches(&assets, 200).Error; err != nil {
		return fmt.Errorf("批量写入资产失败: %w", err)
	}
	return nil
}

// Update 更新资产字段。用 map 而非 struct：struct 模式下 GORM 会跳过
// 零值字段，导致「把端口清空」这类操作静默无效。
func (r *AssetRepository) Update(ctx context.Context, id uint64, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Asset{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("更新资产失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		if _, err := r.FindByID(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// Delete 物理删除资产。
//
// 语义是「修正误录入」。资产退役请改 status = scrapped —— 台账需要留下
// 「这台机器曾经存在、已于某时退役」的事实。将来评估记录引用资产后，
// 这里的物理删除会被外键拦下（P4 接入 assessment_assets）。
func (r *AssetRepository) Delete(ctx context.Context, id uint64) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Asset{})
	if res.Error != nil {
		return fmt.Errorf("删除资产失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrAssetNotFound
	}
	return nil
}

// ExistsAssetNo 判断资产编号是否已被占用。excludeID > 0 时排除自身。
func (r *AssetRepository) ExistsAssetNo(
	ctx context.Context, assetNo string, excludeID uint64,
) (bool, error) {
	q := r.db.WithContext(ctx).Model(&model.Asset{}).Where("asset_no = ?", assetNo)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}
	var n int64
	if err := q.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("检查资产编号是否存在失败: %w", err)
	}
	return n > 0, nil
}

// CountByGroupIDs 统计落在给定资产组集合内的资产数量。
// 用于「删除资产组前先看看里面还有没有资产」。
func (r *AssetRepository) CountByGroupIDs(ctx context.Context, groupIDs []uint64) (int64, error) {
	if len(groupIDs) == 0 {
		return 0, nil
	}
	var n int64
	err := r.db.WithContext(ctx).Model(&model.Asset{}).
		Where("group_id IN ?", groupIDs).Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("统计资产组内资产数量失败: %w", err)
	}
	return n, nil
}

// CountByTypes 统计各资产类型下的资产数量，返回 类型码 → 数量。
// 用于「删除字典项前检查是否仍被资产引用」。
func (r *AssetRepository) CountByTypes(
	ctx context.Context, typeCodes []string,
) (map[string]int64, error) {
	out := make(map[string]int64, len(typeCodes))
	if len(typeCodes) == 0 {
		return out, nil
	}

	var rows []struct {
		AssetType string
		N         int64
	}
	err := r.db.WithContext(ctx).Model(&model.Asset{}).
		Select("asset_type, COUNT(*) AS n").
		Where("asset_type IN ?", typeCodes).
		Group("asset_type").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("统计资产类型分布失败: %w", err)
	}
	for _, row := range rows {
		out[row.AssetType] = row.N
	}
	return out, nil
}

// GroupCounts 统计每个资产组的**直属**资产数量，返回 组 ID → 数量。
//
// 一次 GROUP BY 把所有组的直属数量取回来，而不是每渲染一个组查一次。
// 这里刻意只统计「直属」：子树合计由服务层在内存里沿树累加，
// 因为资产组的层级是树而不是链，在 SQL 里算子树合计要么递归、
// 要么对每个组做一次 LIKE —— 组数量只有几十到几百，内存累加最省。
func (r *AssetRepository) GroupCounts(ctx context.Context) (map[uint64]int64, error) {
	var rows []struct {
		GroupID uint64
		N       int64
	}
	err := r.db.WithContext(ctx).Model(&model.Asset{}).
		Select("group_id, COUNT(*) AS n").
		Where("group_id IS NOT NULL").
		Group("group_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("统计资产组资产数量失败: %w", err)
	}

	out := make(map[uint64]int64, len(rows))
	for _, row := range rows {
		out[row.GroupID] = row.N
	}
	return out, nil
}

// ------------------------------------------------------- 仪表盘聚合（P6）

// CountAll 资产总数，**含已报废**。
//
// 刻意不在 SQL 里排除 scrapped：仪表盘上「资产总数」若与资产列表页显示的
// 条数不一致，用户第一反应是「页面有 bug」而不是「报废的被排除了」。
// 报废数量由 StatusCounts 单独给出，两者一起看才是完整事实。
func (r *AssetRepository) CountAll(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.WithContext(ctx).Model(&model.Asset{}).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("统计资产总数失败: %w", err)
	}
	return n, nil
}

// TypeCounts 统计各资产类型下的资产数量，返回 类型码 → 数量。
//
// 与 CountByTypes 的区别：后者要求调用方先给出码清单（用于「删字典项前
// 看是否被引用」）。仪表盘要回答的是「有哪些类型、各多少」，
// 让调用方先去字典里查一遍再回头传进来，会**漏掉字典里没有的类型码**
// —— 历史数据、被删掉的字典项，而那些恰恰是最该被看见的异常。
func (r *AssetRepository) TypeCounts(ctx context.Context) (map[string]int64, error) {
	return r.groupCount(ctx, "asset_type")
}

// StatusCounts 统计各状态的资产数量，返回 状态码 → 数量。
func (r *AssetRepository) StatusCounts(ctx context.Context) (map[string]int64, error) {
	return r.groupCount(ctx, "status")
}

// groupCount 按给定列做一次 GROUP BY，返回 值 → 数量。
func (r *AssetRepository) groupCount(ctx context.Context, column string) (map[string]int64, error) {
	// column 只来自本文件内的两个常量字符串，不含用户输入，
	// 因此这里的拼接不构成注入面；仍然显式挡一道，防止将来有人
	// 顺手把它改成参数传入的列名。
	switch column {
	case "asset_type", "status":
	default:
		return nil, fmt.Errorf("不支持的分组列: %s", column)
	}

	var rows []GroupCount
	err := r.db.WithContext(ctx).Model(&model.Asset{}).
		Select(column + " AS k, COUNT(*) AS cnt").
		Group(column).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("统计资产 %s 分布失败: %w", column, err)
	}

	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		out[row.Key] = row.Count
	}
	return out, nil
}

// ExistingAssetNos 在给定编号中找出**数据库中已存在**的那些，返回 编号 → ID。
func (r *AssetRepository) ExistingAssetNos(
	ctx context.Context, assetNos []string,
) (map[string]uint64, error) {
	out := make(map[string]uint64, len(assetNos))
	if len(assetNos) == 0 {
		return out, nil
	}

	var rows []struct {
		ID      uint64
		AssetNo string
	}
	// 只 Select 两列，不把整行拉回来：判重只需要 ID 用于报错文案，
	// 而一行有 14 列、含 varchar(512)。
	err := r.db.WithContext(ctx).Model(&model.Asset{}).
		Select("id, asset_no").
		Where("asset_no IN ?", assetNos).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询已存在的资产编号失败: %w", err)
	}
	for _, row := range rows {
		out[row.AssetNo] = row.ID
	}
	return out, nil
}

// ExistingByNameAndIP 在给定 IP 集合中找出**可能同名同 IP** 的资产，
// 返回 身份键（AssetIdentityKey(名称, IP)）→ ID。
//
// 先用 ip_address IN (...) 把候选集缩小到「IP 相同」的那一批，
// 再在内存里按「名称 + IP」精确比对。之所以不直接对 (name, ip) 做
// 行值 IN 查询：那种写法在 GORM 里要拼原生 SQL，且对 5000 行会生成
// 一条几万字符的语句；而按 IP 过滤能走上 idx_assets_ip_address。
// 同 IP 的候选行通常只有个位数，内存比对的开销可以忽略。
func (r *AssetRepository) ExistingByNameAndIP(
	ctx context.Context, ips []string,
) (map[string]uint64, error) {
	out := make(map[string]uint64)
	if len(ips) == 0 {
		return out, nil
	}

	var rows []struct {
		ID        uint64
		Name      string
		IPAddress string
	}
	err := r.db.WithContext(ctx).Model(&model.Asset{}).
		Select("id, name, ip_address").
		Where("ip_address IN ?", ips).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询同名同 IP 资产失败: %w", err)
	}
	for _, row := range rows {
		out[AssetIdentityKey(row.Name, row.IPAddress)] = row.ID
	}
	return out, nil
}
