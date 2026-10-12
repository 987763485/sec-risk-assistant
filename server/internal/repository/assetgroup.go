package repository

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrAssetGroupNotFound 资产组不存在。
var ErrAssetGroupNotFound = errors.New("repository: 资产组不存在")

// AssetGroupRepository 资产组仓储。
type AssetGroupRepository struct{ db *gorm.DB }

// NewAssetGroupRepository 构建资产组仓储。
func NewAssetGroupRepository(db *gorm.DB) *AssetGroupRepository {
	return &AssetGroupRepository{db: db}
}

// ListAll 返回全部资产组，按物化路径排序。
//
// 不做分页：资产组是「组织结构的投影」，量级在几十到几百，
// 而界面需要一次拿到完整层级才能画树。按 path 排序让结果天然是
// 「先父后子、同层相邻」，服务层可以直接一趟扫描建树。
func (r *AssetGroupRepository) ListAll(ctx context.Context) ([]model.AssetGroup, error) {
	var groups []model.AssetGroup
	err := r.db.WithContext(ctx).Order("path ASC, sort_order ASC, id ASC").Find(&groups).Error
	if err != nil {
		return nil, fmt.Errorf("查询资产组列表失败: %w", err)
	}
	return groups, nil
}

// FindByID 按主键查询。
func (r *AssetGroupRepository) FindByID(ctx context.Context, id uint64) (*model.AssetGroup, error) {
	var g model.AssetGroup
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAssetGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按 ID 查询资产组失败: %w", err)
	}
	return &g, nil
}

// Create 新建资产组。
//
// parentPath 是父组的物化路径（根组传空串）。组自身的 path 只能在拿到
// 自增 ID 之后补全，因此这里是「先插入、再回填」，两步在同一个事务里。
// 不这样做的话就只能自己先生成 ID（比如用雪花号），那会放弃自增主键的
// 简单性，换来的收益却不值。
func (r *AssetGroupRepository) Create(
	ctx context.Context, g *model.AssetGroup, parentPath string,
) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		g.Path = parentPath // 占位，拿到 ID 后覆盖
		if err := tx.Create(g).Error; err != nil {
			return fmt.Errorf("创建资产组失败: %w", err)
		}

		full := parentPath + strconv.FormatUint(g.ID, 10) + "/"
		if err := tx.Model(&model.AssetGroup{}).
			Where("id = ?", g.ID).
			Update("path", full).Error; err != nil {
			return fmt.Errorf("回填资产组路径失败: %w", err)
		}
		g.Path = full
		return nil
	})
}

// Update 更新资产组字段。用 map 而非 struct：struct 模式下 GORM 会跳过
// 零值字段，导致「把说明清空」这类操作静默无效。
func (r *AssetGroupRepository) Update(ctx context.Context, id uint64, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.AssetGroup{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("更新资产组失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		// RowsAffected 为 0 有两种可能：行不存在，或新值与旧值完全相同。
		// 用一次存在性查询把两者区分开——把「保存了但没改任何东西」
		// 误报成 404 会让人以为数据丢了。
		if _, err := r.FindByID(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// Delete 物理删除资产组。
//
// 有子组时会被外键 fk_asset_groups_parent 拦下，有资产时会被
// fk_assets_group 拦下。服务层会先查一次给出可读的错误码，
// 这里的约束是数据库层的兜底——不依赖调用方记得检查。
func (r *AssetGroupRepository) Delete(ctx context.Context, id uint64) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.AssetGroup{})
	if res.Error != nil {
		return fmt.Errorf("删除资产组失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrAssetGroupNotFound
	}
	return nil
}

// ExistsNameUnderParent 判断同一父组下是否已存在同名资产组。
// excludeID > 0 时排除自身（改名的场景）。
func (r *AssetGroupRepository) ExistsNameUnderParent(
	ctx context.Context, parentID *uint64, name string, excludeID uint64,
) (bool, error) {
	// 用 IFNULL 归一而不是 `parent_id IS NULL` 分支：让 SQL 只有一种形态，
	// 也与唯一索引的判据（生成列 parent_key）保持完全一致。
	q := r.db.WithContext(ctx).Model(&model.AssetGroup{}).
		Where("IFNULL(parent_id, 0) = ? AND name = ?", parentKeyOf(parentID), name)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}

	var n int64
	if err := q.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("检查资产组重名失败: %w", err)
	}
	return n > 0, nil
}

// CountChildren 统计直接子组数量。
func (r *AssetGroupRepository) CountChildren(ctx context.Context, id uint64) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&model.AssetGroup{}).
		Where("parent_id = ?", id).Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("统计子组数量失败: %w", err)
	}
	return n, nil
}

// SubtreeIDsByPath 返回某棵子树的全部组 ID（含 groupPath 自身）。
//
// 判据是**该组自己的物化路径**作为前缀，而不是拿 ID 拼出来的 `/<id>/`。
// 这一点必须靠签名来保证：物化路径里带的是完整祖先链（根组 `/1/`、
// 其子组 `/1/4/`、再下一层 `/1/4/9/`），用 ID 拼出来的前缀只对根组成立，
// 对任何一层子组都会匹配到 0 行。
//
// 那个写法曾经真实存在过，后果值得记下来：它不报错、只静默返回空集，
// 症状是「按分组筛选返回 0 条」和「删除仍有资产的组一路放行到数据库
// 外键上才失败（500 而不是可读的 409）」。两者都不会指向物化路径，
// 排查成本极高。改成必须由调用方传入路径，编译器就挡住了重蹈覆辙。
//
// 前缀末尾的斜杠保证 `/1/4/` 不会命中 `/1/41/`；而 LIKE 的 % 能匹配
// 空串，于是组自身也会被包含进来。
func (r *AssetGroupRepository) SubtreeIDsByPath(
	ctx context.Context, groupPath string,
) ([]uint64, error) {
	if groupPath == "" {
		return []uint64{}, nil
	}

	var ids []uint64
	err := r.db.WithContext(ctx).Model(&model.AssetGroup{}).
		Where("path LIKE ?", escapeLike(groupPath)+"%").
		Order("id ASC").Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("查询子树资产组失败: %w", err)
	}
	return ids, nil
}

// MaxDepthInSubtree 返回以 prefix 为根的子树中的最大 depth（0 基）。
//
// 移动资产组前用它判断「搬过去之后最深的那个后代还在不在层数上限之内」。
// 只取一个 MAX(depth) 而不是把整棵子树拉回来：移动操作的合法性
// 只取决于这一个数。
func (r *AssetGroupRepository) MaxDepthInSubtree(ctx context.Context, prefix string) (uint32, error) {
	var maxDepth *uint32
	err := r.db.WithContext(ctx).Model(&model.AssetGroup{}).
		Where("path LIKE ?", escapeLike(prefix)+"%").
		Select("MAX(depth)").Scan(&maxDepth).Error
	if err != nil {
		return 0, fmt.Errorf("查询子树最大层级失败: %w", err)
	}
	if maxDepth == nil {
		return 0, nil
	}
	return *maxDepth, nil
}

// MoveSubtree 把 oldPrefix 标识的整棵子树搬到 newPrefix 之下。
//
// 一条 UPDATE 完成整棵子树的重写，而不是逐层递归：
//
//	path   = CONCAT(新前缀, 去掉旧前缀之后的剩余部分)
//	depth  = depth + 层级差
//
// 以「/1/4/」搬到「/1/7/4/」为例，「/1/4/9/」的剩余部分是「9/」，
// 新路径即「/1/7/4/9/」；组自身的「/1/4/」剩余部分是空串，
// 新路径即「/1/7/4/」，一并被这条语句处理掉，无需特殊分支。
//
// oldPrefix 只可能含数字与斜杠，但 escapeLike 仍然加上——
// 一旦将来有人把 name 拼进路径，这里不会突然退化成通配匹配。
func (r *AssetGroupRepository) MoveSubtree(
	ctx context.Context, oldPrefix, newPrefix string, depthDelta int,
) error {
	const q = `UPDATE asset_groups
SET path  = CONCAT(?, SUBSTRING(path, CHAR_LENGTH(?) + 1)),
    depth = depth + ?
WHERE path LIKE ?`

	pattern := escapeLike(oldPrefix) + "%"
	res := r.db.WithContext(ctx).Exec(q, newPrefix, oldPrefix, depthDelta, pattern)
	if res.Error != nil {
		return fmt.Errorf("移动资产组子树失败: %w", res.Error)
	}
	return nil
}

// NameMap 返回 资产组 ID → 组名 的映射。
//
// 资产列表要显示组名，若逐行去查就是典型的 N+1；一次全量拉回
// （资产组量级很小）比按 ID 集合 IN 查询更简单，也少一次 SQL 构造。
func (r *AssetGroupRepository) NameMap(ctx context.Context) (map[uint64]string, error) {
	var rows []struct {
		ID   uint64
		Name string
	}
	if err := r.db.WithContext(ctx).Model(&model.AssetGroup{}).
		Select("id, name").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查询资产组名称映射失败: %w", err)
	}

	out := make(map[uint64]string, len(rows))
	for _, row := range rows {
		out[row.ID] = row.Name
	}
	return out, nil
}

// IDNameMap 返回「路径可读名 → ID」的映射，供导入时按名称定位资产组。
//
// 键是「总部/华东区/机房A」这样的路径写法，值是组 ID。用它而不是
// 逐层查找，是因为导入一次要解析几百个组名，逐层查找会变成
// 「行数 × 层数」次查询。
func (r *AssetGroupRepository) IDNameMap(ctx context.Context) (map[string]uint64, error) {
	groups, err := r.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	byID := make(map[uint64]*model.AssetGroup, len(groups))
	for i := range groups {
		byID[groups[i].ID] = &groups[i]
	}

	out := make(map[string]uint64, len(groups))
	for i := range groups {
		segments := make([]string, 0, groups[i].Depth+1)
		// 沿 parent_id 上溯拼出可读路径。深度有上限（model.MaxAssetGroupDepth），
		// 所以这个循环最多跑 8 次，不会退化。
		for cur := &groups[i]; cur != nil; {
			segments = append([]string{cur.Name}, segments...)
			if cur.ParentID == nil {
				break
			}
			cur = byID[*cur.ParentID]
		}
		out[joinPath(segments)] = groups[i].ID
	}
	return out, nil
}

// parentKeyOf 把可空的 parent_id 归一为与生成列 parent_key 一致的值。
func parentKeyOf(parentID *uint64) uint64 {
	if parentID == nil {
		return 0
	}
	return *parentID
}

// joinPath 把名称片段拼成可读路径（用 / 分隔，不加首尾斜杠）。
func joinPath(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	n := 0
	for _, s := range segments {
		n += len(s)
	}
	n += len(segments) - 1

	buf := make([]byte, 0, n)
	for i, s := range segments {
		if i > 0 {
			buf = append(buf, '/')
		}
		buf = append(buf, s...)
	}
	return string(buf)
}
