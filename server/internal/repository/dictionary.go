package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrDictionaryNotFound 字典项不存在。
var ErrDictionaryNotFound = errors.New("repository: 字典项不存在")

// DictionaryRepository 业务字典仓储。
type DictionaryRepository struct{ db *gorm.DB }

// NewDictionaryRepository 构建字典仓储。
func NewDictionaryRepository(db *gorm.DB) *DictionaryRepository {
	return &DictionaryRepository{db: db}
}

// List 按类目查询字典项。
//
// categories 为空表示不限类目。enabledOnly 为 true 时只返回启用项
// （新建表单用），为 false 时连停用项一并返回（字典维护页与管理端
// 展示历史名称时必须能看到停用项，否则一个已停用的类型在资产列表里
// 会显示成空白）。
func (r *DictionaryRepository) List(
	ctx context.Context, categories []model.DictionaryCategory, enabledOnly bool,
) ([]model.Dictionary, error) {
	q := r.db.WithContext(ctx).Model(&model.Dictionary{})
	if len(categories) > 0 {
		q = q.Where("category IN ?", categories)
	}
	if enabledOnly {
		q = q.Where("enabled = ?", true)
	}

	var items []model.Dictionary
	// 排序用「类目 → 自定义顺序 → 内置优先 → id」四级。
	// 加 id 作为最后一级是为了消除排序键完全相同（同一 sort_order）
	// 时 MySQL 返回顺序不确定的问题——列表在两次刷新之间乱序是很
	// 容易被当成 bug 报上来的。
	err := q.Order("category ASC, sort_order ASC, is_builtin DESC, id ASC").
		Find(&items).Error
	if err != nil {
		return nil, fmt.Errorf("查询字典列表失败: %w", err)
	}
	return items, nil
}

// FindByID 按主键查询。
func (r *DictionaryRepository) FindByID(ctx context.Context, id uint64) (*model.Dictionary, error) {
	var d model.Dictionary
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDictionaryNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按 ID 查询字典项失败: %w", err)
	}
	return &d, nil
}

// Create 新建字典项。
func (r *DictionaryRepository) Create(ctx context.Context, d *model.Dictionary) error {
	if err := r.db.WithContext(ctx).Create(d).Error; err != nil {
		return fmt.Errorf("创建字典项失败: %w", err)
	}
	return nil
}

// Update 更新字典项字段。用 map 而非 struct：
// struct 模式下 GORM 会跳过零值字段，"把 weight 改成 0" 或
// "把 enabled 关掉" 都会静默失效。
func (r *DictionaryRepository) Update(ctx context.Context, id uint64, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Dictionary{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("更新字典项失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		if _, err := r.FindByID(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// Delete 物理删除字典项。
//
// 服务层必须先确认「非内置 且 未被引用」。这里不做额外保护——
// 引用关系是业务规则（资产按 code 引用，没有外键），必须在服务层判定。
func (r *DictionaryRepository) Delete(ctx context.Context, id uint64) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Dictionary{})
	if res.Error != nil {
		return fmt.Errorf("删除字典项失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrDictionaryNotFound
	}
	return nil
}

// ExistsCode 判断同一类目下码是否已存在。excludeID > 0 时排除自身。
func (r *DictionaryRepository) ExistsCode(
	ctx context.Context, category model.DictionaryCategory, code string, excludeID uint64,
) (bool, error) {
	q := r.db.WithContext(ctx).Model(&model.Dictionary{}).
		Where("category = ? AND code = ?", category, code)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}

	var n int64
	if err := q.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("检查字典码是否存在失败: %w", err)
	}
	return n > 0, nil
}

// Resolve 返回指定类目下的 码 → 字典项 映射，供批量校验使用。
//
// enabledOnly 为 false：校验资产时**停用**的类型也要能被解析出来。
// 否则「修改一个用着已停用类型的资产」会因为「类型不存在」而被拒绝，
// 用户明明什么都没改却保存不了——这种死锁体验很糟糕。
// 「是否允许新建时选用停用类型」是另一条规则，由服务层单独判断。
func (r *DictionaryRepository) Resolve(
	ctx context.Context, category model.DictionaryCategory,
) (map[string]model.Dictionary, error) {
	var items []model.Dictionary
	err := r.db.WithContext(ctx).
		Where("category = ?", category).
		Find(&items).Error
	if err != nil {
		return nil, fmt.Errorf("解析字典类目失败: %w", err)
	}

	out := make(map[string]model.Dictionary, len(items))
	for _, item := range items {
		out[item.Code] = item
	}
	return out, nil
}
