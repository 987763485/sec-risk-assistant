package repository

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// SystemConfigRepository 系统配置仓储。
type SystemConfigRepository struct{ db *gorm.DB }

// NewSystemConfigRepository 构建系统配置仓储。
func NewSystemConfigRepository(db *gorm.DB) *SystemConfigRepository {
	return &SystemConfigRepository{db: db}
}

// ListByKeys 按配置键前缀查询。
//
// 用前缀而不是「全部配置」：这张表接下来还会承载非风险类的系统配置，
// 把整表返回给风险评估页既多余，也让前端拿得到与它无关的设置项。
func (r *SystemConfigRepository) ListByKeys(ctx context.Context, keys []string) ([]model.SystemConfig, error) {
	var rows []model.SystemConfig
	q := r.db.WithContext(ctx).Model(&model.SystemConfig{})
	if len(keys) > 0 {
		q = q.Where("config_key IN ?", keys)
	}
	if err := q.Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查询系统配置失败: %w", err)
	}
	return rows, nil
}

// ListByPrefix 按键前缀查询（如 "risk."）。
func (r *SystemConfigRepository) ListByPrefix(ctx context.Context, prefix string) ([]model.SystemConfig, error) {
	var rows []model.SystemConfig
	err := r.db.WithContext(ctx).Model(&model.SystemConfig{}).
		Where("config_key LIKE ?", escapeLike(prefix)+"%").
		Order("id ASC").Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询系统配置失败: %w", err)
	}
	return rows, nil
}

// ValuesByPrefix 返回「键 → 值」映射，供服务层读取风险模型配置。
func (r *SystemConfigRepository) ValuesByPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	rows, err := r.ListByPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.ConfigKey] = strings.TrimSpace(row.ConfigValue)
	}
	return out, nil
}

// UpdateValues 批量更新配置值。
//
// 不做 upsert（不 INSERT）：配置表的行是与代码配套的「出厂设置」，
// 允许接口凭空插入新键，就等于允许前端把任意键写进库，而代码根本不认识
// 它们——这类「幽灵配置」不会报错，只会在某次读配置时静默多出一个默认值。
// 因此「键是否存在」必须由服务层先读一遍确认，本方法只负责写。
//
// ⚠️ 刻意**不**检查 RowsAffected：MySQL 对「值没有变化」的 UPDATE 同样
// 返回 0 行受影响，于是「键不存在」与「提交了相同的值」在这里完全不可
// 区分（除非开 CLIENT_FOUND_ROWS）。按 RowsAffected 报 404 会让
// 「不改数值直接点保存」变成一个莫名其妙的错误。
func (r *SystemConfigRepository) UpdateValues(ctx context.Context, values map[string]string) error {
	for key, value := range values {
		err := r.db.WithContext(ctx).Model(&model.SystemConfig{}).
			Where("config_key = ?", key).
			Update("config_value", value).Error
		if err != nil {
			return fmt.Errorf("更新系统配置 %s 失败: %w", key, err)
		}
	}
	return nil
}
