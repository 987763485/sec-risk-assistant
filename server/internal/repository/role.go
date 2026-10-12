package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrRoleNotFound 角色不存在。
var ErrRoleNotFound = errors.New("repository: 角色不存在")

// RoleRepository 角色仓储。
type RoleRepository struct{ db *gorm.DB }

// NewRoleRepository 构建角色仓储。
func NewRoleRepository(db *gorm.DB) *RoleRepository { return &RoleRepository{db: db} }

// List 返回全部角色，按固定顺序输出以保证前端展示稳定。
func (r *RoleRepository) List(ctx context.Context) ([]model.Role, error) {
	var roles []model.Role
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("查询角色列表失败: %w", err)
	}
	return roles, nil
}

// FindByCode 按角色码查询。
func (r *RoleRepository) FindByCode(ctx context.Context, code string) (*model.Role, error) {
	var role model.Role
	err := r.db.WithContext(ctx).Where("code = ?", code).Take(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按角色码查询失败: %w", err)
	}
	return &role, nil
}

// IDMap 返回 角色码 → 角色 ID 的映射，供批量写入关联表使用。
func (r *RoleRepository) IDMap(ctx context.Context, codes []string) (map[string]uint64, error) {
	q := r.db.WithContext(ctx).Model(&model.Role{})
	if len(codes) > 0 {
		q = q.Where("code IN ?", codes)
	}

	var rows []struct {
		ID   uint64
		Code string
	}
	if err := q.Select("id, code").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查询角色 ID 映射失败: %w", err)
	}

	out := make(map[string]uint64, len(rows))
	for _, row := range rows {
		out[row.Code] = row.ID
	}
	return out, nil
}

// LockByCode 在事务内对指定角色行加排他锁。
//
// 用途：把「修改某人的角色分配」串行化。所有涉及管理员角色的变更
// 都先来锁这一行，从而杜绝并发下「两个请求各自认为还有另一个管理员，
// 结果双双摘掉 admin」导致系统失去管理入口的竞态。
func (r *RoleRepository) LockByCode(ctx context.Context, code string) error {
	var id uint64
	err := r.db.WithContext(ctx).
		Raw("SELECT id FROM roles WHERE code = ? FOR UPDATE", code).
		Scan(&id).Error
	if err != nil {
		return fmt.Errorf("锁定角色行失败: %w", err)
	}
	if id == 0 {
		return ErrRoleNotFound
	}
	return nil
}
