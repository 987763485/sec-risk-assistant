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

// ErrUserNotFound 用户不存在。
//
// 仓储层不返回 gorm.ErrRecordNotFound，让上层不必依赖 ORM 细节。
var ErrUserNotFound = errors.New("repository: 用户不存在")

// UserListQuery 用户列表查询条件。
type UserListQuery struct {
	Keyword  string           // 匹配登录名 / 显示名 / 邮箱
	Status   model.UserStatus // 精确匹配状态，空串表示不限
	RoleCode string           // 按角色过滤，空串表示不限
	Page     int
	PageSize int
}

// UserRepository 账号仓储。
type UserRepository struct{ db *gorm.DB }

// NewUserRepository 构建账号仓储。
func NewUserRepository(db *gorm.DB) *UserRepository { return &UserRepository{db: db} }

// FindByID 按主键查询。用于认证中间件每次请求加载用户状态。
func (r *UserRepository) FindByID(ctx context.Context, id uint64) (*model.User, error) {
	var u model.User
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按 ID 查询用户失败: %w", err)
	}
	return &u, nil
}

// FindByUsername 按登录名查询。
func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	var u model.User
	err := r.db.WithContext(ctx).Where("username = ?", username).Take(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("按登录名查询用户失败: %w", err)
	}
	return &u, nil
}

// List 分页查询账号列表。
//
// 过滤条件全部下推 SQL；总数与当页数据各查一次（而不是把全量拉回来再切分），
// 这样即便账号规模增长，单次请求的内存占用与网络传输都保持恒定。
func (r *UserRepository) List(ctx context.Context, q UserListQuery) ([]model.User, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.User{})

	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		like := "%" + escapeLike(kw) + "%"
		base = base.Where(
			"(username LIKE ? OR display_name LIKE ? OR email LIKE ?)",
			like, like, like,
		)
	}
	if q.Status != "" {
		base = base.Where("status = ?", q.Status)
	}
	if q.RoleCode != "" {
		// 用 EXISTS 子查询而非 JOIN：避免一个用户挂多个角色时结果集出现重复行，
		// 也让「总数」与「当页数据」的口径天然一致。
		base = base.Where(
			"EXISTS (SELECT 1 FROM user_roles ur JOIN roles ro ON ro.id = ur.role_id "+
				"WHERE ur.user_id = users.id AND ro.code = ?)", q.RoleCode)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计用户总数失败: %w", err)
	}

	var users []model.User
	err := base.Order("id ASC").
		Limit(q.PageSize).
		Offset((q.Page - 1) * q.PageSize).
		Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("查询用户列表失败: %w", err)
	}
	return users, total, nil
}

// Create 新建账号并绑定角色，两者在同一事务内完成。
func (r *UserRepository) Create(ctx context.Context, u *model.User, roleIDs []uint64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(u).Error; err != nil {
			return fmt.Errorf("创建用户失败: %w", err)
		}
		return replaceRoles(ctx, tx, u.ID, roleIDs)
	})
}

// UpdateProfile 更新资料。用 map 而非 struct 更新：
// struct 模式下 GORM 会跳过零值字段，导致「把显示名清空」这类操作无效。
func (r *UserRepository) UpdateProfile(ctx context.Context, id uint64, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	fields["updated_at"] = time.Now()

	res := r.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("更新用户资料失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetStatus 启用或禁用账号。
func (r *UserRepository) SetStatus(ctx context.Context, id uint64, status model.UserStatus) error {
	return r.UpdateProfile(ctx, id, map[string]any{"status": status})
}

// UpdatePassword 更新密码哈希，并可选地重置「强制改密」标记。
func (r *UserRepository) UpdatePassword(ctx context.Context, id uint64, hash string, mustChange bool) error {
	now := time.Now()
	return r.UpdateProfile(ctx, id, map[string]any{
		"password_hash":        hash,
		"must_change_password": mustChange,
		"password_changed_at":  now,
	})
}

// RecordLoginSuccess 记录登录成功：清零失败计数、解除锁定、写入最近登录信息。
func (r *UserRepository) RecordLoginSuccess(ctx context.Context, id uint64, clientIP string) error {
	now := time.Now()
	return r.UpdateProfile(ctx, id, map[string]any{
		"failed_login_attempts": 0,
		"locked_until":          nil, // 显式置 NULL，否则锁定状态会残留
		"last_login_at":         now,
		"last_login_ip":         clientIP,
	})
}

// RecordLoginFailure 记录一次登录失败，达到阈值时锁定账号。
//
// ⚠️ 这里必须用原生 SQL 且**顺序不可调换**。原因：MySQL 的 UPDATE 是
// 「从左到右求值，后面的表达式能看到前面赋值的**结果**」，而标准 SQL 是
// 取原始值。因此若先自增 failed_login_attempts，后面 CASE 里的
// `failed_login_attempts + 1` 就会拿到自增后的值，等于多加一次，
// 阈值判定会提前触发。
// 把 locked_until 放在前面、让它读到自增前的值，语义才正确。
// 另外 GORM 的 Updates(map) 会对键排序，无法保证语句内顺序，故不能用它。
func (r *UserRepository) RecordLoginFailure(
	ctx context.Context, id uint64, maxAttempts uint32, lockUntil time.Time,
) error {
	const q = `UPDATE users
SET locked_until = CASE WHEN failed_login_attempts + 1 >= ? THEN ? ELSE locked_until END,
    failed_login_attempts = failed_login_attempts + 1,
    updated_at = ?
WHERE id = ?`

	res := r.db.WithContext(ctx).Exec(q, maxAttempts, lockUntil, time.Now(), id)
	if res.Error != nil {
		return fmt.Errorf("记录登录失败次数失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ClearLoginFailures 手动解除锁定（管理员操作或成功登录后调用）。
func (r *UserRepository) ClearLoginFailures(ctx context.Context, id uint64) error {
	return r.UpdateProfile(ctx, id, map[string]any{
		"failed_login_attempts": 0,
		"locked_until":          nil,
	})
}

// SetTokenNotBefore 更新访问令牌生效下界。
//
// 用于登出：把下界设为当前时间后，该账号此前签发的所有访问令牌
// 在认证中间件的下界校验处立即被拒——等效于「立刻把此人踢下线」，
// 且不需要为每个 JWT 落一条吊销记录。
func (r *UserRepository) SetTokenNotBefore(ctx context.Context, id uint64, at time.Time) error {
	return r.UpdateProfile(ctx, id, map[string]any{"token_not_before": at})
}

// ReplaceRoles 覆盖式设置账号角色（先清空再写入），在事务内完成。
func (r *UserRepository) ReplaceRoles(ctx context.Context, userID uint64, roleIDs []uint64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return replaceRoles(ctx, tx, userID, roleIDs)
	})
}

func replaceRoles(ctx context.Context, tx *gorm.DB, userID uint64, roleIDs []uint64) error {
	if err := tx.WithContext(ctx).
		Exec("DELETE FROM user_roles WHERE user_id = ?", userID).Error; err != nil {
		return fmt.Errorf("清空用户角色失败: %w", err)
	}
	if len(roleIDs) == 0 {
		return nil
	}

	// 去重后再批量插入，避免触发主键冲突
	seen := make(map[uint64]struct{}, len(roleIDs))
	rows := make([]model.UserRole, 0, len(roleIDs))
	for _, rid := range roleIDs {
		if _, dup := seen[rid]; dup {
			continue
		}
		seen[rid] = struct{}{}
		rows = append(rows, model.UserRole{UserID: userID, RoleID: rid})
	}

	if err := tx.WithContext(ctx).Create(&rows).Error; err != nil {
		return fmt.Errorf("写入用户角色失败: %w", err)
	}
	return nil
}

// RolesOf 批量查询多个账号的角色，返回 userID → 角色列表。
//
// 一次 IN 查询解决列表页的角色展示，避免「每个用户查一次角色」的 N+1。
func (r *UserRepository) RolesOf(ctx context.Context, userIDs []uint64) (map[uint64][]model.RoleBrief, error) {
	out := make(map[uint64][]model.RoleBrief, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}

	var rows []struct {
		UserID uint64
		ID     uint64
		Code   string
		Name   string
	}
	err := r.db.WithContext(ctx).
		Table("user_roles AS ur").
		Select("ur.user_id, ro.id, ro.code, ro.name").
		Joins("JOIN roles AS ro ON ro.id = ur.role_id").
		Where("ur.user_id IN ?", userIDs).
		Order("ur.user_id ASC, ro.id ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("批量查询用户角色失败: %w", err)
	}

	for _, row := range rows {
		out[row.UserID] = append(out[row.UserID], model.RoleBrief{
			ID: row.ID, Code: row.Code, Name: row.Name,
		})
	}
	return out, nil
}

// RolesOfUser 查询单个账号的角色码。
func (r *UserRepository) RolesOfUser(ctx context.Context, userID uint64) ([]string, error) {
	m, err := r.RolesOf(ctx, []uint64{userID})
	if err != nil {
		return nil, err
	}
	briefs := m[userID]
	codes := make([]string, 0, len(briefs))
	for _, b := range briefs {
		codes = append(codes, b.Code)
	}
	return codes, nil
}

// CountActiveAdmins 统计启用状态的管理员数量。
//
// excludeUserID 用于「判断移除某人管理员身份后是否还有人能管系统」，
// 传 0 表示不排除任何人。
func (r *UserRepository) CountActiveAdmins(ctx context.Context, excludeUserID uint64) (int64, error) {
	q := r.db.WithContext(ctx).
		Table("users AS u").
		Joins("JOIN user_roles AS ur ON ur.user_id = u.id").
		Joins("JOIN roles AS ro ON ro.id = ur.role_id").
		Where("ro.code = ? AND u.status = ?", "admin", model.UserStatusActive)
	if excludeUserID > 0 {
		q = q.Where("u.id <> ?", excludeUserID)
	}

	var n int64
	if err := q.Distinct("u.id").Count(&n).Error; err != nil {
		return 0, fmt.Errorf("统计管理员数量失败: %w", err)
	}
	return n, nil
}

// ExistsUsername 判断登录名是否已被占用。excludeID > 0 时排除自身（编辑场景）。
func (r *UserRepository) ExistsUsername(ctx context.Context, username string, excludeID uint64) (bool, error) {
	q := r.db.WithContext(ctx).Model(&model.User{}).Where("username = ?", username)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}
	var n int64
	if err := q.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("检查登录名是否存在失败: %w", err)
	}
	return n > 0, nil
}

// ExistsEmail 判断邮箱是否已被占用。
func (r *UserRepository) ExistsEmail(ctx context.Context, email string, excludeID uint64) (bool, error) {
	q := r.db.WithContext(ctx).Model(&model.User{}).Where("email = ?", email)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}
	var n int64
	if err := q.Limit(1).Count(&n).Error; err != nil {
		return false, fmt.Errorf("检查邮箱是否存在失败: %w", err)
	}
	return n > 0, nil
}

// CountAll 统计账号总数。用于判断是否需要创建引导管理员。
func (r *UserRepository) CountAll(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.WithContext(ctx).Model(&model.User{}).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("统计账号总数失败: %w", err)
	}
	return n, nil
}

// NamesByIDs 批量取显示名，返回 用户 ID → 显示名。
//
// 显示名优先取 display_name，为空时退化为 username——列表页那一列
// 若显示成空白，用户没法判断「这张单子到底派给了谁」，而空 display_name
// 在数据上是完全合法的（users 表允许它为空串）。
//
// 取不到的 ID 不出现在结果里（账号可能已被删）；调用方按「查不到就留空」
// 处理，而不是把它当成错误——一张整改单不该因为负责人账号被删而打不开。
func (r *UserRepository) NamesByIDs(ctx context.Context, ids []uint64) (map[uint64]string, error) {
	out := make(map[uint64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	var rows []struct {
		ID          uint64
		Username    string
		DisplayName string
	}
	err := r.db.WithContext(ctx).Model(&model.User{}).
		Select("id, username, display_name").
		Where("id IN ?", ids).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("批量查询用户显示名失败: %w", err)
	}
	for _, row := range rows {
		if strings.TrimSpace(row.DisplayName) != "" {
			out[row.ID] = row.DisplayName
			continue
		}
		out[row.ID] = row.Username
	}
	return out, nil
}

// escapeLike 转义 LIKE 模式中的通配符。
//
// 不转义的话，用户搜索 "%" 会匹配全部记录、搜索 "_" 会匹配任意单字符，
// 属于典型的「输入被当作语法」问题。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}
