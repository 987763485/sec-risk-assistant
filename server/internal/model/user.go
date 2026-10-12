// Package model 定义与数据库表一一对应的持久化模型。
//
// 约定：
//  1. 每个模型显式实现 TableName()，不依赖 GORM 的复数化推断——
//     表名一旦漂移，错误只会以「表不存在」的形式在运行时暴露。
//  2. 可空列一律用指针类型（*string / *time.Time），
//     避免零值被误写为真实数据（例如空的 locked_until 把账号永久锁死）。
//  3. 结构体**不加 GORM 关联标签**。角色关联由 repository 显式维护，
//     以换取 SQL 的完全可见性，并规避关联预加载带来的 N+1 查询。
package model

import "time"

// UserStatus 账号状态。
type UserStatus string

const (
	// UserStatusActive 正常可用
	UserStatusActive UserStatus = "active"
	// UserStatusDisabled 已禁用。禁用用户无法登录，
	// 且已签发的 Access Token 在下次请求时即被拒绝（权限每次请求现查）。
	UserStatusDisabled UserStatus = "disabled"
)

// Valid 判断状态值是否合法。
func (s UserStatus) Valid() bool {
	return s == UserStatusActive || s == UserStatusDisabled
}

// User 账号。
type User struct {
	ID          uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	Username    string `gorm:"column:username;size:64"`
	DisplayName string `gorm:"column:display_name;size:64"`
	// Email 可空。唯一索引下多个 NULL 互不冲突，而空串会互相冲突，
	// 因此「未填邮箱」必须存 NULL 而非 ""。
	Email        *string    `gorm:"column:email;size:128"`
	PasswordHash string     `gorm:"column:password_hash;size:255"`
	Status       UserStatus `gorm:"column:status;size:16"`

	MustChangePassword  bool       `gorm:"column:must_change_password"`
	FailedLoginAttempts uint32     `gorm:"column:failed_login_attempts"`
	LockedUntil         *time.Time `gorm:"column:locked_until"`
	LastLoginAt         *time.Time `gorm:"column:last_login_at"`
	LastLoginIP         string     `gorm:"column:last_login_ip;size:64"`
	PasswordChangedAt   *time.Time `gorm:"column:password_changed_at"`
	// TokenNotBefore 访问令牌生效下界。登出时写入当前时间，
	// 使该账号此前签发的所有访问令牌立即失效（详见迁移 000003 的说明）。
	TokenNotBefore *time.Time `gorm:"column:token_not_before"`
	CreatedBy      *uint64    `gorm:"column:created_by"`
	CreatedAt      time.Time  `gorm:"column:created_at"`
	UpdatedAt      time.Time  `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (User) TableName() string { return "users" }

// IsLocked 判断账号在给定时刻是否处于锁定状态。
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// IsActive 判断账号是否可登录。
func (u *User) IsActive() bool { return u.Status == UserStatusActive }

// EmailValue 返回邮箱字符串（未填时为空串），便于直接参与 JSON 序列化。
func (u *User) EmailValue() string {
	if u.Email == nil {
		return ""
	}
	return *u.Email
}

// Role 角色。
type Role struct {
	ID          uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	Code        string    `gorm:"column:code;size:32"`
	Name        string    `gorm:"column:name;size:64"`
	Description string    `gorm:"column:description;size:255"`
	IsBuiltin   bool      `gorm:"column:is_builtin"`
	CreatedAt   time.Time `gorm:"column:created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (Role) TableName() string { return "roles" }

// UserRole 账号角色关联。
//
// 仅用于批量写入，不含业务逻辑。关联关系由 repository 显式维护，
// 不使用 GORM 的 many2many 关联——这样才能对实际执行的 SQL 完全掌握，
// 也避免关联预加载在不经意间退化成 N+1 查询。
type UserRole struct {
	UserID uint64 `gorm:"column:user_id;primaryKey"`
	RoleID uint64 `gorm:"column:role_id;primaryKey"`
}

// TableName 指定表名。
func (UserRole) TableName() string { return "user_roles" }

// RoleBrief 角色的精简视图，用于随用户列表一并返回。
type RoleBrief struct {
	ID   uint64 `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}
