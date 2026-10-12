package model

import "time"

// 刷新令牌的吊销原因。写入 revoke_reason 列，用于事后追溯会话为何失效。
const (
	// RevokeReasonLogout 用户主动登出
	RevokeReasonLogout = "logout"
	// RevokeReasonRotated 正常轮换（旧令牌在换新时作废，属于预期行为）
	RevokeReasonRotated = "rotated"
	// RevokeReasonReuseDetected 检测到已使用的令牌被重放——高度疑似令牌泄露，
	// 此时会连带吊销整条轮换链
	RevokeReasonReuseDetected = "reuse_detected"
	// RevokeReasonPasswordChanged 改密后强制下线其他会话
	RevokeReasonPasswordChanged = "password_changed"
	// RevokeReasonAdmin 管理员禁用账号或重置密码所致
	RevokeReasonAdmin = "admin"
)

// RefreshToken 刷新令牌。
//
// 只保存 SHA-256 摘要，明文令牌仅存在于「响应 → 客户端 Cookie」这一条路径上。
type RefreshToken struct {
	ID     uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	UserID uint64 `gorm:"column:user_id"`
	// TokenHash SHA-256 十六进制摘要，唯一索引保证同一令牌只可能对应一行
	TokenHash string `gorm:"column:token_hash;size:64"`
	// FamilyID 轮换链标识。同一次登录派生的所有令牌共享它，
	// 一旦检测到重放，按此字段一次性吊销整条链。
	FamilyID     string     `gorm:"column:family_id;size:36"`
	IssuedAt     time.Time  `gorm:"column:issued_at"`
	ExpiresAt    time.Time  `gorm:"column:expires_at"`
	UsedAt       *time.Time `gorm:"column:used_at"`
	RevokedAt    *time.Time `gorm:"column:revoked_at"`
	RevokeReason string     `gorm:"column:revoke_reason;size:32"`
	ClientIP     string     `gorm:"column:client_ip;size:64"`
	UserAgent    string     `gorm:"column:user_agent;size:255"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
}

// TableName 指定表名。
func (RefreshToken) TableName() string { return "refresh_tokens" }

// IsUsable 判断令牌在给定时刻是否仍可用于换取新的访问令牌。
func (t *RefreshToken) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && t.RevokedAt == nil && t.ExpiresAt.After(now)
}
