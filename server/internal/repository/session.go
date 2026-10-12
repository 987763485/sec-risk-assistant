package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"secrisk/server/internal/model"
)

// ErrTokenNotFound 刷新令牌不存在。
var ErrTokenNotFound = errors.New("repository: 刷新令牌不存在")

// SessionRepository 刷新令牌仓储。
type SessionRepository struct{ db *gorm.DB }

// NewSessionRepository 构建刷新令牌仓储。
func NewSessionRepository(db *gorm.DB) *SessionRepository { return &SessionRepository{db: db} }

// Create 写入一条刷新令牌记录。
func (r *SessionRepository) Create(ctx context.Context, t *model.RefreshToken) error {
	if err := r.db.WithContext(ctx).Create(t).Error; err != nil {
		return fmt.Errorf("写入刷新令牌失败: %w", err)
	}
	return nil
}

// FindByHash 按摘要查询令牌。明文令牌不落库，因此只能按摘要查找。
func (r *SessionRepository) FindByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	var t model.RefreshToken
	err := r.db.WithContext(ctx).Where("token_hash = ?", hash).Take(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询刷新令牌失败: %w", err)
	}
	return &t, nil
}

// MarkUsed 将令牌标记为「已使用」。
//
// ⚠️ 这是整个刷新流程的并发安全核心。判定与更新必须合并成一条
// 带条件的 UPDATE 交给数据库原子执行：
//
//	UPDATE refresh_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL
//
// 若改成「先 SELECT 判断未使用、再 UPDATE」，两个请求同时刷新时
// 都会读到「未使用」，从而各自签发一套新令牌——旧令牌被用了两次却无人察觉。
// 现在的写法下，只有 RowsAffected == 1 的那个请求算成功，
// 另一个请求会拿到 false，进而触发「令牌重放」处理分支。
func (r *SessionRepository) MarkUsed(ctx context.Context, id uint64, now time.Time) (bool, error) {
	res := r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("id = ? AND used_at IS NULL AND revoked_at IS NULL", id).
		Updates(map[string]any{"used_at": now})
	if res.Error != nil {
		return false, fmt.Errorf("标记刷新令牌已使用失败: %w", res.Error)
	}
	return res.RowsAffected == 1, nil
}

// RevokeByID 吊销单条令牌。
func (r *SessionRepository) RevokeByID(ctx context.Context, id uint64, reason string) error {
	now := time.Now()
	res := r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Updates(map[string]any{"revoked_at": now, "revoke_reason": reason})
	if res.Error != nil {
		return fmt.Errorf("吊销刷新令牌失败: %w", res.Error)
	}
	return nil
}

// RevokeFamily 吊销整条轮换链，返回受影响行数。
//
// 触发场景：检测到已使用的令牌被重放。此时无法分辨「是攻击者拿到了旧令牌」
// 还是「是合法客户端被劫持」，因此把整条链全部作废，强制重新登录。
func (r *SessionRepository) RevokeFamily(ctx context.Context, familyID, reason string) (int64, error) {
	now := time.Now()
	res := r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Updates(map[string]any{"revoked_at": now, "revoke_reason": reason})
	if res.Error != nil {
		return 0, fmt.Errorf("吊销令牌族失败: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// RevokeUserTokens 吊销某账号的全部令牌。
//
// exceptFamilyID 非空时保留该轮换链（用于「改密后踢掉其他设备，但当前设备继续可用」）。
func (r *SessionRepository) RevokeUserTokens(ctx context.Context, userID uint64, reason, exceptFamilyID string) (int64, error) {
	now := time.Now()
	q := r.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID)
	if exceptFamilyID != "" {
		q = q.Where("family_id <> ?", exceptFamilyID)
	}

	res := q.Updates(map[string]any{"revoked_at": now, "revoke_reason": reason})
	if res.Error != nil {
		return 0, fmt.Errorf("吊销账号令牌失败: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// ListActiveByUser 查询账号当前有效的令牌（用于「登录设备」展示）。
func (r *SessionRepository) ListActiveByUser(ctx context.Context, userID uint64) ([]model.RefreshToken, error) {
	var rows []model.RefreshToken
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked_at IS NULL AND used_at IS NULL AND expires_at > ?",
			userID, time.Now()).
		Order("issued_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查询有效会话失败: %w", err)
	}
	return rows, nil
}

// DeleteExpired 清理过期令牌，返回删除行数。
//
// 只删「已过期且已吊销」的：仍在有效期内的记录即便被吊销也要留着，
// 否则审计追溯「这个会话是什么时候被谁踢掉的」就失去了依据。
func (r *SessionRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("expires_at < ? AND revoked_at IS NOT NULL", before).
		Delete(&model.RefreshToken{})
	if res.Error != nil {
		return 0, fmt.Errorf("清理过期令牌失败: %w", res.Error)
	}
	return res.RowsAffected, nil
}
