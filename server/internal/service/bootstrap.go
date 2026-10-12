package service

import (
	"context"
	"fmt"
	"log/slog"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/model"
	"secrisk/server/internal/repository"
)

// EnsureBootstrapAdmin 在系统内一个账号都没有时创建引导管理员。
//
// 为什么不在 SQL 迁移里直接插入管理员：
// 那意味着把密码哈希写死在版本库里，而这个哈希对所有部署实例都相同。
// 一旦仓库公开或镜像被反查，所有人就都能算出初始密码。
//
// 这里的做法是「启动时按需创建」，密码来自环境变量，且始终带
// must_change_password 标记——首次登录必须改密，管理员本人设定的初始密码
// 因此只在极短的时间窗内有效。
//
// 并发说明：多实例同时启动时可能都通过「无账号」检查，此时由
// users.username 唯一索引兜底，只有一个能创建成功，另一个报错但不致命。
func EnsureBootstrapAdmin(
	ctx context.Context, cfg *config.Config,
	repo *repository.Repository, logger *slog.Logger,
) error {
	if logger == nil {
		logger = slog.Default()
	}

	count, err := repo.User.CountAll(ctx)
	if err != nil {
		return fmt.Errorf("检查账号数量失败: %w", err)
	}
	if count > 0 {
		return nil
	}

	if cfg.Auth.BootstrapPassword == "" {
		logger.Warn("系统内尚无任何账号，但未配置引导管理员密码，" +
			"请设置 SR_AUTH_BOOTSTRAP_PASSWORD 后重启以完成初始化")
		return nil
	}
	if err := auth.ValidatePasswordStrength(cfg.Auth.BootstrapPassword); err != nil {
		return fmt.Errorf("引导管理员密码不符合要求: %w", err)
	}

	roleMap, err := repo.Role.IDMap(ctx, []string{auth.RoleAdmin})
	if err != nil {
		return fmt.Errorf("查询管理员角色失败: %w", err)
	}
	adminRoleID, ok := roleMap[auth.RoleAdmin]
	if !ok {
		return fmt.Errorf("内置角色 %q 不存在，请确认数据库迁移是否已执行", auth.RoleAdmin)
	}

	hash, err := auth.HashPassword(cfg.Auth.BootstrapPassword)
	if err != nil {
		return fmt.Errorf("生成引导管理员密码哈希失败: %w", err)
	}

	displayName := cfg.Auth.BootstrapDisplayName
	if displayName == "" {
		displayName = cfg.Auth.BootstrapUsername
	}

	admin := &model.User{
		Username:     cfg.Auth.BootstrapUsername,
		DisplayName:  displayName,
		PasswordHash: hash,
		Status:       model.UserStatusActive,
		// 这一行是整个引导流程的安全关键：初始密码是一次性的
		MustChangePassword: true,
	}

	if err := repo.User.Create(ctx, admin, []uint64{adminRoleID}); err != nil {
		if isDuplicateKey(err) {
			logger.Info("引导管理员已由其他实例创建，跳过")
			return nil
		}
		return fmt.Errorf("创建引导管理员失败: %w", err)
	}

	logger.Warn("已创建引导管理员账号，请立即登录并修改初始密码",
		"username", admin.Username,
		"must_change_password", true)

	return nil
}
