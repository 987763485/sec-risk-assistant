// Command api 是 sec-risk-assistant 的主服务入口。
//
// 启动顺序（任一环节失败即退出，绝不带残缺状态对外提供服务）：
//
//	配置加载与校验 → 数据库连接（带重试）→ 结构迁移 → 权限自检
//	→ 引导管理员 → HTTP 监听 → 优雅退出
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/database"
	"secrisk/server/internal/middleware"
	"secrisk/server/internal/repository"
	"secrisk/server/internal/router"
	"secrisk/server/internal/service"
	"secrisk/server/internal/version"
)

func main() {
	migrateOnly := flag.Bool("migrate", false, "仅执行数据库迁移后退出（用于 CI / 运维脚本）")
	flag.Parse()

	// ---- 1. 配置：失败即退出 ----
	cfg, err := config.Load()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[FATAL] 配置加载或校验失败:\n%v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.App.LogLevel)
	slog.SetDefault(logger)

	logger.Info("启动 sec-risk-assistant 主服务",
		slog.String("env", cfg.App.Env),
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
	)

	// ---- 2. 数据库连接（最多等 30 秒，容忍 MySQL 启动慢） ----
	dbCtx, dbCancel := context.WithCancel(context.Background())
	defer dbCancel()

	db, err := database.OpenWithRetry(dbCtx, cfg.Database, cfg.App.LogLevel, 30*time.Second, logger)
	if err != nil {
		logger.Error("数据库连接失败，进程退出", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("数据库连接成功",
		slog.String("host", cfg.Database.Host),
		slog.Int("port", cfg.Database.Port),
		slog.String("database", cfg.Database.Name),
	)

	// ---- 3. 迁移 ----
	if err := database.Migrate(db, cfg.Database, logger); err != nil {
		logger.Error("数据库迁移失败，进程退出", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if *migrateOnly {
		logger.Info("--migrate 模式：迁移完成，退出")
		return
	}

	// ---- 4. 认证基础设施 ----
	//
	// 权限注册表自检放在启动阶段而不是测试里，是为了让容器**启动即失败**。
	// 权限码写错会导致角色「看起来授权了、实际什么都没拿到」，
	// 这类问题如果拖到线上被人点了按钮才发现，排查成本高得多。
	if problems := auth.CheckPermissionRegistry(); len(problems) > 0 {
		for _, p := range problems {
			logger.Error("权限注册表自检失败", slog.String("problem", p))
		}
		logger.Error("进程退出：请修复 internal/auth/rbac.go 中的权限码定义")
		os.Exit(1)
	}

	tokens, err := auth.NewTokenManager(cfg.Auth.JWTSecret, auth.TokenIssuer, cfg.Auth.AccessTTL)
	if err != nil {
		logger.Error("初始化令牌管理器失败，进程退出", slog.String("error", err.Error()))
		os.Exit(1)
	}

	repo := repository.New(db)

	// 引导管理员：仅在系统内一个账号都没有时创建，且强制首次改密
	if err := service.EnsureBootstrapAdmin(
		context.Background(), cfg, repo, logger); err != nil {
		logger.Error("创建引导管理员失败，进程退出", slog.String("error", err.Error()))
		os.Exit(1)
	}

	loginLimiter := middleware.NewRateLimiter(cfg.Auth.LoginRateLimit, cfg.Auth.LoginRateWindow)

	// ---- 5. HTTP 服务 ----
	engine, err := router.New(router.Deps{
		Config:       cfg,
		Repo:         repo,
		Logger:       logger,
		Tokens:       tokens,
		LoginLimiter: loginLimiter,
	}, db)
	if err != nil {
		logger.Error("初始化路由失败，进程退出", slog.String("error", err.Error()))
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      engine,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("HTTP 服务已启动",
			slog.String("addr", srv.Addr),
			slog.String("health", "http://"+srv.Addr+"/api/health"),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// ---- 6. 后台维护任务 ----
	maintCtx, maintCancel := context.WithCancel(context.Background())
	defer maintCancel()
	go runMaintenance(maintCtx, repo, loginLimiter, logger)

	// ---- 7. 优雅退出 ----
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		logger.Error("HTTP 服务异常退出", slog.String("error", err.Error()))
		os.Exit(1)
	case sig := <-quit:
		logger.Info("收到退出信号，开始优雅关闭", slog.String("signal", sig.String()))
	}

	maintCancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP 服务关闭超时，强制退出", slog.String("error", err.Error()))
	} else {
		logger.Info("HTTP 服务已优雅关闭")
	}

	if sqlDB, err := db.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			logger.Warn("关闭数据库连接出错", slog.String("error", err.Error()))
		}
	}

	logger.Info("进程已退出")
}

// runMaintenance 周期性清理内存与数据库中的过期数据。
//
// 单机部署下这些都是「小数据、低频次」的清理：
// 跑得太频繁是浪费，永远不跑则会缓慢积累成问题。
func runMaintenance(
	ctx context.Context, repo *repository.Repository,
	limiter *middleware.RateLimiter, logger *slog.Logger,
) {
	ticker := time.NewTicker(maintenanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			// 限流器：清掉已滑出窗口的键，防止长期运行下内存缓慢增长
			limiter.Cleanup(now)

			// 刷新令牌：只删「已过期且已吊销」的记录。
			// 仍在有效期内的记录即便已吊销也必须留着——
			// 否则追溯「这个会话是什么时候被谁踢掉的」就失去了依据。
			n, err := repo.Session.DeleteExpired(ctx, now)
			if err != nil {
				logger.Warn("清理过期刷新令牌失败", slog.String("error", err.Error()))
				continue
			}
			if n > 0 {
				logger.Info("已清理过期刷新令牌", slog.Int64("count", n))
			}
		}
	}
}

// maintenanceInterval 后台维护间隔。
const maintenanceInterval = 1 * time.Hour

// newLogger 构建结构化 JSON 日志器。
func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
