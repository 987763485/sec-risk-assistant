// Package database 负责 MySQL 连接、连接池调优与迁移执行。
package database

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"secrisk/server/internal/config"
)

// Open 建立数据库连接并完成一次 ping 自检。
func Open(cfg config.Database, logLevel string) (*gorm.DB, error) {
	gormLogLevel := gormlogger.Warn
	if logLevel == "debug" {
		gormLogLevel = gormlogger.Info
	}

	db, err := gorm.Open(gormmysql.Open(cfg.DSN()), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormLogLevel),
		// 单条写操作不需要隐式事务包裹，避免不必要的 BEGIN/COMMIT
		SkipDefaultTransaction: true,
		// 与 MySQL DATETIME(3) 对齐
		NowFunc: func() time.Time { return time.Now().Local() },
	})
	if err != nil {
		return nil, fmt.Errorf("gorm.Open 失败: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取底层 *sql.DB 失败: %w", err)
	}

	if cfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("数据库 ping 失败: %w", err)
	}

	return db, nil
}

// OpenWithRetry 带重试地建立连接。
//
// 必要性：compose 环境里 server 启动时 MySQL 未必已就绪；即便声明了
// depends_on + healthcheck，跨主机部署时也不能依赖启动顺序。宁可等，
// 也不要以「连接失败」为由退出。
func OpenWithRetry(
	ctx context.Context,
	cfg config.Database,
	logLevel string,
	timeout time.Duration,
	logger *slog.Logger,
) (*gorm.DB, error) {
	deadline := time.Now().Add(timeout)

	for attempt := 1; ; attempt++ {
		db, err := Open(cfg, logLevel)
		if err == nil {
			return db, nil
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("等待数据库就绪超时（%s），最后一次错误: %w", timeout, err)
		}

		logger.Warn("数据库尚未就绪，2 秒后重试",
			slog.Int("attempt", attempt),
			slog.String("error", err.Error()),
		)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
