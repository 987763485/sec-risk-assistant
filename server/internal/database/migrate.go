package database

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	migratemysql "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"

	"secrisk/server/internal/config"
	"secrisk/server/migrations"
)

// Migrate 执行数据库结构迁移（up）。
//
// 刻意不使用 GORM AutoMigrate：AutoMigrate 会静默改表（加列、改索引），
// 生产环境上这是不可接受的隐式变更。所有结构变更必须走 migrations/ 下的
// 显式 SQL 文件，可 review、可回滚、可追溯。
func Migrate(db *gorm.DB, cfg config.Database, logger *slog.Logger) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取底层 *sql.DB 失败: %w", err)
	}

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("加载内嵌迁移文件失败: %w", err)
	}
	defer func() { _ = src.Close() }()

	driver, err := migratemysql.WithInstance(sqlDB, &migratemysql.Config{
		DatabaseName:    cfg.Name,
		MigrationsTable: "schema_migrations",
	})
	if err != nil {
		return fmt.Errorf("初始化 migrate mysql driver 失败: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "mysql", driver)
	if err != nil {
		return fmt.Errorf("初始化 migrate 失败: %w", err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			logger.Info("数据库结构已是最新，无需迁移")
			return nil
		}
		return fmt.Errorf("执行迁移失败: %w", err)
	}

	ver, dirty, verr := m.Version()
	if verr != nil {
		logger.Info("迁移执行完成（版本号不可用）")
		return nil
	}
	logger.Info("迁移执行完成",
		slog.Uint64("schema_version", uint64(ver)),
		slog.Bool("dirty", dirty),
	)
	return nil
}
