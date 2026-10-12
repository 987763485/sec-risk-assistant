// Package handler 存放 HTTP 处理器。
package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"secrisk/server/internal/config"
	"secrisk/server/internal/version"
)

// Health 健康检查处理器。
type Health struct {
	cfg *config.Config
	db  *gorm.DB
}

// NewHealth 构造健康检查处理器。
func NewHealth(cfg *config.Config, db *gorm.DB) *Health {
	return &Health{cfg: cfg, db: db}
}

// Live 存活探针：只证明进程还在跑，**不查数据库**。
//
// 这个区分很重要：如果存活探针依赖数据库，数据库短暂抖动会导致容器被
// 反复重启，反而放大故障。
func (h *Health) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": h.cfg.App.Name,
		"version": version.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}

// Ready 就绪探针：逐项检查下游依赖，任一不可用即返回 503。
func (h *Health) Ready(c *gin.Context) {
	checks := gin.H{}
	ready := true

	// 数据库
	dbStatus, dbDetail := h.checkDatabase(c.Request.Context())
	checks["database"] = gin.H{"status": dbStatus, "detail": dbDetail}
	if dbStatus != "ok" {
		ready = false
	}

	status := http.StatusOK
	overall := "ok"
	if !ready {
		status = http.StatusServiceUnavailable
		overall = "degraded"
	}

	c.JSON(status, gin.H{
		"status":  overall,
		"service": h.cfg.App.Name,
		"version": version.Version,
		"env":     h.cfg.App.Env,
		"commit":  version.Commit,
		"checks":  checks,
		"time":    time.Now().Format(time.RFC3339),
	})
}

func (h *Health) checkDatabase(parent context.Context) (string, string) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()

	sqlDB, err := h.db.DB()
	if err != nil {
		return "error", "获取连接池失败: " + err.Error()
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return "error", "ping 失败: " + err.Error()
	}

	stats := sqlDB.Stats()
	return "ok", fmt.Sprintf("连接正常（open=%d inUse=%d idle=%d）",
		stats.OpenConnections, stats.InUse, stats.Idle)
}
