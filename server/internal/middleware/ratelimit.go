package middleware

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/response"
)

// RateLimiter 基于滑动窗口的内存限流器。
//
// 为什么用内存而不是 Redis：本期是单机部署（docker compose 单节点），
// 引入 Redis 会多一个需要运维的组件，收益却只是「重启后计数不清零」。
// 若将来横向扩容，把这个结构体换成 Redis 实现即可，接口不变。
//
// 内存占用：只保留窗口内的命中时间戳，键数 = 窗口内的独立来源数，
// 配合 Cleanup 定时清理，不会随运行时间单调增长。
type RateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

// NewRateLimiter 构建限流器：window 时间窗内最多允许 limit 次。
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{
		limit:  limit,
		window: window,
		hits:   make(map[string][]time.Time),
	}
}

// Limit 返回窗口大小与上限，供接口配置自检。
func (l *RateLimiter) Limit() (int, time.Duration) { return l.limit, l.window }

// Allow 判断某键是否放行。不放行时返回建议的重试等待时长。
func (l *RateLimiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	prev := l.hits[key]

	// 只保留窗口内的命中记录
	kept := make([]time.Time, 0, len(prev)+1)
	for _, t := range prev {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}

	if len(kept) >= l.limit {
		// 最早那次命中滑出窗口后即可重试
		retry := l.window - now.Sub(kept[0])
		if retry < 0 {
			retry = 0
		}
		l.hits[key] = kept
		return false, retry
	}

	l.hits[key] = append(kept, now)
	return true, 0
}

// Reset 清除某个键的计数。登录成功后调用，避免成功登录后仍被历史失败次数拖累。
func (l *RateLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

// Cleanup 清理已滑出窗口的键，防止长期运行下的内存缓慢增长。
func (l *RateLimiter) Cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	for k, ts := range l.hits {
		// 原地压缩：写入位置始终不落后于读取位置，可安全复用底层数组
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(l.hits, k)
			continue
		}
		l.hits[k] = kept
	}
}

// Size 返回当前跟踪的键数量，用于测试与观测。
func (l *RateLimiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}

// RateLimit 按客户端 IP 限流的中间件。
//
// ⚠️ 客户端 IP 的取值依赖 router 中 SetTrustedProxies 的正确配置。
// 若信任了所有代理，攻击者只要伪造 X-Forwarded-For 就能绕过限流
// （同时也会让审计日志中的 IP 失真）。
func RateLimit(limiter *RateLimiter, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		allowed, retry := limiter.Allow(key, time.Now())
		if !allowed {
			seconds := int(retry.Seconds()) + 1
			c.Header("Retry-After", strconv.Itoa(seconds))

			limit, window := limiter.Limit()
			if logger != nil {
				logger.Warn("触发限流",
					"client_ip", key,
					"path", c.Request.URL.Path,
					"limit", limit,
					"window", window.String())
			}

			response.TooManyRequests(c, errcode.CodeTooManyRequests,
				fmt.Sprintf("操作过于频繁，请 %d 秒后重试", seconds))
			return
		}
		c.Next()
	}
}
