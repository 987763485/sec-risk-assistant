package middleware

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	l := NewRateLimiter(3, time.Minute)
	now := time.Now()

	for i := 1; i <= 3; i++ {
		if ok, _ := l.Allow("k", now); !ok {
			t.Fatalf("窗口内第 %d 次应放行", i)
		}
	}

	ok, retry := l.Allow("k", now)
	if ok {
		t.Fatal("超出上限的请求应被拒绝")
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("重试等待时长不合理: %s", retry)
	}
}

func TestRateLimiter_WindowSlides(t *testing.T) {
	l := NewRateLimiter(2, time.Minute)
	base := time.Now()

	l.Allow("k", base)
	l.Allow("k", base.Add(10*time.Second))

	if ok, _ := l.Allow("k", base.Add(20*time.Second)); ok {
		t.Fatal("窗口内第 3 次应被拒绝")
	}

	// 首次命中在 base+60s 处滑出窗口，此时应重新放行
	if ok, _ := l.Allow("k", base.Add(61*time.Second)); !ok {
		t.Fatal("首次命中滑出窗口后应恢复放行")
	}
}

func TestRateLimiter_KeysAreIndependent(t *testing.T) {
	l := NewRateLimiter(1, time.Minute)
	now := time.Now()

	if ok, _ := l.Allow("a", now); !ok {
		t.Fatal("a 第一次应放行")
	}
	if ok, _ := l.Allow("a", now); ok {
		t.Fatal("a 第二次应被拒绝")
	}
	// 另一个键不应受影响——这正是「按 IP 限流」不会被单个来源拖垮的前提
	if ok, _ := l.Allow("b", now); !ok {
		t.Fatal("不同键之间不应互相影响")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	l := NewRateLimiter(1, time.Minute)
	now := time.Now()

	l.Allow("k", now)
	if ok, _ := l.Allow("k", now); ok {
		t.Fatal("第二次应被拒绝")
	}

	l.Reset("k")
	if ok, _ := l.Allow("k", now); !ok {
		t.Fatal("Reset 后应恢复放行（登录成功后清除历史失败计数）")
	}
}

func TestRateLimiter_CleanupReleasesMemory(t *testing.T) {
	l := NewRateLimiter(5, time.Minute)
	now := time.Now()

	l.Allow("a", now)
	l.Allow("b", now)
	if l.Size() != 2 {
		t.Fatalf("应有 2 个跟踪键，实际 %d", l.Size())
	}

	l.Cleanup(now.Add(2 * time.Minute))
	if l.Size() != 0 {
		t.Fatalf("清理后不应残留任何键，实际 %d", l.Size())
	}
}

func TestRateLimiter_ConcurrentSafety(t *testing.T) {
	const limit = 100
	l := NewRateLimiter(limit, time.Minute)
	now := time.Now()

	var allowed int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.Allow("k", now); ok {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()

	if allowed != limit {
		t.Fatalf("并发下放行次数应恰为 %d，实际 %d（存在竞态）", limit, allowed)
	}
}

func TestNewRateLimiter_GuardsInvalidParams(t *testing.T) {
	// 传入 0 或负数时不应产生「永久封锁」或「永不放行」的极端行为
	l := NewRateLimiter(0, 0)
	limit, window := l.Limit()
	if limit < 1 || window <= 0 {
		t.Fatalf("非法参数未被归一化: limit=%d window=%s", limit, window)
	}
}
