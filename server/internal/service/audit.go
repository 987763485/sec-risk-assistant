package service

import (
	"context"
	"log/slog"

	"secrisk/server/internal/model"
	"secrisk/server/internal/repository"
)

// auditor 审计写入辅助。
//
// 抽成独立小对象而不是散落在各 service 方法里，是为了统一一个关键决策：
// **审计失败不改变业务结果**。
//
// 理由：调用到这个位置时，业务写操作通常已经提交。若此时把请求改判为失败，
// 用户会以为操作没生效而重复提交——由此产生的重复数据，比丢掉一条审计记录
// 严重得多。因此这里只记 Error 日志并放行，由日志告警链路兜住。
//
// 代价说清楚：极端情况下（数据库审计表写入持续失败）会出现「有业务、无审计」。
// 这是权衡后的取舍，不是疏忽。
type auditor struct {
	repo   *repository.Repository
	logger *slog.Logger
}

func newAuditor(repo *repository.Repository, logger *slog.Logger) *auditor {
	if logger == nil {
		logger = slog.Default()
	}
	return &auditor{repo: repo, logger: logger}
}

// record 写入一条审计记录。失败只记日志。
func (a *auditor) record(ctx context.Context, entry model.AuditEntry) {
	if err := a.repo.Audit.Record(ctx, entry); err != nil {
		a.logger.Error("审计日志写入失败",
			"action", entry.Action,
			"username", entry.Username,
			"path", entry.Path,
			"err", err,
			"request_id", entry.RequestID)
	}
}

// recordAsync 在独立 goroutine 中写入审计记录。
//
// 用于「响应不需要等待审计落库」的场景，比如登录失败——
// 登录失败的响应时间若包含一次数据库写，会变成一个可被利用的
// 账号存在性探测侧信道（存在账号与不存在账号的耗时不同）。
func (a *auditor) recordAsync(entry model.AuditEntry) {
	// 用 Background 而非请求 context：请求结束后 context 会被取消，
	// 直接使用会导致 goroutine 里的写库操作立即失败。
	go func() {
		a.record(context.Background(), entry)
	}()
}
