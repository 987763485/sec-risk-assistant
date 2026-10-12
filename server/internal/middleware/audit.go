package middleware

import (
	"context"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/sanitize"
)

// AuditRecorder 审计落地接口。由 repository.AuditRepository 实现。
//
// 接口定义在消费方（本包）而非实现方，是 Go 的惯例：
// 这样中间件不依赖 repository，单测可注入任意假实现。
type AuditRecorder interface {
	Record(ctx context.Context, entry model.AuditEntry) error
}

// Audit 审计中间件。
//
// 工作机制：先执行业务（c.Next()），再读取 handler 通过
// reqctx.WithAuditMark 留下的标注并落库。
//
// 为什么要求 handler 显式标注，而不是由中间件按「方法 + 路径」自动推导：
// 自动推导只能得到「POST /api/users」这种机器可读但人不可读的信息，
// 无法区分「新建用户」与「重置密码」，更拿不到变更前后的值。
// 审计日志的价值恰恰在于后者。
//
// 两条并存的审计路径，以及为什么要显式区分：
//   - **中间件记录**：handler 通过 reqctx.WithAuditMark 留下标注，本中间件落库
//   - **service 自行落库**：业务写操作的审计在 service 层写（那里才拿得到
//     「改了哪些字段」这类明细），由 handler 用 reqctx.MarkAuditRecorded 声明
//
// 还有第三种情况——**按设计不该有审计**：导入预览必须用 POST（要传文件），
// 但它只解析校验、不改变任何状态。这种接口由 handler 用
// reqctx.MarkAuditSkipped 声明，否则每次预览都会打一条告警。
//
// 漏标检测：写请求成功却既没有标注、也没有声明已落库或无需审计时打 Warn 日志，
// 让「新接口忘了加审计」在联调阶段就暴露，而不是等合规检查时才发现。
// 漏写的后果刻意设计成「多一条日志」而不是「少一条审计」，因此告警文案
// 同时说明几种可能，避免把方向引偏。
func Audit(recorder AuditRecorder, logger *slog.Logger, skipPaths ...string) gin.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}

	skip := make(map[string]struct{}, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = struct{}{}
	}

	return func(c *gin.Context) {
		c.Next()

		if _, ok := safeMethods[c.Request.Method]; ok {
			return
		}
		if _, ok := skip[c.FullPath()]; ok {
			return
		}

		mark, marked := reqctx.AuditMarkOf(c)
		if !marked {
			// 两种合法的「未标注」：
			//   - service 层已自行落库（业务写操作走的是这条路径），
			//     由 handler 通过 MarkAuditRecorded 声明
			//   - 按设计不产生审计（POST 传文件但只读的接口，如导入预览），
			//     由 handler 通过 MarkAuditSkipped 声明
			if reqctx.AuditRecorded(c) || reqctx.AuditSkipped(c) {
				return
			}
			if c.Writer.Status() < 400 {
				logger.Warn("写操作既未由中间件记录、也未声明已由服务层落库或无需审计，"+
					"若该接口确实没有其它审计路径，本次操作不会留下审计记录",
					"method", c.Request.Method,
					"path", c.Request.URL.Path,
					"request_id", reqctx.RequestID(c))
			}
			return
		}

		entry := model.AuditEntry{
			UserID:     reqctx.UserID(c),
			Username:   reqctx.Username(c),
			Action:     mark.Action,
			Resource:   mark.Resource,
			ResourceID: mark.ResourceID,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			StatusCode: c.Writer.Status(),
			ClientIP:   c.ClientIP(),
			UserAgent:  truncate(c.Request.UserAgent(), 255),
			RequestID:  reqctx.RequestID(c),
		}

		// 明细节统一过一遍敏感字段剔除：即便某个 handler 不小心把整个请求体
		// 塞进 Detail，密码也不会以明文形式落进审计日志。
		entry.Detail = sanitize.JSON(mark.Detail)

		// ⚠️ 必须脱离原请求的 context。
		// 响应写完后原 context 很快会被取消，直接拿它写库会导致
		// 「业务成功、审计丢失」这种最糟糕的情况。
		ctx, cancel := context.WithTimeout(
			context.WithoutCancel(c.Request.Context()), 5*time.Second)
		defer cancel()

		if err := recorder.Record(ctx, entry); err != nil {
			logger.Error("审计日志写入失败",
				"action", entry.Action,
				"resource", entry.Resource,
				"err", err,
				"request_id", entry.RequestID)
		}
	}
}

// truncate 按字节截断字符串，避免超长输入撑爆定长列导致写入失败。
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
