// Package reqctx 集中管理 gin.Context 上的跨层数据传递。
//
// 单独成包的动机：response 包需要读取 request_id 才能填充统一响应信封，
// 而中间件又需要调用 response 写错误响应。若 request_id 的存取放在
// middleware 包里，这两个包就会互相 import 形成循环依赖。
// 把这一小撮上下文键值操作下沉到本包，依赖方向变为单向：
//
//	response ─┐
//	          ├─→ reqctx ─→ auth
//	middleware ┘
package reqctx

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/auth"
)

// Context 键名。集中定义，避免各处以字符串字面量读写导致对不上。
const (
	KeyRequestID = "request_id"
	KeyPrincipal = "principal"
	KeyAuditMark = "audit_mark"
	// KeyAuditRecorded 标记「本次请求的审计已由 service 层自行落库」。
	KeyAuditRecorded = "audit_recorded"
	// KeyAuditSkipped 标记「本次请求按设计不产生审计记录」。
	KeyAuditSkipped = "audit_skipped"
)

// WithRequestID 写入请求 ID。
func WithRequestID(c *gin.Context, id string) { c.Set(KeyRequestID, id) }

// RequestID 读取请求 ID；缺失返回空串而非 panic，日志场景不应因此中断。
func RequestID(c *gin.Context) string {
	if v, ok := c.Get(KeyRequestID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WithPrincipal 写入认证主体，由 Authn 中间件调用。
func WithPrincipal(c *gin.Context, p *auth.Principal) { c.Set(KeyPrincipal, p) }

// Principal 读取认证主体。第二个返回值表示当前请求是否已通过认证。
func Principal(c *gin.Context) (*auth.Principal, bool) {
	v, ok := c.Get(KeyPrincipal)
	if !ok {
		return nil, false
	}
	p, ok := v.(*auth.Principal)
	if !ok || p == nil {
		return nil, false
	}
	return p, true
}

// UserID 便捷读取当前用户 ID；未认证返回 0。
func UserID(c *gin.Context) uint64 {
	if p, ok := Principal(c); ok {
		return p.UserID
	}
	return 0
}

// Username 便捷读取当前用户名；未认证返回空串。
func Username(c *gin.Context) string {
	if p, ok := Principal(c); ok {
		return p.Username
	}
	return ""
}

// AuditMark 审计标注。由 handler 在业务成功后就地填写，
// 审计中间件在请求结束时读取并落库。
//
// 之所以要求 handler 显式标注而不是由中间件自动推导：自动推导只能得到
// 「POST /api/users」这类机器可读但人不可读的信息，无法区分「创建用户」
// 与「重置密码」，也拿不到变更前后的值。审计日志的价值恰恰在于后者。
type AuditMark struct {
	Action     string // 动作码，如 user.create
	Resource   string // 资源类型，如 user
	ResourceID string // 资源标识
	Detail     any    // 变更明细，将被序列化为 JSON
}

// WithAuditMark 写入审计标注。
func WithAuditMark(c *gin.Context, mark AuditMark) { c.Set(KeyAuditMark, mark) }

// AuditMarkOf 读取审计标注。
func AuditMarkOf(c *gin.Context) (AuditMark, bool) {
	v, ok := c.Get(KeyAuditMark)
	if !ok {
		return AuditMark{}, false
	}
	m, ok := v.(AuditMark)
	if !ok || m.Action == "" {
		return AuditMark{}, false
	}
	return m, true
}

// MarkAuditRecorded 声明「本次请求的审计已经由 service 层自行落库」。
//
// 为什么需要这个声明：业务服务自己落库时（`auditor.record`）能拿到
// 「改了哪些字段」「导入了多少行」这类只有 service 层才知道的明细，
// 因此 P1 起业务写操作的审计是在 service 层写的；而审计中间件按设计
// 只在 handler 显式标注时才记录。两条路径并存的结果是中间件把每一个
// 已审计的写请求都当成「漏审计」并打 Warn —— 一条既嘈杂、字面上又不
// 成立的日志，久了就会被当成噪声忽略，真正的漏审计也就跟着被忽略了。
//
// 因此由 handler 显式声明一次。漏写这个声明的后果是「多一条警告日志」
// 而不是「丢掉一条审计记录」——护栏退化成噪音，而不是退化成沉默。
func MarkAuditRecorded(c *gin.Context) { c.Set(KeyAuditRecorded, true) }

// AuditRecorded 判断本次请求是否已声明被 service 层审计。
func AuditRecorded(c *gin.Context) bool {
	v, ok := c.Get(KeyAuditRecorded)
	if !ok {
		return false
	}
	done, ok := v.(bool)
	return ok && done
}

// MarkAuditSkipped 声明「本次请求按设计不产生审计记录」。
//
// 与 MarkAuditRecorded 的区别是实质性的，不能合并：
//
//	MarkAuditRecorded —— 审计**已经写了**，只是不经过中间件（例如导入的
//	                     「写入 N 条 / 建了 M 个组」只有 service 层算得出来）
//	MarkAuditSkipped  —— 审计**不该写**，因为这个请求没改变任何状态
//
// 后者存在的理由是导入预览：它必须用 POST（要传文件），解析与校验却不落库。
// 中间件按「非安全方法 + 未标注」判定漏审计，于是每一次预览都会打一条
// 「本次操作不会留下审计记录」的告警 —— 而预览本来就不需要审计。
// 这种告警会把真正的漏审计淹掉，因此必须能明确声明「这里不需要」。
func MarkAuditSkipped(c *gin.Context) { c.Set(KeyAuditSkipped, true) }

// AuditSkipped 判断本次请求是否已被声明「不需要审计」。
func AuditSkipped(c *gin.Context) bool {
	v, ok := c.Get(KeyAuditSkipped)
	if !ok {
		return false
	}
	skipped, ok := v.(bool)
	return ok && skipped
}
