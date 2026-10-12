package service

import (
	"sort"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/sanitize"
)

// auditEntryFor 构造一条待落库的审计记录。
//
// 抽成包级函数而不是让每个 service 各写一份，是为了收口一个约束：
// Detail 必须过一遍 sanitize.JSON（敏感字段剔除）。靠「每个服务都记得
// 调用」是撑不住的，尤其当某个服务后来开始往明细里塞请求体的时候。
func auditEntryFor(
	operator *auth.Principal, meta RequestMeta,
	action, resource, resourceID string, detail map[string]any,
) model.AuditEntry {
	e := model.AuditEntry{
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Method:     meta.Method,
		Path:       meta.Path,
		// 走到这里说明业务已经成功（失败路径不会调审计），因此固定 200。
		// 审计中间件那条路径才需要真实状态码。
		StatusCode: 200,
		ClientIP:   meta.ClientIP,
		UserAgent:  truncate(meta.UserAgent, 255),
		Detail:     sanitize.JSON(detail),
		RequestID:  meta.RequestID,
	}
	if operator != nil {
		e.UserID = operator.UserID
		e.Username = operator.Username
	}
	return e
}

// sortedKeys 返回 map 的键，按字典序排序，并排除指定的键。
//
// 用在审计明细里记录「本次改了哪些字段」。必须排序：Go 的 map 遍历
// 顺序是随机的，不排序会让同一个操作在审计日志里每次留下不同的写法，
// 而「看起来不一样」会被当成「改的东西不一样」。
func sortedKeys(m map[string]any, exclude ...string) []string {
	skip := make(map[string]struct{}, len(exclude))
	for _, k := range exclude {
		skip[k] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		if _, ok := skip[k]; ok {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// principalID 取操作人 ID（未认证时返回 nil）。
//
// 返回指针而不是 0：审计表与整改单的 operator_id 都是可空列，
// 「匿名」与「ID 为 0 的用户」必须可区分——0 不是任何真实账号的 ID，
// 但把 0 写进可空列会在读回来时变成「一个 ID 为 0 的人干的」。
func principalID(p *auth.Principal) *uint64 {
	if p == nil {
		return nil
	}
	id := p.UserID
	return &id
}

// principalName 取操作人登录名（未认证时为空串）。
//
// 三处消费它，且理由一致：**这些东西会被带离系统**。
//   - 报告里要写「导出人」：报告一旦被转发，审计日志就不在它身边了；
//   - 整改单流转记录要写「当时是谁推进的」：账号后来改名不该改写历史；
//   - 审计日志本身（audit_logs 冗余存 username，同一条理由）。
func principalName(p *auth.Principal) string {
	if p == nil {
		return ""
	}
	return p.Username
}
