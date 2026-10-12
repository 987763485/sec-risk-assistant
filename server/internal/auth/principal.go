package auth

import (
	"errors"
	"time"
)

// 认证过程中的主体级错误。定义在 auth 包而非 service 包，
// 是为了让中间件可以在不依赖业务层的前提下判断失败原因。
var (
	// ErrAccountNotFound 令牌对应的账号已不存在（被硬删除等异常情况）
	ErrAccountNotFound = errors.New("auth: 账号不存在")
	// ErrAccountDisabled 账号已被禁用
	ErrAccountDisabled = errors.New("auth: 账号已禁用")
)

// Principal 当前请求的认证主体。
//
// ⚠️ 关键设计：Principal **每个请求都重新从数据库加载**，而不是把权限码
// 签进 JWT。代价是每请求一次主键查询（本地 MySQL，命中索引，亚毫秒级），
// 换来的是「禁用账号 / 撤销角色 / 改密」立即生效——不需要等待令牌过期，
// 也不需要维护一套复杂的令牌吊销列表。
type Principal struct {
	UserID      uint64
	Username    string
	DisplayName string
	// Roles 角色码列表，用于前端展示与日志记录
	Roles []string
	// Permissions 权限集合，鉴权的唯一依据
	Permissions PermissionSet
	// MustChangePassword 为 true 时，除改密相关接口外一律拒绝
	MustChangePassword bool

	// TokensValidFrom 访问令牌生效下界。签发时间早于此值的令牌一律拒绝，
	// 零值表示不限制。
	//
	// 用途：让「登出」对无状态 JWT 也立即生效。没有它的话，用户点完登出
	// 离开工位，旧令牌还能用满剩余的有效期（默认 15 分钟），
	// 在共用终端的场景下等同于没有登出。
	TokensValidFrom time.Time
}

// Can 判断主体是否持有指定权限。
func (p *Principal) Can(perm Permission) bool {
	if p == nil {
		return false
	}
	return p.Permissions.Has(perm)
}

// CanAny 判断主体是否持有其中任意一个权限。
func (p *Principal) CanAny(perms ...Permission) bool {
	if p == nil {
		return false
	}
	return p.Permissions.HasAny(perms...)
}

// HasRole 判断主体是否具备指定角色。
func (p *Principal) HasRole(code string) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Roles {
		if r == code {
			return true
		}
	}
	return false
}

// PermissionCodes 返回权限码字符串切片，供接口响应用。
func (p *Principal) PermissionCodes() []string {
	if p == nil {
		return []string{}
	}
	perms := p.Permissions.Slice()
	out := make([]string, 0, len(perms))
	for _, perm := range perms {
		out = append(out, string(perm))
	}
	return out
}
