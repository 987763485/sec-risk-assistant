package service

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/sanitize"
	"secrisk/server/internal/repository"
)

// RequestMeta 请求元信息，用于审计留痕与会话记录。
type RequestMeta struct {
	ClientIP  string
	UserAgent string
	RequestID string
	Method    string
	Path      string
}

// Session 一次成功认证后的会话载荷。
//
// 三个令牌一并返回，由 handler 分别写进三枚不同属性的 Cookie；
// 明文刷新令牌在这个结构体之外不再存在（库里只有它的 SHA-256 摘要）。
type Session struct {
	AccessToken        string
	RefreshToken       string
	CSRFToken          string
	Principal          *auth.Principal
	FamilyID           string
	ExpiresIn          int
	MustChangePassword bool
}

// MeResult 当前登录者信息。
type MeResult struct {
	UserID             uint64            `json:"user_id"`
	Username           string            `json:"username"`
	DisplayName        string            `json:"display_name"`
	Email              string            `json:"email"`
	Roles              []model.RoleBrief `json:"roles"`
	Permissions        []string          `json:"permissions"`
	MustChangePassword bool              `json:"must_change_password"`
	LastLoginAt        *time.Time        `json:"last_login_at"`
	LastLoginIP        string            `json:"last_login_ip"`
}

// AuthService 认证与会话服务。
type AuthService struct {
	cfg    *config.Config
	repo   *repository.Repository
	tokens *auth.TokenManager
	cookie auth.CookieOptions
	audit  *auditor
	logger *slog.Logger
}

// NewAuthService 构建认证服务。
func NewAuthService(
	cfg *config.Config, repo *repository.Repository,
	tokens *auth.TokenManager, logger *slog.Logger,
) *AuthService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthService{
		cfg:    cfg,
		repo:   repo,
		tokens: tokens,
		cookie: auth.CookieOptions{Secure: cfg.Auth.CookieSecure},
		audit:  newAuditor(repo, logger),
		logger: logger,
	}
}

// CookieOptions 暴露 Cookie 属性供 handler 下发。
func (s *AuthService) CookieOptions() auth.CookieOptions { return s.cookie }

// AccessTTL 访问令牌有效期。
func (s *AuthService) AccessTTL() time.Duration { return s.cfg.Auth.AccessTTL }

// RefreshTTL 刷新令牌有效期。
func (s *AuthService) RefreshTTL() time.Duration { return s.cfg.Auth.RefreshTTL }

// LoginRateLimit 返回登录接口的 IP 限流参数。
func (s *AuthService) LoginRateLimit() (int, time.Duration) {
	return s.cfg.Auth.LoginRateLimit, s.cfg.Auth.LoginRateWindow
}

// NewCSRFToken 生成一枚新的 CSRF 双提交令牌。
func (s *AuthService) NewCSRFToken() (string, error) { return auth.NewCSRFToken() }

// LoadPrincipal 实现 middleware.PrincipalLoader。
//
// 每个请求都会走到这里，因此它的效率直接决定整站吞吐。
// 两次索引查询（按主键取用户 + 按外键取角色）在本地 MySQL 上远低于 1ms，
// 换来的是权限变更即时生效——这个交换非常划算。
func (s *AuthService) LoadPrincipal(ctx context.Context, userID uint64) (*auth.Principal, error) {
	user, err := s.repo.User.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, auth.ErrAccountNotFound
		}
		return nil, err
	}
	if !user.IsActive() {
		return nil, auth.ErrAccountDisabled
	}
	return s.buildPrincipal(ctx, user)
}

// buildPrincipal 组装认证主体（用户信息 + 角色 + 权限集合）。
func (s *AuthService) buildPrincipal(ctx context.Context, user *model.User) (*auth.Principal, error) {
	roles, err := s.repo.User.RolesOfUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	principal := &auth.Principal{
		UserID:             user.ID,
		Username:           user.Username,
		DisplayName:        user.DisplayName,
		Roles:              roles,
		Permissions:        auth.NewPermissionSet(auth.PermissionsForRoles(roles)),
		MustChangePassword: user.MustChangePassword,
	}
	if user.TokenNotBefore != nil {
		principal.TokensValidFrom = *user.TokenNotBefore
	}
	return principal, nil
}

// ------------------------------------------------------------------ 登录

// Login 执行登录。
//
// 失败路径刻意保持「对外文案一致、对内原因分明」：
// 用户名不存在与密码错误返回同一个错误，避免接口退化成账号枚举器；
// 而账号锁定与账号禁用是管理员决策的结果，明确告知反而更友好。
func (s *AuthService) Login(
	ctx context.Context, username, password string, meta RequestMeta,
) (*Session, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, errInvalidCredentials()
	}

	user, err := s.repo.User.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			// 用户名不存在时也做一次等价耗时的哈希校验。
			// 否则「存在但密码错」比「用户不存在」慢上百毫秒，
			// 攻击者据此就能枚举出哪些账号真实存在。
			burnPasswordCompare(password)
			s.audit.recordAsync(s.failureAudit(meta, username,
				errcode.CodeInvalidCredentials, "用户不存在"))
			return nil, errInvalidCredentials()
		}
		return nil, wrapError(500, errcode.CodeInternal, "登录失败，请稍后重试", err)
	}

	now := time.Now()
	if !user.IsActive() {
		s.audit.recordAsync(s.failureAudit(meta, username,
			errcode.CodeAccountDisabled, "账号已禁用"))
		return nil, errAccountDisabled()
	}
	if user.IsLocked(now) {
		return nil, errAccountLocked(*user.LockedUntil)
	}

	ok, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		// 哈希无法解析属于数据损坏，需要告警，但不能把细节透给客户端
		s.logger.Error("密码哈希解析失败，账号数据可能已损坏",
			"user_id", user.ID, "err", err, "request_id", meta.RequestID)
		return nil, errInvalidCredentials()
	}
	if !ok {
		return nil, s.handleLoginFailure(ctx, user, meta)
	}

	if err := s.repo.User.RecordLoginSuccess(ctx, user.ID, meta.ClientIP); err != nil {
		// 仅影响「最近登录」统计，不应阻断正常登录
		s.logger.Error("记录登录成功信息失败",
			"user_id", user.ID, "err", err, "request_id", meta.RequestID)
	}

	session, err := s.issueSession(ctx, user, "", meta)
	if err != nil {
		return nil, err
	}

	s.audit.record(ctx, model.AuditEntry{
		UserID:     user.ID,
		Username:   user.Username,
		Action:     model.ActionAuthLogin,
		Resource:   "user",
		ResourceID: strconv.FormatUint(user.ID, 10),
		Method:     meta.Method,
		Path:       meta.Path,
		StatusCode: 200,
		ClientIP:   meta.ClientIP,
		UserAgent:  truncate(meta.UserAgent, 255),
		RequestID:  meta.RequestID,
	})

	return session, nil
}

// handleLoginFailure 记录一次失败并按需锁定账号。
func (s *AuthService) handleLoginFailure(
	ctx context.Context, user *model.User, meta RequestMeta,
) error {
	lockUntil := time.Now().Add(s.cfg.Auth.LockDuration)

	if err := s.repo.User.RecordLoginFailure(
		ctx, user.ID, s.cfg.Auth.MaxLoginAttempts, lockUntil); err != nil {
		s.logger.Error("记录登录失败次数失败",
			"user_id", user.ID, "err", err, "request_id", meta.RequestID)
		return errInvalidCredentials()
	}

	// 回读一次以拿到准确的计数与锁定状态，用于给出精确提示
	updated, err := s.repo.User.FindByID(ctx, user.ID)
	if err == nil && updated.IsLocked(time.Now()) {
		s.logger.Warn("账号因连续登录失败被锁定",
			"user_id", user.ID, "username", user.Username,
			"locked_until", updated.LockedUntil, "client_ip", meta.ClientIP)
		s.audit.recordAsync(s.failureAudit(meta, user.Username,
			errcode.CodeAccountLocked, "连续失败触发锁定"))
		return errAccountLocked(*updated.LockedUntil)
	}

	s.audit.recordAsync(s.failureAudit(meta, user.Username,
		errcode.CodeInvalidCredentials, "密码错误"))
	return errInvalidCredentials()
}

// failureAudit 构造登录失败类审计记录。
//
// 注意：明细里只放用户名与原因，**绝不放密码**——
// 即便密码本身就是错的，把它写进审计日志也毫无价值且风险巨大。
func (s *AuthService) failureAudit(
	meta RequestMeta, username, code, reason string,
) model.AuditEntry {
	return model.AuditEntry{
		Username:   username,
		Action:     model.ActionAuthLoginFailed,
		Resource:   "user",
		Method:     meta.Method,
		Path:       meta.Path,
		StatusCode: statusOfCode(code),
		ClientIP:   meta.ClientIP,
		UserAgent:  truncate(meta.UserAgent, 255),
		Detail: sanitize.JSON(map[string]any{
			"username": username,
			"reason":   reason,
			"code":     code,
		}),
		RequestID: meta.RequestID,
	}
}

func statusOfCode(code string) int {
	switch code {
	case errcode.CodeInvalidCredentials:
		return 401
	case errcode.CodeAccountDisabled:
		return 403
	case errcode.CodeAccountLocked:
		return 423
	default:
		return 400
	}
}

// issueSession 签发一整套会话凭据。
//
// familyID 为空表示新建轮换链（首次登录）；非空表示沿用既有链（刷新）。
// 沿用同一 family 是「令牌重放可牵连整链」这一防护的前提。
func (s *AuthService) issueSession(
	ctx context.Context, user *model.User, familyID string, meta RequestMeta,
) (*Session, error) {
	principal, err := s.buildPrincipal(ctx, user)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "构建会话失败", err)
	}

	accessToken, err := s.tokens.IssueAccess(user.ID, user.Username)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "签发访问令牌失败", err)
	}

	refreshPlain, refreshHash, err := auth.NewRefreshToken()
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "生成刷新令牌失败", err)
	}

	if familyID == "" {
		if familyID, err = auth.NewUUID(); err != nil {
			return nil, wrapError(500, errcode.CodeInternal, "生成会话标识失败", err)
		}
	}

	csrfToken, err := auth.NewCSRFToken()
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "生成 CSRF 令牌失败", err)
	}

	now := time.Now()
	record := &model.RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshHash,
		FamilyID:  familyID,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.cfg.Auth.RefreshTTL),
		ClientIP:  meta.ClientIP,
		UserAgent: truncate(meta.UserAgent, 255),
	}
	if err := s.repo.Session.Create(ctx, record); err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "写入会话失败", err)
	}

	return &Session{
		AccessToken:        accessToken,
		RefreshToken:       refreshPlain,
		CSRFToken:          csrfToken,
		Principal:          principal,
		FamilyID:           familyID,
		ExpiresIn:          int(s.cfg.Auth.AccessTTL / time.Second),
		MustChangePassword: user.MustChangePassword,
	}, nil
}

// ------------------------------------------------------------------ 刷新

// Refresh 用刷新令牌换取新的访问令牌，并轮换刷新令牌本身。
//
// 轮换（rotation）的意义：刷新令牌每次使用后立即作废，从而把「一次泄露」
// 的可利用窗口压到两次刷新之间。配套的重放检测则让泄露变得可发现——
// 若旧令牌被第二次使用，说明它同时存在于两方手中，此时整条链作废。
func (s *AuthService) Refresh(
	ctx context.Context, refreshPlain string, meta RequestMeta,
) (*Session, error) {
	if refreshPlain == "" {
		return nil, errTokenInvalid()
	}

	record, err := s.repo.Session.FindByHash(ctx, auth.HashToken(refreshPlain))
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			// 摘要不在库里：伪造令牌，或已被清理的历史令牌
			return nil, errTokenInvalid()
		}
		return nil, wrapError(500, errcode.CodeInternal, "刷新登录状态失败", err)
	}

	now := time.Now()

	// 重放检测：令牌已被使用过或已被吊销，却又出现在刷新请求里
	if record.UsedAt != nil || record.RevokedAt != nil {
		return nil, s.handleTokenReuse(ctx, record, meta)
	}
	if !record.ExpiresAt.After(now) {
		return nil, errTokenExpired()
	}

	// 原子标记「已使用」。并发安全的关键闸门：
	// 两个请求同时刷新时，只有一个能拿到 marked=true。
	marked, err := s.repo.Session.MarkUsed(ctx, record.ID, now)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "刷新登录状态失败", err)
	}
	if !marked {
		// 竞态落败方：等价于重放，按最坏情况处理
		return nil, s.handleTokenReuse(ctx, record, meta)
	}

	user, err := s.repo.User.FindByID(ctx, record.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, errTokenInvalid()
		}
		return nil, wrapError(500, errcode.CodeInternal, "刷新登录状态失败", err)
	}
	if !user.IsActive() {
		// 账号已被禁用：顺手清掉它的全部会话
		if _, err := s.repo.Session.RevokeUserTokens(
			ctx, user.ID, model.RevokeReasonAdmin, ""); err != nil {
			s.logger.Error("吊销被禁用账号的会话失败", "user_id", user.ID, "err", err)
		}
		return nil, errAccountDisabled()
	}

	session, err := s.issueSession(ctx, user, record.FamilyID, meta)
	if err != nil {
		return nil, err
	}

	s.audit.recordAsync(model.AuditEntry{
		UserID:     user.ID,
		Username:   user.Username,
		Action:     model.ActionAuthRefresh,
		Resource:   "user",
		ResourceID: strconv.FormatUint(user.ID, 10),
		Method:     meta.Method,
		Path:       meta.Path,
		StatusCode: 200,
		ClientIP:   meta.ClientIP,
		UserAgent:  truncate(meta.UserAgent, 255),
		RequestID:  meta.RequestID,
	})

	return session, nil
}

// handleTokenReuse 处理刷新令牌重放：吊销整条轮换链。
//
// 为什么必须连带吊销尚未使用的子令牌：此刻无法分辨「是攻击者拿到了旧令牌」
// 还是「合法客户端被中间人劫持」。保守做法是把这条链上的所有令牌一并作废，
// 强制当事人重新登录——代价是用户被打断一次，收益是攻击者立刻失去立足点。
func (s *AuthService) handleTokenReuse(
	ctx context.Context, record *model.RefreshToken, meta RequestMeta,
) error {
	revoked, err := s.repo.Session.RevokeFamily(
		ctx, record.FamilyID, model.RevokeReasonReuseDetected)
	if err != nil {
		s.logger.Error("吊销令牌族失败", "family_id", record.FamilyID, "err", err)
	}

	s.logger.Warn("检测到刷新令牌重放，已吊销整条会话链",
		"user_id", record.UserID,
		"family_id", record.FamilyID,
		"revoked_count", revoked,
		"client_ip", meta.ClientIP,
		"request_id", meta.RequestID)

	s.audit.recordAsync(model.AuditEntry{
		UserID:     record.UserID,
		Action:     model.ActionAuthTokenReuse,
		Resource:   "session",
		ResourceID: record.FamilyID,
		Method:     meta.Method,
		Path:       meta.Path,
		StatusCode: 401,
		ClientIP:   meta.ClientIP,
		UserAgent:  truncate(meta.UserAgent, 255),
		Detail: sanitize.JSON(map[string]any{
			"family_id":     record.FamilyID,
			"revoked_count": revoked,
		}),
		RequestID: meta.RequestID,
	})

	return errTokenInvalid()
}

// ------------------------------------------------------------------ 登出

// Logout 结束当前会话。
//
// 做两件事，缺一不可：
//  1. 吊销整条刷新令牌链——决定这个会话「不能续期」
//  2. 更新账号的令牌生效下界——决定此前签发的访问令牌「立刻不可用」
//
// 少了第 2 步，登出就只是「删掉浏览器里的 Cookie」：JWT 是无状态的，
// 服务端手里那份仍然有效，直到 15 分钟后自然过期。共用终端场景下，
// 下一个人按一下后退键就能继续以登出者的身份操作。
//
// 传递不存在的刷新令牌时**静默成功**：登出接口不应成为
// 「这个令牌是否有效」的探测器，也不该在用户退出时抛出莫名其妙的错误。
func (s *AuthService) Logout(
	ctx context.Context, refreshPlain string, principal *auth.Principal, meta RequestMeta,
) error {
	now := time.Now()
	targetUserID := uint64(0)

	if refreshPlain != "" {
		record, err := s.repo.Session.FindByHash(ctx, auth.HashToken(refreshPlain))
		if err == nil {
			targetUserID = record.UserID
			// 吊销整条链而非单条：登出的语义是「结束这次登录」，
			// 而不是「作废这一个令牌」
			if _, err := s.repo.Session.RevokeFamily(
				ctx, record.FamilyID, model.RevokeReasonLogout); err != nil {
				return wrapError(500, errcode.CodeInternal, "登出失败，请稍后重试", err)
			}
		} else if !errors.Is(err, repository.ErrTokenNotFound) {
			return wrapError(500, errcode.CodeInternal, "登出失败，请稍后重试", err)
		}
	}

	// 刷新令牌不可用时退回到认证主体，保证「访问令牌过期也能登出」这条路径
	// 同样能完成令牌失效
	if targetUserID == 0 && principal != nil {
		targetUserID = principal.UserID
	}

	if targetUserID > 0 {
		if err := s.repo.User.SetTokenNotBefore(ctx, targetUserID, now); err != nil {
			s.logger.Error("设置访问令牌失效下界失败，旧令牌可能仍短暂可用",
				"user_id", targetUserID, "err", err, "request_id", meta.RequestID)
		}
	}

	if principal != nil {
		s.audit.record(ctx, model.AuditEntry{
			UserID:     principal.UserID,
			Username:   principal.Username,
			Action:     model.ActionAuthLogout,
			Resource:   "user",
			ResourceID: strconv.FormatUint(principal.UserID, 10),
			Method:     meta.Method,
			Path:       meta.Path,
			StatusCode: 200,
			ClientIP:   meta.ClientIP,
			UserAgent:  truncate(meta.UserAgent, 255),
			RequestID:  meta.RequestID,
		})
	}
	return nil
}

// ------------------------------------------------------------------ 当前用户

// Me 返回当前登录者信息，前端据此生成菜单与路由。
func (s *AuthService) Me(ctx context.Context, userID uint64) (*MeResult, error) {
	user, err := s.repo.User.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, errUserNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "读取用户信息失败", err)
	}

	roleMap, err := s.repo.User.RolesOf(ctx, []uint64{userID})
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "读取用户角色失败", err)
	}
	roles := roleMap[userID]
	if roles == nil {
		roles = []model.RoleBrief{}
	}

	codes := make([]string, 0, len(roles))
	for _, r := range roles {
		codes = append(codes, r.Code)
	}

	perms := auth.PermissionsForRoles(codes)
	permCodes := make([]string, 0, len(perms))
	for _, p := range perms {
		permCodes = append(permCodes, string(p))
	}

	return &MeResult{
		UserID:             user.ID,
		Username:           user.Username,
		DisplayName:        user.DisplayName,
		Email:              user.EmailValue(),
		Roles:              roles,
		Permissions:        permCodes,
		MustChangePassword: user.MustChangePassword,
		LastLoginAt:        user.LastLoginAt,
		LastLoginIP:        user.LastLoginIP,
	}, nil
}

// ------------------------------------------------------------------ 修改密码

// ChangePasswordInput 修改密码入参。
type ChangePasswordInput struct {
	OldPassword string
	NewPassword string
	// CurrentRefreshToken 当前会话的刷新令牌明文。
	// 改密后会吊销该账号的其他全部会话，但保留当前这条——
	// 否则用户改完密码立刻被自己踢下线，体验上说不过去。
	CurrentRefreshToken string
	Meta                RequestMeta
}

// ChangePassword 修改本人密码。
func (s *AuthService) ChangePassword(
	ctx context.Context, userID uint64, in ChangePasswordInput,
) error {
	user, err := s.repo.User.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return errUserNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "修改密码失败", err)
	}

	ok, err := auth.VerifyPassword(in.OldPassword, user.PasswordHash)
	if err != nil {
		s.logger.Error("密码哈希解析失败", "user_id", user.ID, "err", err)
		return errPasswordMismatch()
	}
	if !ok {
		return errPasswordMismatch()
	}

	if in.OldPassword == in.NewPassword {
		return errPasswordUnchanged()
	}
	if err := auth.ValidatePasswordStrength(in.NewPassword); err != nil {
		return errPasswordWeak(err.Error())
	}

	hash, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "修改密码失败", err)
	}

	// 改密顺带清掉 must_change_password 标记
	if err := s.repo.User.UpdatePassword(ctx, user.ID, hash, false); err != nil {
		return wrapError(500, errcode.CodeInternal, "修改密码失败", err)
	}

	keepFamily := s.familyOf(ctx, in.CurrentRefreshToken)
	revoked, err := s.repo.Session.RevokeUserTokens(
		ctx, user.ID, model.RevokeReasonPasswordChanged, keepFamily)
	if err != nil {
		// 会话吊销失败不应让改密整体失败——密码已经改成功了
		s.logger.Error("改密后吊销历史会话失败",
			"user_id", user.ID, "err", err, "request_id", in.Meta.RequestID)
	}

	s.audit.record(ctx, model.AuditEntry{
		UserID:     user.ID,
		Username:   user.Username,
		Action:     model.ActionAuthPasswordChange,
		Resource:   "user",
		ResourceID: strconv.FormatUint(user.ID, 10),
		Method:     in.Meta.Method,
		Path:       in.Meta.Path,
		StatusCode: 200,
		ClientIP:   in.Meta.ClientIP,
		UserAgent:  truncate(in.Meta.UserAgent, 255),
		Detail: sanitize.JSON(map[string]any{
			"revoked_other_sessions": revoked,
		}),
		RequestID: in.Meta.RequestID,
	})

	return nil
}

// familyOf 由刷新令牌明文反查其所属轮换链；查不到返回空串。
func (s *AuthService) familyOf(ctx context.Context, refreshPlain string) string {
	if refreshPlain == "" {
		return ""
	}
	record, err := s.repo.Session.FindByHash(ctx, auth.HashToken(refreshPlain))
	if err != nil {
		return ""
	}
	return record.FamilyID
}

// ------------------------------------------------------------------ 内部工具

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// burnPasswordCompare 执行一次等耗时的哈希校验，用于抹平
// 「用户名不存在」与「密码错误」两条路径的响应时间差。
//
// 哈希在首次调用时现算并缓存：写死一个常量会让参数调整后
// 两者的耗时重新产生差异。
func burnPasswordCompare(password string) {
	dummyHashOnce.Do(func() {
		if h, err := auth.HashPassword("timing-equalization-placeholder-value"); err == nil {
			dummyHash = h
		}
	})
	if dummyHash != "" {
		_, _ = auth.VerifyPassword(password, dummyHash)
	}
}

// truncate 按字节截断，避免超长 UA 撑爆定长列。
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
