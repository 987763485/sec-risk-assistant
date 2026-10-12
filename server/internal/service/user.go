package service

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/repository"
)

// usernamePattern 登录名格式：3–32 位，字母数字开头，可含 _ . -
//
// 收紧字符集有两个好处：避免用户名里出现空白/控制字符污染日志，
// 也让「用户名不可变」这条规则更容易被用户接受。
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$`)

// UserView 用户列表/详情视图。
type UserView struct {
	ID                 uint64            `json:"id"`
	Username           string            `json:"username"`
	DisplayName        string            `json:"display_name"`
	Email              string            `json:"email"`
	Status             string            `json:"status"`
	Roles              []model.RoleBrief `json:"roles"`
	MustChangePassword bool              `json:"must_change_password"`
	LockedUntil        *time.Time        `json:"locked_until"`
	LastLoginAt        *time.Time        `json:"last_login_at"`
	LastLoginIP        string            `json:"last_login_ip"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// UserListResult 用户列表结果。
type UserListResult struct {
	Items    []UserView
	Total    int64
	Page     int
	PageSize int
}

// CreateUserInput 新建用户入参。
type CreateUserInput struct {
	Username    string
	DisplayName string
	Email       string
	Password    string
	RoleCodes   []string
}

// UpdateUserInput 编辑用户入参。
//
// 全部字段用指针：nil 表示「本次不修改」。
// 这样「把显示名清空」与「不动显示名」才能区分开——
// 若用零值语义，前端页面上留空的字段会被静默改写。
type UpdateUserInput struct {
	DisplayName *string
	Email       *string
	Status      *model.UserStatus
	RoleCodes   []string // nil = 不改角色
}

// UserService 用户管理服务。
type UserService struct {
	cfg    *config.Config
	repo   *repository.Repository
	audit  *auditor
	logger *slog.Logger
}

// NewUserService 构建用户管理服务。
func NewUserService(
	cfg *config.Config, repo *repository.Repository, logger *slog.Logger,
) *UserService {
	if logger == nil {
		logger = slog.Default()
	}
	return &UserService{cfg: cfg, repo: repo, audit: newAuditor(repo, logger), logger: logger}
}

// List 分页查询用户。
func (s *UserService) List(ctx context.Context, q repository.UserListQuery) (*UserListResult, error) {
	users, total, err := s.repo.User.List(ctx, q)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询用户列表失败", err)
	}

	ids := make([]uint64, 0, len(users))
	for i := range users {
		ids = append(ids, users[i].ID)
	}
	// 一次 IN 查询取回全部角色，避免逐个用户查角色的 N+1
	roleMap, err := s.repo.User.RolesOf(ctx, ids)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询用户角色失败", err)
	}

	views := make([]UserView, 0, len(users))
	for i := range users {
		views = append(views, toUserView(&users[i], roleMap[users[i].ID]))
	}

	return &UserListResult{
		Items: views, Total: total, Page: q.Page, PageSize: q.PageSize,
	}, nil
}

// Get 查询单个用户。
func (s *UserService) Get(ctx context.Context, id uint64) (*UserView, error) {
	user, err := s.repo.User.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, errUserNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "查询用户失败", err)
	}
	roleMap, err := s.repo.User.RolesOf(ctx, []uint64{id})
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询用户角色失败", err)
	}
	view := toUserView(user, roleMap[id])
	return &view, nil
}

// ListRoles 返回全部可选角色。
func (s *UserService) ListRoles(ctx context.Context) ([]model.Role, error) {
	roles, err := s.repo.Role.List(ctx)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询角色失败", err)
	}
	return roles, nil
}

// Create 新建用户。
func (s *UserService) Create(
	ctx context.Context, in CreateUserInput, operator *auth.Principal, meta RequestMeta,
) (*UserView, error) {
	username := strings.TrimSpace(in.Username)
	displayName := strings.TrimSpace(in.DisplayName)
	email := strings.TrimSpace(in.Email)

	if !usernamePattern.MatchString(username) {
		return nil, newError(400, errcode.CodeInvalidParam,
			"登录名需为 3–32 位字母、数字、下划线、点或短横线，且以字母或数字开头")
	}
	if displayName == "" {
		displayName = username
	}
	if len([]rune(displayName)) > 32 {
		return nil, newError(400, errcode.CodeInvalidParam, "显示名不得超过 32 个字符")
	}
	if email != "" {
		if _, err := mail.ParseAddress(email); err != nil {
			return nil, newError(400, errcode.CodeInvalidParam, "邮箱格式不正确")
		}
	}
	if err := auth.ValidatePasswordStrength(in.Password); err != nil {
		return nil, errPasswordWeak(err.Error())
	}

	exists, err := s.repo.User.ExistsUsername(ctx, username, 0)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "创建用户失败", err)
	}
	if exists {
		return nil, errUsernameTaken()
	}
	if email != "" {
		if taken, err := s.repo.User.ExistsEmail(ctx, email, 0); err != nil {
			return nil, wrapError(500, errcode.CodeInternal, "创建用户失败", err)
		} else if taken {
			return nil, errEmailTaken()
		}
	}

	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "创建用户失败", err)
	}

	roleIDs, err := s.resolveRoleIDs(ctx, in.RoleCodes)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: hash,
		Status:       model.UserStatusActive,
		// 管理员设定的初始密码必须由本人改掉，否则「管理员知道每个人密码」
		// 这件事会一直成立
		MustChangePassword: true,
	}
	if email != "" {
		user.Email = &email
	}
	if operator != nil {
		operatorID := operator.UserID
		user.CreatedBy = &operatorID
	}

	if err := s.repo.User.Create(ctx, user, roleIDs); err != nil {
		// 并发下唯一索引兜底：两个请求同时创建同名账号时，
		// 先做的前置检查会双双通过，最终由数据库拦住
		if isDuplicateKey(err) {
			return nil, errUsernameTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "创建用户失败", err)
	}

	roleMap, _ := s.repo.User.RolesOf(ctx, []uint64{user.ID})
	view := toUserView(user, roleMap[user.ID])

	s.audit.record(ctx, s.auditEntry(operator, meta, model.ActionUserCreate,
		strconv.FormatUint(user.ID, 10), map[string]any{
			"username": username,
			"roles":    in.RoleCodes,
		}))

	return &view, nil
}

// Update 编辑用户资料、状态与角色。
func (s *UserService) Update(
	ctx context.Context, id uint64, in UpdateUserInput,
	operator *auth.Principal, meta RequestMeta,
) (*UserView, error) {
	current, err := s.repo.User.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, errUserNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "更新用户失败", err)
	}

	fields := make(map[string]any, 3)

	if in.DisplayName != nil {
		name := strings.TrimSpace(*in.DisplayName)
		if name == "" {
			name = current.Username
		}
		if len([]rune(name)) > 32 {
			return nil, newError(400, errcode.CodeInvalidParam, "显示名不得超过 32 个字符")
		}
		fields["display_name"] = name
	}

	if in.Email != nil {
		email := strings.TrimSpace(*in.Email)
		if email == "" {
			fields["email"] = nil // 显式置 NULL，否则唯一索引下空串会互相冲突
		} else {
			if _, err := mail.ParseAddress(email); err != nil {
				return nil, newError(400, errcode.CodeInvalidParam, "邮箱格式不正确")
			}
			taken, err := s.repo.User.ExistsEmail(ctx, email, id)
			if err != nil {
				return nil, wrapError(500, errcode.CodeInternal, "更新用户失败", err)
			}
			if taken {
				return nil, errEmailTaken()
			}
			fields["email"] = email
		}
	}

	if in.Status != nil {
		if !in.Status.Valid() {
			return nil, newError(400, errcode.CodeInvalidParam, "账号状态取值非法")
		}
		if err := s.guardStatusChange(ctx, current, *in.Status, operator); err != nil {
			return nil, err
		}
		fields["status"] = *in.Status
	}

	if len(fields) > 0 || in.RoleCodes != nil {
		if err := s.repo.Transaction(ctx, func(txRepo *repository.Repository) error {
			if len(fields) > 0 {
				if err := txRepo.User.UpdateProfile(ctx, id, fields); err != nil {
					return err
				}
			}
			if in.RoleCodes != nil {
				return s.applyRoles(ctx, txRepo, id, in.RoleCodes, current)
			}
			return nil
		}); err != nil {
			var be *Error
			if errors.As(err, &be) {
				return nil, be
			}
			return nil, wrapError(500, errcode.CodeInternal, "更新用户失败", err)
		}
	}

	// 状态变更后立即吊销该账号的全部会话，避免「已禁用但旧令牌还能用」
	if in.Status != nil && *in.Status == model.UserStatusDisabled {
		if _, err := s.repo.Session.RevokeUserTokens(
			ctx, id, model.RevokeReasonAdmin, ""); err != nil {
			s.logger.Error("禁用账号后吊销会话失败", "user_id", id, "err", err)
		}
	}

	updated, err := s.repo.User.FindByID(ctx, id)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "更新用户失败", err)
	}
	roleMap, _ := s.repo.User.RolesOf(ctx, []uint64{id})
	view := toUserView(updated, roleMap[id])

	s.audit.record(ctx, s.auditEntry(operator, meta, model.ActionUserUpdate,
		strconv.FormatUint(id, 10), map[string]any{
			"fields": changedFieldNames(fields),
			"roles":  in.RoleCodes,
			"status": in.Status,
		}))

	return &view, nil
}

// ResetPassword 管理员重置他人密码，被重置者下次登录必须改密。
func (s *UserService) ResetPassword(
	ctx context.Context, id uint64, newPassword string,
	operator *auth.Principal, meta RequestMeta,
) error {
	if err := auth.ValidatePasswordStrength(newPassword); err != nil {
		return errPasswordWeak(err.Error())
	}

	user, err := s.repo.User.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return errUserNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "重置密码失败", err)
	}

	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "重置密码失败", err)
	}

	if err := s.repo.User.UpdatePassword(ctx, user.ID, hash, true); err != nil {
		return wrapError(500, errcode.CodeInternal, "重置密码失败", err)
	}
	// 重置密码后所有既有会话立即失效
	if _, err := s.repo.Session.RevokeUserTokens(
		ctx, user.ID, model.RevokeReasonAdmin, ""); err != nil {
		s.logger.Error("重置密码后吊销会话失败", "user_id", id, "err", err)
	}

	s.audit.record(ctx, s.auditEntry(operator, meta, model.ActionUserPasswordReset,
		strconv.FormatUint(id, 10), map[string]any{"username": user.Username}))

	return nil
}

// Unlock 解除账号锁定并清零失败计数（管理员操作）。
func (s *UserService) Unlock(
	ctx context.Context, id uint64, operator *auth.Principal, meta RequestMeta,
) error {
	user, err := s.repo.User.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return errUserNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "解除锁定失败", err)
	}
	if err := s.repo.User.ClearLoginFailures(ctx, user.ID); err != nil {
		return wrapError(500, errcode.CodeInternal, "解除锁定失败", err)
	}

	s.audit.record(ctx, s.auditEntry(operator, meta, model.ActionUserUpdate,
		strconv.FormatUint(id, 10), map[string]any{"unlocked": true}))

	return nil
}

// ------------------------------------------------------------------ 内部

// guardStatusChange 校验状态变更是否越界。
func (s *UserService) guardStatusChange(
	ctx context.Context, target *model.User, next model.UserStatus,
	operator *auth.Principal,
) error {
	if next == target.Status {
		return nil
	}
	if next != model.UserStatusDisabled {
		return nil
	}

	if operator != nil && operator.UserID == target.ID {
		return errSelfOperation("不能禁用自己的账号")
	}

	// 目标是启用的管理员时，必须保证禁用它之后系统里还有管理员
	roles, err := s.repo.User.RolesOfUser(ctx, target.ID)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "校验管理员数量失败", err)
	}
	if !containsString(roles, auth.RoleAdmin) {
		return nil
	}

	n, err := s.repo.User.CountActiveAdmins(ctx, target.ID)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "校验管理员数量失败", err)
	}
	if n == 0 {
		return errLastAdmin()
	}
	return nil
}

// applyRoles 在事务内替换用户角色，并守住「最后一个管理员」这条底线。
//
// 调用方必须已经开启事务。这里先对 roles 表中的 admin 行加排他锁，
// 把所有涉及管理员身份的并发变更串行化——否则两个请求可能同时读到
// 「还有另一个管理员」而双双放行，最终系统失去管理入口。
func (s *UserService) applyRoles(
	ctx context.Context, txRepo *repository.Repository,
	userID uint64, roleCodes []string, target *model.User,
) error {
	if err := txRepo.Role.LockByCode(ctx, auth.RoleAdmin); err != nil {
		return wrapError(500, errcode.CodeInternal, "锁定角色失败", err)
	}

	roleIDs, err := resolveRoleIDs(ctx, txRepo, roleCodes)
	if err != nil {
		return err
	}

	current, err := txRepo.User.RolesOfUser(ctx, userID)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "读取用户角色失败", err)
	}

	wasAdmin := containsString(current, auth.RoleAdmin)
	willBeAdmin := containsString(roleCodes, auth.RoleAdmin)

	if wasAdmin && !willBeAdmin && target.IsActive() {
		n, err := txRepo.User.CountActiveAdmins(ctx, userID)
		if err != nil {
			return wrapError(500, errcode.CodeInternal, "校验管理员数量失败", err)
		}
		if n == 0 {
			return errLastAdmin()
		}
	}

	if err := txRepo.User.ReplaceRoles(ctx, userID, roleIDs); err != nil {
		return wrapError(500, errcode.CodeInternal, "更新用户角色失败", err)
	}
	return nil
}

// resolveRoleIDs 把角色码解析成 ID，并校验全部存在。
func (s *UserService) resolveRoleIDs(ctx context.Context, codes []string) ([]uint64, error) {
	return resolveRoleIDs(ctx, s.repo, codes)
}

func resolveRoleIDs(
	ctx context.Context, repo *repository.Repository, codes []string,
) ([]uint64, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	m, err := repo.Role.IDMap(ctx, codes)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "解析角色失败", err)
	}
	ids := make([]uint64, 0, len(codes))
	for _, code := range codes {
		id, ok := m[code]
		if !ok {
			return nil, errRoleNotAssignable()
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// auditEntry 构造用户相关的审计记录。
// 统一委托给 auditEntryFor，保证敏感字段剔除这条约束只有一处实现。
func (s *UserService) auditEntry(
	operator *auth.Principal, meta RequestMeta,
	action, resourceID string, detail map[string]any,
) model.AuditEntry {
	return auditEntryFor(operator, meta, action, "user", resourceID, detail)
}

func toUserView(u *model.User, roles []model.RoleBrief) UserView {
	if roles == nil {
		roles = []model.RoleBrief{}
	}
	return UserView{
		ID:                 u.ID,
		Username:           u.Username,
		DisplayName:        u.DisplayName,
		Email:              u.EmailValue(),
		Status:             string(u.Status),
		Roles:              roles,
		MustChangePassword: u.MustChangePassword,
		LockedUntil:        u.LockedUntil,
		LastLoginAt:        u.LastLoginAt,
		LastLoginIP:        u.LastLoginIP,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// changedFieldNames 返回本次实际变更的字段名，用于审计留痕。
func changedFieldNames(fields map[string]any) []string {
	out := make([]string, 0, len(fields))
	for k := range fields {
		out = append(out, k)
	}
	return out
}

// isDuplicateKey 判断是否为唯一键冲突。
//
// 靠错误文本匹配虽然不优雅，但 MySQL 驱动没有提供结构化的错误码枚举，
// 而这里只需在「两个请求同时创建同名账号」的极窄窗口里兜一次底。
func isDuplicateKey(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate entry") || strings.Contains(msg, "error 1062")
}
