package handler

import (
	"github.com/gin-gonic/gin"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/reqctx"
	"secrisk/server/internal/pkg/response"
	"secrisk/server/internal/repository"
	"secrisk/server/internal/service"
)

// UserHandler 用户管理接口。
type UserHandler struct {
	Base
	svc *service.UserService
}

// NewUserHandler 构建用户管理接口处理器。
func NewUserHandler(base Base, svc *service.UserService) *UserHandler {
	return &UserHandler{Base: base, svc: svc}
}

// List 分页查询用户列表。
func (h *UserHandler) List(c *gin.Context) {
	page, pageSize := pagination(c)

	status := model.UserStatus(c.Query("status"))
	if status != "" && !status.Valid() {
		h.invalidParam(c, "status 取值非法")
		return
	}

	result, err := h.svc.List(c.Request.Context(), repository.UserListQuery{
		Keyword:  c.Query("keyword"),
		Status:   status,
		RoleCode: c.Query("role"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		h.fail(c, err)
		return
	}

	response.OK(c, response.NewPage(result.Items, result.Total, result.Page, result.PageSize))
}

// Get 查询单个用户。
func (h *UserHandler) Get(c *gin.Context) {
	id, ok := h.userIDParam(c)
	if !ok {
		return
	}

	view, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.OK(c, view)
}

type createUserRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
}

// Create 新建用户。
func (h *UserHandler) Create(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	view, err := h.svc.Create(c.Request.Context(), service.CreateUserInput{
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Password:    req.Password,
		RoleCodes:   req.Roles,
	}, h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.Created(c, view)
}

type updateUserRequest struct {
	DisplayName *string   `json:"display_name"`
	Email       *string   `json:"email"`
	Status      *string   `json:"status"`
	Roles       *[]string `json:"roles"`
}

// Update 编辑用户资料、状态与角色。
func (h *UserHandler) Update(c *gin.Context) {
	id, ok := h.userIDParam(c)
	if !ok {
		return
	}

	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}

	in := service.UpdateUserInput{DisplayName: req.DisplayName, Email: req.Email}

	if req.Status != nil {
		status := model.UserStatus(*req.Status)
		if !status.Valid() {
			h.invalidParam(c, "status 取值非法，只能是 active 或 disabled")
			return
		}
		in.Status = &status
	}
	// Roles 用指针区分「不传」与「传空数组」：
	// 前者表示不改角色，后者表示清空全部角色。
	if req.Roles != nil {
		in.RoleCodes = *req.Roles
	}

	view, err := h.svc.Update(c.Request.Context(), id, in, h.principal(c), requestMeta(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, view)
}

type resetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// ResetPassword 管理员重置他人密码。
func (h *UserHandler) ResetPassword(c *gin.Context) {
	id, ok := h.userIDParam(c)
	if !ok {
		return
	}

	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.invalidParam(c, "请求格式不正确")
		return
	}
	if req.NewPassword == "" {
		h.invalidParam(c, "请填写新密码")
		return
	}

	if err := h.svc.ResetPassword(c.Request.Context(), id, req.NewPassword,
		h.principal(c), requestMeta(c)); err != nil {
		h.fail(c, err)
		return
	}

	reqctx.MarkAuditRecorded(c)
	response.OK(c, gin.H{"reset": true})
}

// Unlock 解除账号锁定。
func (h *UserHandler) Unlock(c *gin.Context) {
	id, ok := h.userIDParam(c)
	if !ok {
		return
	}

	if err := h.svc.Unlock(c.Request.Context(), id, h.principal(c), requestMeta(c)); err != nil {
		h.fail(c, err)
		return
	}
	reqctx.MarkAuditRecorded(c)
	response.OK(c, gin.H{"unlocked": true})
}

// roleView 角色的对外视图。
//
// 与 auditLogView 同理：model.Role 没有 json tag，直接序列化会输出
// PascalCase 字段名（Code / Name / IsBuiltin），与全局小写下划线风格
// 不一致，前端拿到后必须写两套取值逻辑。对外形状由接口层显式钉住，
// 后续调整模型字段才不会悄悄改掉 API 契约。
type roleView struct {
	ID          uint64 `json:"id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsBuiltin   bool   `json:"is_builtin"`
}

// Roles 返回全部可选角色。
//
// 权限码不下发：角色到权限的映射由后端 auth 包唯一持有，
// 前端只拿到当前登录者已下发的 permissions 列表用于动态路由，
// 角色与权限的对应关系不暴露，避免前端出现第二份权限表。
func (h *UserHandler) Roles(c *gin.Context) {
	roles, err := h.svc.ListRoles(c.Request.Context())
	if err != nil {
		h.fail(c, err)
		return
	}

	items := make([]roleView, 0, len(roles))
	for i := range roles {
		items = append(items, roleView{
			ID:          roles[i].ID,
			Code:        roles[i].Code,
			Name:        roles[i].Name,
			Description: roles[i].Description,
			IsBuiltin:   roles[i].IsBuiltin,
		})
	}
	response.OK(c, gin.H{"items": items})
}

// ------------------------------------------------------------------ 内部

// userIDParam 解析路径上的用户 ID。
func (h *UserHandler) userIDParam(c *gin.Context) (uint64, bool) {
	return h.idParam(c, "用户")
}
