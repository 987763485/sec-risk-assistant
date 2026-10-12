package auth

import "sort"

// Permission 权限码。
//
// 命名约定：`<资源>:<动作>`，动作只用 read / write 两档。
// 刻意不引入 read/create/update/delete 四档细分——政企内部系统的角色划分
// 远达不到这个粒度，多出来的档位只会让前端菜单判断与后端注解都变得啰嗦。
type Permission string

// 权限码全集。
//
// ⚠️ 新增权限码时必须同时登记进 allPermissions，否则启动自检会失败
// （见 CheckPermissionRegistry），这是防止「加了权限码但忘了给角色授权」的护栏。
const (
	PermUserRead    Permission = "user:read"
	PermUserWrite   Permission = "user:write"
	PermRoleRead    Permission = "role:read"
	PermRoleWrite   Permission = "role:write"
	PermAssetRead   Permission = "asset:read"
	PermAssetWrite  Permission = "asset:write"
	PermDictRead    Permission = "dictionary:read"
	PermDictWrite   Permission = "dictionary:write"
	PermFileRead    Permission = "file:read"
	PermFileWrite   Permission = "file:write"
	PermVulnRead    Permission = "vulnerability:read"
	PermVulnWrite   Permission = "vulnerability:write"
	PermAssessRead  Permission = "assessment:read"
	PermAssessWrite Permission = "assessment:write"
	PermRemedRead   Permission = "remediation:read"
	PermRemedWrite  Permission = "remediation:write"
	PermReportRead  Permission = "report:read"
	PermReportWrite Permission = "report:write"
	PermAuditRead   Permission = "audit:read"
	PermSystemRead  Permission = "system:read"
	PermSystemWrite Permission = "system:write"
	// PermIntegrationRead / PermIntegrationWrite 三方情报源（P7）。
	//
	// ⚠️ 与 system:read / system:write 的分工是本模块的核心决策：
	//
	//	改集成配置（POST/PATCH /integrations）→ system:write
	//	读配置、触发拉取                       → integration:read / integration:write
	//
	// 判据是「管理动作 vs 业务动作」：改 base_url 与凭据指向，
	// 决定的是**这台服务器接下来会向哪里发起请求**，属于系统设置；
	// 而「对这条漏洞拉一次情报」是业务动作，评估员就该能做。
	// 若把配置修改也挂在 integration:write 上，那么给评估员开这个权限
	// 就等于同时把「指定出站目标」的能力交给了他——那是 SSRF 的入口。
	PermIntegrationRead  Permission = "integration:read"
	PermIntegrationWrite Permission = "integration:write"
)

// allPermissions 权限码全集。顺序即前端权限展示顺序，按业务模块归组。
var allPermissions = []Permission{
	PermUserRead, PermUserWrite,
	PermRoleRead, PermRoleWrite,
	PermAssetRead, PermAssetWrite,
	PermDictRead, PermDictWrite,
	PermFileRead, PermFileWrite,
	PermVulnRead, PermVulnWrite,
	PermAssessRead, PermAssessWrite,
	PermRemedRead, PermRemedWrite,
	PermReportRead, PermReportWrite,
	PermAuditRead,
	PermSystemRead, PermSystemWrite,
	PermIntegrationRead, PermIntegrationWrite,
}

// AllPermissions 返回权限码全集的副本。
func AllPermissions() []Permission {
	out := make([]Permission, len(allPermissions))
	copy(out, allPermissions)
	return out
}

// 内置角色码。与 roles 表的 code 字段一一对应。
const (
	RoleAdmin    = "admin"
	RoleAssessor = "assessor"
	RoleAuditor  = "auditor"
)

// BuiltinRoles 内置角色码列表。
var BuiltinRoles = []string{RoleAdmin, RoleAssessor, RoleAuditor}

// rolePermissions 角色 → 权限码映射。
//
// 这是全系统唯一的授权真相源：中间件鉴权、前端菜单渲染、审计可读范围
// 全部由它派生。**不在数据库里存权限**，避免「改一行数据即可提权」的风险面。
var rolePermissions = map[string][]Permission{
	// 系统管理员：全权
	RoleAdmin: allPermissions,

	// 评估员：业务全流程，但不碰用户/角色/系统设置，也看不到审计日志。
	// 保留 user:read 是为了在评估任务里选择负责人时能拉到候选列表。
	//
	// P7 起含 integration:read + integration:write：对漏洞拉一次情报是
	// 评估工作的一部分。**但不含 system:write**，因此评估员能拉取、
	// 不能改集成配置——这正是上面权限码定义里那条分工的落点。
	RoleAssessor: {
		PermUserRead,
		PermAssetRead, PermAssetWrite,
		PermDictRead, PermDictWrite,
		PermFileRead, PermFileWrite,
		PermVulnRead, PermVulnWrite,
		PermAssessRead, PermAssessWrite,
		PermRemedRead, PermRemedWrite,
		PermReportRead, PermReportWrite,
		PermIntegrationRead, PermIntegrationWrite,
	},

	// 审计员：全站只读，但能看审计日志与系统配置（这正是审计岗的价值所在）。
	// integration:read 由 readOnlyPermissions() 自动派生——这条派生规则
	// 的意义在这里体现得很直接：P7 新增了资源，审计员的读权限自动跟上，
	// 不需要有人记得回来加一行。
	RoleAuditor: readOnlyPermissions(),
}

// readOnlyPermissions 从权限全集中筛出所有只读权限。
// 用派生而非手写，保证新增资源时审计员自动获得对应的读权限。
func readOnlyPermissions() []Permission {
	out := make([]Permission, 0, len(allPermissions))
	for _, p := range allPermissions {
		if len(p) >= 5 && p[len(p)-5:] == ":read" {
			out = append(out, p)
		}
	}
	return out
}

// PermissionsForRoles 汇总多个角色持有的权限码，去重并按全集顺序排序。
//
// 排序保证同一组角色在任意时刻返回的权限码顺序一致，
// 否则前端菜单与接口响应会在不同请求间抖动。
func PermissionsForRoles(roles []string) []Permission {
	set := make(map[Permission]struct{})
	for _, r := range roles {
		for _, p := range rolePermissions[r] {
			set[p] = struct{}{}
		}
	}

	// 按 allPermissions 的既定顺序输出，末尾追加未知权限码（理论上不会出现）
	out := make([]Permission, 0, len(set))
	for _, p := range allPermissions {
		if _, ok := set[p]; ok {
			out = append(out, p)
			delete(set, p)
		}
	}
	if len(set) > 0 {
		rest := make([]string, 0, len(set))
		for p := range set {
			rest = append(rest, string(p))
		}
		sort.Strings(rest)
		for _, s := range rest {
			out = append(out, Permission(s))
		}
	}
	return out
}

// IsBuiltinRole 判断是否为内置角色码。
func IsBuiltinRole(code string) bool {
	_, ok := rolePermissions[code]
	return ok
}

// PermissionSet 权限集合，供中间件高频查询使用。
type PermissionSet map[Permission]struct{}

// NewPermissionSet 由权限码切片构建集合。
func NewPermissionSet(perms []Permission) PermissionSet {
	s := make(PermissionSet, len(perms))
	for _, p := range perms {
		s[p] = struct{}{}
	}
	return s
}

// Has 判断是否持有指定权限。
func (s PermissionSet) Has(p Permission) bool {
	_, ok := s[p]
	return ok
}

// HasAny 判断是否持有其中任意一个权限。用于「任一权限即可访问」的端点。
func (s PermissionSet) HasAny(ps ...Permission) bool {
	for _, p := range ps {
		if _, ok := s[p]; ok {
			return true
		}
	}
	return false
}

// Slice 导出为字符串切片，便于 JSON 序列化。
func (s PermissionSet) Slice() []Permission {
	out := make([]Permission, 0, len(s))
	for _, p := range allPermissions {
		if _, ok := s[p]; ok {
			out = append(out, p)
		}
	}
	return out
}

// CheckPermissionRegistry 启动自检：确保每个内置角色引用的权限码都在全集中。
//
// 防的是这类低级但致命的错误：权限码拼写错误导致角色「看起来授权了、
// 实际什么都没拿到」。放在启动阶段而非测试里，是为了让容器启动即失败，
// 而不是等到线上有人点了按钮才发现。
func CheckPermissionRegistry() []string {
	known := make(map[Permission]struct{}, len(allPermissions))
	for _, p := range allPermissions {
		if _, dup := known[p]; dup {
			return []string{"权限码全集存在重复项: " + string(p)}
		}
		known[p] = struct{}{}
	}

	var problems []string
	for _, role := range BuiltinRoles {
		perms, ok := rolePermissions[role]
		if !ok {
			problems = append(problems, "内置角色缺少权限定义: "+role)
			continue
		}
		if len(perms) == 0 {
			problems = append(problems, "内置角色权限为空: "+role)
		}
		for _, p := range perms {
			if _, ok := known[p]; !ok {
				problems = append(problems,
					"角色 "+role+" 引用了未登记的权限码: "+string(p))
			}
		}
	}
	return problems
}
