import { api } from './http'
import { toQueryString } from './query'
import type {
  CreateUserRequest,
  ResetPasswordRequest,
  Role,
  RoleList,
  UpdateUserRequest,
  UserDetail,
  UserPage,
  UserStatus,
} from './endpoints'

/** 用户列表查询参数 */
export interface UserListQuery {
  page?: number
  pageSize?: number
  keyword?: string
  status?: UserStatus
  role?: string
}

/**
 * 用户管理接口。
 *
 * 注意所有入参的字段名都是 snake_case：它们直接来自 docs/openapi.yaml，
 * 不在这一层做 camelCase 转换。多一层命名转换等于多一处可能写错、
 * 且出错时只能在运行时发现的地方。
 */
export function listUsers(query: UserListQuery = {}): Promise<UserPage> {
  return api.get<UserPage>(`/users${toQueryString(query)}`)
}

export function getUser(id: number): Promise<UserDetail> {
  return api.get<UserDetail>(`/users/${id}`)
}

export function createUser(payload: CreateUserRequest): Promise<UserDetail> {
  return api.post<UserDetail>('/users', payload)
}

export function updateUser(id: number, payload: UpdateUserRequest): Promise<UserDetail> {
  return api.patch<UserDetail>(`/users/${id}`, payload)
}

export function resetUserPassword(
  id: number,
  payload: ResetPasswordRequest,
): Promise<{ reset: boolean }> {
  return api.post<{ reset: boolean }>(`/users/${id}/reset-password`, payload)
}

export function unlockUser(id: number): Promise<{ unlocked: boolean }> {
  return api.post<{ unlocked: boolean }>(`/users/${id}/unlock`)
}

/** 角色字典。响应中的 `items` 是接口层定义的视图对象，字段为 snake_case。 */
export async function listRoles(): Promise<Role[]> {
  const res = await api.get<RoleList>('/roles')
  return res.items ?? []
}
