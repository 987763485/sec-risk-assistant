import { http } from './client'

/** GET /api/health 的响应结构（与 Go 侧 handler.Health.Ready 保持一致） */
export interface HealthResponse {
  status: 'ok' | 'degraded'
  service: string
  version: string
  env: string
  commit: string
  checks: Record<string, { status: string; detail: string }>
  time: string
}

/** GET /api/version 的响应结构 */
export interface VersionResponse {
  service: string
  version: string
  commit: string
  build_time: string
  env: string
}

export async function fetchHealth(): Promise<HealthResponse> {
  const { data } = await http.get<HealthResponse>('/health')
  return data
}

export async function fetchVersion(): Promise<VersionResponse> {
  const { data } = await http.get<VersionResponse>('/version')
  return data
}
