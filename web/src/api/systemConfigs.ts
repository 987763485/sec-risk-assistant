import type { SystemConfigView, UpdateSystemConfigRequest } from './endpoints'
import { api } from './http'

/**
 * 读取风险模型配置。
 *
 * 后端对读接口放宽到 `assessment:read` 也放行：评估员没有系统设置权限，
 * 但他在评估执行页必须能看到当前阈值才能理解结果。
 */
export function getSystemConfigs(): Promise<SystemConfigView> {
  return api.get<SystemConfigView>('/system/configs')
}

/**
 * 更新风险模型配置。
 *
 * ⚠️ 改动只影响**之后**的计算：已计算过的评估用的是它自己的配置快照，
 * 不会被这里改动影响。这一点必须让用户在界面上看见——否则他会以为
 * 「改了阈值，那份旧报告怎么没跟着变」是个 bug。
 *
 * 四个阈值可只传其中几个，服务端与现值合并后再校验。
 */
export function updateSystemConfigs(payload: UpdateSystemConfigRequest): Promise<SystemConfigView> {
  return api.patch<SystemConfigView>('/system/configs', payload)
}
