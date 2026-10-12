import { api } from './http'
import type {
  AssetGroup,
  AssetGroupList,
  CreateAssetGroupRequest,
  MoveAssetGroupRequest,
  UpdateAssetGroupRequest,
} from './endpoints'

/**
 * 资产分组接口。
 *
 * 整个域只有五个端点，其中移动是独立的（`POST /:id/move`）而不是 PATCH 里
 * 的一个字段：混在一起的话，「把组移到根」与「不移动」在 JSON 里都是
 * `parent_id` 缺失，无法区分。
 */

/**
 * 拉取完整的资产组树（根节点数组，子节点在 `children` 里）。
 *
 * 后端一次性返回整棵树，因此树控件、分组下拉、移动对话框三处共用
 * 同一份数据，不必各自处理「展开时再拉一层」。
 */
export async function listAssetGroupTree(): Promise<AssetGroup[]> {
  const res = await api.get<AssetGroupList>('/asset-groups')
  return res.items ?? []
}

export function createAssetGroup(payload: CreateAssetGroupRequest): Promise<AssetGroup> {
  return api.post<AssetGroup>('/asset-groups', payload)
}

export function updateAssetGroup(
  id: number,
  payload: UpdateAssetGroupRequest,
): Promise<AssetGroup> {
  return api.patch<AssetGroup>(`/asset-groups/${id}`, payload)
}

/** 移动资产组。`parent_id` 为 null 表示移到根。 */
export function moveAssetGroup(id: number, payload: MoveAssetGroupRequest): Promise<AssetGroup> {
  return api.post<AssetGroup>(`/asset-groups/${id}/move`, payload)
}

export function deleteAssetGroup(id: number): Promise<void> {
  return api.delete<void>(`/asset-groups/${id}`)
}

// ------------------------------------------------------------------ 树遍历辅助

/**
 * 把树摊平成列表（深度优先），并附带 `depth` 与只含祖先名的路径。
 *
 * 存在的理由是 el-tree 之外的几处消费：分组下拉需要一个带缩进的扁平列表，
 * 而「移动」对话框需要判断「哪些节点不能选」（自己与自己的后代）。
 */
export interface FlatAssetGroup {
  group: AssetGroup
  depth: number
  /** 只含祖先名称的可读路径，如「总部 / 华东区」；根节点为空串 */
  parentPath: string
  disabled: boolean
}

/**
 * 摊平资产组树。
 *
 * @param disabledIds 需要在结果里标为不可选的组 ID（移动时传「自身 + 全部后代」）
 */
export function flattenAssetGroups(
  nodes: AssetGroup[],
  disabledIds: ReadonlySet<number> = new Set(),
  depth = 0,
  parentPath = '',
): FlatAssetGroup[] {
  const out: FlatAssetGroup[] = []
  for (const group of nodes) {
    out.push({
      group,
      depth,
      parentPath,
      disabled: disabledIds.has(group.id),
    })
    const nextPath = parentPath ? `${parentPath} / ${group.name}` : group.name
    if (group.children?.length) {
      out.push(...flattenAssetGroups(group.children, disabledIds, depth + 1, nextPath))
    }
  }
  return out
}

/**
 * 收集某棵子树里全部节点的 ID（含自身）。
 *
 * 用途：移动对话框里把「自己与自己的后代」标成不可选——选中它们会成环，
 * 那部分节点会从树上脱落，既不在任何根下、也永远无法通过界面找到。
 * 后端也会拦（`ASSET_GROUP_CYCLE`），前端先挡一层是为了不让用户
 * 做出一个注定失败的选择。
 */
export function collectSubtreeIds(node: AssetGroup): Set<number> {
  const ids = new Set<number>()
  const walk = (n: AssetGroup) => {
    ids.add(n.id)
    for (const child of n.children ?? []) walk(child)
  }
  walk(node)
  return ids
}

/** 在树里按 ID 找节点（含子树）。找不到返回 null。 */
export function findAssetGroup(nodes: AssetGroup[], id: number): AssetGroup | null {
  for (const node of nodes) {
    if (node.id === id) return node
    const found = findAssetGroup(node.children ?? [], id)
    if (found) return found
  }
  return null
}
