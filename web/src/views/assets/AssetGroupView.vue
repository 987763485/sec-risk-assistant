<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import type { TreeNodeData, TreeInstance } from 'element-plus'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'

import {
  collectSubtreeIds,
  createAssetGroup,
  deleteAssetGroup,
  findAssetGroup,
  listAssetGroupTree,
  moveAssetGroup,
  updateAssetGroup,
} from '@/api/assetGroups'
import type { AssetGroup } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'

const auth = useAuthStore()

/**
 * 写操作按 asset:write 权限显隐。
 *
 * 资产组没有独立的权限码：它决定「资产归谁看」，与资产共用一套
 * （后端路由挂的也是 PermAssetWrite）。拆出 asset_group:write 会让
 * 「能改资产但不能改分组」这种半残状态成为可能，而那个状态没有任何用途。
 */
const canWrite = computed(() => auth.can('asset:write'))

/** 后端定的层级上限（根为 0，共 8 层），用于提前禁掉「新建子组」 */
const MAX_DEPTH = 7

// ------------------------------------------------------------------ 树

const loading = ref(false)
const tree = ref<AssetGroup[]>([])
const selected = ref<AssetGroup | null>(null)
const filterText = ref('')

const treeRef = ref<TreeInstance | null>(null)

async function load(preferId?: number | null) {
  loading.value = true
  try {
    tree.value = await listAssetGroupTree()

    // 数据整体替换后 el-tree 会重建节点，之前高亮的项就丢了。
    // 用 preferId 找回它：新建、改名、移动之后都应当留在原地，
    // 否则用户每操作一次都要重新在树里点一遍。
    const target = preferId === undefined ? (selected.value?.id ?? null) : preferId

    selected.value = target ? findAssetGroup(tree.value, target) : null

    await nextTick()
    // 过滤条件不会被数据替换清掉，但节点是新的，要重新跑一遍
    if (filterText.value) treeRef.value?.filter(filterText.value)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载资产分组失败')
    tree.value = []
    selected.value = null
  } finally {
    loading.value = false
  }
}

watch(filterText, (value) => {
  treeRef.value?.filter(value)
})

/**
 * 树的搜索只按名称匹配。
 *
 * 用 `includes` 而不是把关键字当正则：用户输入的 `(` 或 `[` 会让
 * `new RegExp` 抛错，而「搜索框里打一个括号导致整页报错」是很糟糕的体验。
 *
 * 形参类型**必须**是 el-tree 的 `TreeNodeData`，不能收窄成 `AssetGroup`：
 * 这个函数是作为属性值传给组件的，`strictFunctionTypes` 下函数参数按
 * **逆变**检查，把参数收窄会让整个函数不再是 `FilterNodeMethodFunction`
 * 的子类型。所以这里收下 el-tree 给的宽类型，在函数体里再收窄。
 */
function filterNode(value: string, data: TreeNodeData): boolean {
  if (!value) return true
  return (data as AssetGroup).name.includes(value)
}

/** 供 el-tree 的 `props` 用；默认的 label 字段是 `label`，它得换成 `name` */
const treeProps = { label: 'name', children: 'children' } as const

onMounted(() => void load())

// ------------------------------------------------------------------ 新建 / 重命名

const dialogVisible = ref(false)
const dialogMode = ref<'create' | 'edit'>('create')
const submitting = ref(false)
const formRef = ref<FormInstance>()

/** 新建时的父组；null 表示建为根组 */
const createParent = ref<AssetGroup | null>(null)

const form = reactive({ name: '', description: '', sortOrder: 0 })

const rules: FormRules<typeof form> = {
  name: [
    { required: true, message: '请输入分组名称', trigger: 'blur' },
    { max: 64, message: '名称不得超过 64 个字符', trigger: 'blur' },
  ],
  description: [{ max: 255, message: '说明不得超过 255 个字符', trigger: 'blur' }],
}

const dialogTitle = computed(() =>
  dialogMode.value === 'create'
    ? createParent.value
      ? `在「${createParent.value.name}」下新建子组`
      : '新建根组'
    : `编辑「${selected.value?.name ?? ''}」`,
)

function openCreate(parent: AssetGroup | null) {
  dialogMode.value = 'create'
  createParent.value = parent
  Object.assign(form, { name: '', description: '', sortOrder: 0 })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

function openEdit() {
  const node = selected.value
  if (!node) return
  dialogMode.value = 'edit'
  Object.assign(form, {
    name: node.name,
    description: node.description ?? '',
    sortOrder: node.sort_order ?? 0,
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    if (dialogMode.value === 'create') {
      const created = await createAssetGroup({
        parent_id: createParent.value?.id ?? null,
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        sort_order: form.sortOrder,
      })
      ElMessage.success('分组已创建')
      dialogVisible.value = false
      await load(created.id)
    } else if (selected.value) {
      await updateAssetGroup(selected.value.id, {
        name: form.name.trim(),
        description: form.description.trim(),
        sort_order: form.sortOrder,
      })
      ElMessage.success('已保存')
      dialogVisible.value = false
      await load(selected.value.id)
    }
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

// ------------------------------------------------------------------ 移动

const moveVisible = ref(false)
const moveTarget = ref<number | null>(null)
const moving = ref(false)

/**
 * 供移动对话框使用的树：把「自身 + 全部后代」标为不可选。
 *
 * 选中它们会成环——那部分节点会从树上脱落，既不在任何根下、也再无法通过
 * 界面找到（只剩直接改数据库一条路）。后端也会用 ASSET_GROUP_CYCLE 拦住，
 * 前端先挡一层是为了不让用户做出一个注定失败的选择。
 */
type MoveTreeNode = AssetGroup & { disabled: boolean }

const moveTree = computed<MoveTreeNode[]>(() => {
  const blocked = selected.value ? collectSubtreeIds(selected.value) : new Set<number>()
  const mark = (nodes: AssetGroup[]): MoveTreeNode[] =>
    nodes.map((node) => ({
      ...node,
      disabled: blocked.has(node.id),
      children: mark(node.children ?? []),
    }))
  return mark(tree.value)
})

function openMove() {
  const node = selected.value
  if (!node) return
  moveTarget.value = node.parent_id ?? null
  moveVisible.value = true
}

async function handleMove() {
  const node = selected.value
  if (!node) return

  moving.value = true
  try {
    await moveAssetGroup(node.id, { parent_id: moveTarget.value })
    ElMessage.success('已移动')
    moveVisible.value = false
    await load(node.id)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '移动失败')
  } finally {
    moving.value = false
  }
}

// ------------------------------------------------------------------ 删除

async function handleDelete() {
  const node = selected.value
  if (!node) return

  // 拦得住的原因必须说清楚。「该分组下还有资产」这种提示如果不带数量，
  // 用户只能一层层点开去数，而按子树统计的 asset_count 正好回答了这个问题。
  const blocking =
    node.children.length > 0
      ? `它下面还有 ${node.children.length} 个直接子组`
      : node.total_asset_count > 0
        ? `它（含子组）下还有 ${node.total_asset_count} 条资产`
        : ''

  if (blocking) {
    ElMessage.warning(`「${node.name}」${blocking}，请先移除后再删除该分组`)
    return
  }

  try {
    await ElMessageBox.confirm(
      `确定删除分组「${node.name}」吗？\n\n该分组下没有资产，删除后无法恢复。`,
      '删除资产分组',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }

  try {
    await deleteAssetGroup(node.id)
    ElMessage.success('已删除')
    await load(null)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '删除失败')
  }
}

// ------------------------------------------------------------------ 展示辅助

/** 扁平列表，仅用于右侧的「层级」展示（面包屑式路径） */
const selectedPath = computed(() => {
  const node = selected.value
  if (!node) return ''
  if (node.parent_id === null || node.parent_id === undefined) return node.name
  const chain: string[] = []
  let cursor: AssetGroup | null = node
  while (cursor) {
    chain.unshift(cursor.name)
    const parentId: number | null | undefined = cursor.parent_id
    cursor = parentId ? findAssetGroup(tree.value, parentId) : null
  }
  return chain.join(' / ')
})

const canCreateChild = computed(() => !!selected.value && selected.value.depth < MAX_DEPTH)
</script>

<template>
  <div class="app-page">
    <div class="flex gap-4">
      <!-- ── 分组树 ─────────────────────────────────────────────── -->
      <div class="app-panel w-80 shrink-0">
        <div class="mb-3 flex items-center gap-2">
          <el-input v-model="filterText" :prefix-icon="Search" placeholder="按名称筛选" clearable />
          <el-button :icon="Refresh" @click="load()" />
        </div>

        <el-tree
          ref="treeRef"
          v-loading="loading"
          :data="tree"
          :props="treeProps"
          node-key="id"
          highlight-current
          default-expand-all
          :expand-on-click-node="false"
          :current-node-key="selected?.id"
          :filter-node-method="filterNode"
          @node-click="(data: AssetGroup) => (selected = data)"
        >
          <template #default="{ data }">
            <span class="flex w-full items-center gap-2 pr-1">
              <span class="truncate">{{ data.name }}</span>
              <!-- 两个计数回答的是两个不同的问题：直属数决定能不能删，
                   合计数是点进去能看到几条 -->
              <el-tag v-if="data.total_asset_count" size="small" type="info" effect="plain">
                {{ data.total_asset_count }}
              </el-tag>
            </span>
          </template>
        </el-tree>

        <div v-if="canWrite" class="mt-3">
          <el-button class="w-full" :icon="Plus" @click="openCreate(null)">新建根组</el-button>
        </div>
      </div>

      <!-- ── 选中分组 ───────────────────────────────────────────── -->
      <div class="app-panel flex-1">
        <template v-if="selected">
          <div class="mb-4">
            <div class="text-base font-semibold">{{ selected.name }}</div>
            <div class="mt-1 text-xs text-gray-500">{{ selectedPath }}</div>
          </div>

          <el-descriptions :column="2" border class="mb-4">
            <el-descriptions-item label="层级">{{ selected.depth + 1 }} 层</el-descriptions-item>
            <el-descriptions-item label="直属子组">
              {{ selected.children.length }} 个
            </el-descriptions-item>
            <el-descriptions-item label="直属资产">
              {{ selected.asset_count }} 条
            </el-descriptions-item>
            <el-descriptions-item label="含子组资产">
              {{ selected.total_asset_count }} 条
            </el-descriptions-item>
            <el-descriptions-item label="说明" :span="2">
              {{ selected.description || '—' }}
            </el-descriptions-item>
            <el-descriptions-item label="创建时间">
              {{ formatDateTime(selected.created_at) }}
            </el-descriptions-item>
            <el-descriptions-item label="更新时间">
              {{ formatDateTime(selected.updated_at) }}
            </el-descriptions-item>
          </el-descriptions>

          <div v-if="canWrite" class="flex flex-wrap gap-2">
            <el-tooltip
              :disabled="canCreateChild"
              content="已达 8 层上限，无法继续新建子组"
              placement="top"
            >
              <span>
                <el-button
                  type="primary"
                  :icon="Plus"
                  :disabled="!canCreateChild"
                  @click="openCreate(selected)"
                >
                  新建子组
                </el-button>
              </span>
            </el-tooltip>
            <el-button @click="openEdit">编辑</el-button>
            <el-button @click="openMove">移动</el-button>
            <el-button type="danger" plain @click="handleDelete">删除</el-button>
          </div>
        </template>

        <el-empty v-else description="在左侧选择一个分组查看详情" />
      </div>
    </div>

    <!-- ── 新建 / 编辑 ───────────────────────────────────────────── -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="520px" destroy-on-close>
      <el-form ref="formRef" :model="form" :rules="rules" label-width="80px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="例如 华东区、核心机房" />
        </el-form-item>
        <el-form-item label="排序">
          <el-input-number v-model="form.sortOrder" :min="0" :max="9999" />
          <span class="ml-2 text-xs text-gray-400">同级内数字小的排前面</span>
        </el-form-item>
        <el-form-item label="说明" prop="description">
          <el-input
            v-model="form.description"
            type="textarea"
            :rows="3"
            placeholder="可留空，例如责任部门或物理位置"
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmit">保存</el-button>
      </template>
    </el-dialog>

    <!-- ── 移动 ─────────────────────────────────────────────────── -->
    <el-dialog v-model="moveVisible" title="移动分组" width="480px" destroy-on-close>
      <el-alert
        class="mb-4"
        type="info"
        :closable="false"
        show-icon
        title="移动会把整棵子树一起搬走"
        description="自身与自己的后代不可选 —— 那会形成环，使这部分节点从树上脱落。"
      />

      <el-form label-width="80px">
        <el-form-item label="分组">
          <span>{{ selected?.name }}</span>
        </el-form-item>
        <el-form-item label="目标父组">
          <el-tree-select
            v-model="moveTarget"
            class="w-full"
            :data="moveTree"
            :props="treeProps"
            node-key="id"
            check-strictly
            clearable
            default-expand-all
            :render-after-expand="false"
            placeholder="留空表示移到顶层"
          />
          <span class="text-xs text-gray-400">留空表示移到顶层（成为根组）</span>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="moveVisible = false">取消</el-button>
        <el-button type="primary" :loading="moving" @click="handleMove">确认移动</el-button>
      </template>
    </el-dialog>
  </div>
</template>
