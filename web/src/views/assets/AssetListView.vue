<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { Download, Plus, Refresh, Search, Upload } from '@element-plus/icons-vue'

import {
  ASSET_STATUS_LABELS,
  ASSET_STATUS_TAG_TYPE,
  createAsset,
  deleteAsset,
  downloadImportTemplate,
  IMPORTANCE_LABELS,
  listAssets,
  updateAsset,
} from '@/api/assets'
import { listAssetGroupTree } from '@/api/assetGroups'
import { listDictionaries } from '@/api/dictionaries'
import type { Asset, AssetGroup, AssetStatus, Dictionary } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { saveBlob } from '@/utils/download'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'
import AssetImportDialog from './components/AssetImportDialog.vue'

const auth = useAuthStore()

/**
 * 写操作按 asset:write 权限显隐。
 *
 * ⚠️ 这只是体验层：真正的拦阻在后端路由的 RequirePermission 上。
 * 隐藏按钮是为了不让人点进去再吃一个 403，不是安全边界。
 */
const canWrite = computed(() => auth.can('asset:write'))

/** 是否允许下载模板。下载写在后端也是 asset:write（只有能导入的人才需要模板） */
const canImport = canWrite

const STATUS_OPTIONS: AssetStatus[] = ['in_use', 'idle', 'offline', 'scrapped']

// ------------------------------------------------------------------ 字典与分组

const assetTypes = ref<Dictionary[]>([])
const groupTree = ref<AssetGroup[]>([])

/** el-tree / el-tree-select 默认按 `label` 取名称，这里要换成 `name` */
const groupTreeProps = { label: 'name', children: 'children' } as const

async function loadCatalogs() {
  // 两个字典各自失败不影响另一方：类型拿不到时筛选框是空的，但台账还能看
  try {
    // enabledOnly = true：新建/编辑表单里不能出现已停用的类型。
    // 停用项仍会出现在**列表**的中文名里（那是服务端补齐的 asset_type_name），
    // 两种展示口径的差异是刻意的。
    assetTypes.value = await listDictionaries('asset_type', true)
  } catch {
    assetTypes.value = []
  }

  try {
    groupTree.value = await listAssetGroupTree()
  } catch {
    groupTree.value = []
  }
}

// ------------------------------------------------------------------ 列表

const loading = ref(false)
const rows = ref<Asset[]>([])
const total = ref(0)

const query = reactive({
  keyword: '',
  assetType: '',
  status: '' as AssetStatus | '',
  importance: undefined as number | undefined,
  groupId: undefined as number | undefined,
  includeChildren: true,
  page: 1,
  pageSize: 20,
})

async function load() {
  loading.value = true
  try {
    const page = await listAssets({
      page: query.page,
      pageSize: query.pageSize,
      keyword: query.keyword.trim(),
      asset_type: query.assetType || undefined,
      status: query.status || undefined,
      importance: query.importance,
      group_id: query.groupId,
      // 只在选中了组的时候才传：没选组时传 include_children 是一个
      // 与任何筛选条件都无关的参数，会让「这次查询到底筛了什么」变模糊
      include_children: query.groupId ? query.includeChildren : undefined,
    })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载资产台账失败')
    rows.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  query.page = 1
  void load()
}

function handleReset() {
  Object.assign(query, {
    keyword: '',
    assetType: '',
    status: '',
    importance: undefined,
    groupId: undefined,
    includeChildren: true,
    page: 1,
  })
  void load()
}

onMounted(() => {
  void load()
  void loadCatalogs()
})

// ------------------------------------------------------------------ 导入

const importVisible = ref(false)

/** 导入成功后要同时刷新台账与分组树：一次导入可能建出好几个新组 */
async function handleImported() {
  await Promise.all([load(), loadCatalogs()])
}

const templateDownloading = ref(false)

async function handleDownloadTemplate() {
  templateDownloading.value = true
  try {
    const { blob, fileName } = await downloadImportTemplate()
    saveBlob(blob, fileName)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '下载模板失败')
  } finally {
    templateDownloading.value = false
  }
}

// ------------------------------------------------------------------ 新建 / 编辑

const dialogVisible = ref(false)
const editingId = ref(0)
const submitting = ref(false)
const formRef = ref<FormInstance>()

const isCreate = computed(() => editingId.value === 0)

const form = reactive({
  assetNo: '',
  name: '',
  assetType: '',
  groupId: null as number | null,
  ipAddress: '',
  port: null as number | null,
  hostname: '',
  osType: '',
  importance: 3,
  owner: '',
  department: '',
  status: 'in_use' as AssetStatus,
  tags: [] as string[],
  description: '',
})

/**
 * 标签的输入约束。
 *
 * 后端以逗号分隔存储标签，因此单个标签里出现逗号会把一个标签变成两个。
 * 这是**输入卫生**而不是业务规则：真正的约束仍在后端，这里只是不让用户
 * 提交一份注定被拒绝或不按本意解释的表单。
 */
function validateTags(_rule: unknown, value: string[], callback: (error?: Error) => void) {
  if (value.length > 10) {
    callback(new Error('标签最多 10 个'))
    return
  }
  const tooLong = value.find((tag) => tag.length > 32)
  if (tooLong) {
    callback(new Error(`标签「${tooLong}」超过 32 字符`))
    return
  }
  const withComma = value.find((tag) => tag.includes(',') || tag.includes('，'))
  if (withComma) {
    callback(new Error(`标签「${withComma}」不能包含逗号`))
    return
  }
  callback()
}

const rules = computed<FormRules<typeof form>>(() => ({
  name: [
    { required: true, message: '请输入资产名称', trigger: 'blur' },
    { max: 128, message: '名称不得超过 128 个字符', trigger: 'blur' },
  ],
  assetType: [{ required: true, message: '请选择资产类型', trigger: 'change' }],
  assetNo: [
    {
      pattern: /^[A-Za-z0-9][A-Za-z0-9_./-]{0,63}$/,
      message: '以字母或数字开头，只能包含字母、数字、_ . / -，最长 64 位',
      trigger: 'blur',
    },
  ],
  ipAddress: [{ max: 64, message: 'IP 或主机名不得超过 64 个字符', trigger: 'blur' }],
  hostname: [{ max: 128, message: '主机名不得超过 128 个字符', trigger: 'blur' }],
  osType: [{ max: 64, message: '操作系统不得超过 64 个字符', trigger: 'blur' }],
  owner: [{ max: 64, message: '负责人不得超过 64 个字符', trigger: 'blur' }],
  department: [{ max: 64, message: '归属部门不得超过 64 个字符', trigger: 'blur' }],
  description: [{ max: 512, message: '备注不得超过 512 个字符', trigger: 'blur' }],
  tags: [{ validator: validateTags, trigger: 'change' }],
}))

function openCreate() {
  editingId.value = 0
  Object.assign(form, {
    assetNo: '',
    name: '',
    assetType: assetTypes.value[0]?.code ?? '',
    groupId: null,
    ipAddress: '',
    port: null,
    hostname: '',
    osType: '',
    importance: 3,
    owner: '',
    department: '',
    status: 'in_use' as AssetStatus,
    tags: [],
    description: '',
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

function openEdit(row: Asset) {
  editingId.value = row.id
  Object.assign(form, {
    assetNo: row.asset_no ?? '',
    name: row.name,
    assetType: row.asset_type,
    groupId: row.group_id ?? null,
    ipAddress: row.ip_address ?? '',
    // 后端的「未填写」是 0，而 0 不是合法端口；这里换回 null，
    // 否则输入框里会出现一个 0，保存时被后端以「端口取值非法」拒绝
    port: row.port && row.port > 0 ? row.port : null,
    hostname: row.hostname ?? '',
    osType: row.os_type ?? '',
    importance: row.importance,
    owner: row.owner ?? '',
    department: row.department ?? '',
    status: row.status,
    tags: [...row.tags],
    description: row.description ?? '',
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  const common = {
    name: form.name.trim(),
    asset_type: form.assetType,
    // 显式传 null 而不是 undefined：三态语义下，undefined 会被后端理解为
    // 「不要动这个字段」，于是「把资产移出分组」「清掉端口」都会静默失效
    group_id: form.groupId,
    ip_address: form.ipAddress.trim(),
    port: form.port,
    hostname: form.hostname.trim(),
    os_type: form.osType.trim(),
    importance: form.importance,
    owner: form.owner.trim(),
    department: form.department.trim(),
    status: form.status,
    tags: form.tags,
    description: form.description.trim(),
  }

  submitting.value = true
  try {
    if (isCreate.value) {
      await createAsset({ ...common, asset_no: form.assetNo.trim() })
      ElMessage.success('资产已创建')
    } else {
      await updateAsset(editingId.value, {
        ...common,
        asset_no: form.assetNo.trim() || null,
      })
      ElMessage.success('已保存')
    }
    dialogVisible.value = false
    await Promise.all([load(), loadCatalogs()])
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

// ------------------------------------------------------------------ 删除

/**
 * 删除资产。
 *
 * 语义是「修正误录入」。退役请改状态为 scrapped —— 台账需要留下
 * 「这台机器曾经存在、已于某时退役」这个事实，删掉就丢掉了一段历史。
 * 因此确认框里把这条说清楚，而不是只问「确定删除吗」。
 */
async function handleDelete(row: Asset) {
  try {
    await ElMessageBox.confirm(
      `确定删除资产「${row.name}」吗？\n\n` +
        '删除后无法恢复。如果这台设备只是停用了，请改用「编辑 → 状态 → 已退役」，' +
        '这样台账里仍能查到它曾经存在。',
      '删除资产',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }

  try {
    await deleteAsset(row.id)
    ElMessage.success('已删除')
    await Promise.all([load(), loadCatalogs()])
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '删除失败')
  }
}

// ------------------------------------------------------------------ 展示辅助

function asAsset(row: TableRow): Asset {
  return asRow<Asset>(row)
}

function importanceLabel(value: number) {
  return IMPORTANCE_LABELS[value] ?? String(value)
}

function importanceTagType(value: number) {
  if (value >= 5) return 'danger'
  if (value >= 4) return 'warning'
  return 'info'
}

function statusLabel(row: Asset) {
  return ASSET_STATUS_LABELS[row.status]
}

function statusTagType(row: Asset) {
  return ASSET_STATUS_TAG_TYPE[row.status]
}

/** 资产类型下拉展示「中文名（码）」，方便与导入文件里的码对上 */
function assetTypeLabel(item: Dictionary) {
  return `${item.name}（${item.code}）`
}
</script>

<template>
  <div class="app-page">
    <!-- ── 筛选 ─────────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-end gap-3">
        <el-input
          v-model="query.keyword"
          class="w-60"
          placeholder="名称 / 编号 / IP / 主机名 / 负责人"
          :prefix-icon="Search"
          clearable
          @keyup.enter="handleSearch"
        />

        <el-select v-model="query.assetType" class="w-48" placeholder="全部类型" clearable>
          <el-option
            v-for="item in assetTypes"
            :key="item.code"
            :label="assetTypeLabel(item)"
            :value="item.code"
          />
        </el-select>

        <el-select v-model="query.status" class="w-32" placeholder="全部状态" clearable>
          <el-option
            v-for="status in STATUS_OPTIONS"
            :key="status"
            :label="ASSET_STATUS_LABELS[status]"
            :value="status"
          />
        </el-select>

        <el-select v-model="query.importance" class="w-32" placeholder="全部重要性" clearable>
          <el-option
            v-for="level in [1, 2, 3, 4, 5]"
            :key="level"
            :label="importanceLabel(level)"
            :value="level"
          />
        </el-select>

        <el-tree-select
          v-model="query.groupId"
          class="w-64"
          :data="groupTree"
          :props="groupTreeProps"
          node-key="id"
          check-strictly
          clearable
          default-expand-all
          :render-after-expand="false"
          placeholder="全部资产组"
        />

        <!-- 只在选中了具体某个组时才有意义，否则这个开关在描述一件与
             当前查询无关的事 -->
        <el-checkbox v-if="query.groupId" v-model="query.includeChildren"> 含子组 </el-checkbox>

        <el-button type="primary" :icon="Search" @click="handleSearch">查询</el-button>
        <el-button :icon="Refresh" @click="handleReset">重置</el-button>
      </div>
    </div>

    <!-- ── 列表 ─────────────────────────────────────────────────── -->
    <div class="app-panel">
      <div class="mb-4 flex items-center gap-2">
        <span class="text-sm text-gray-500">共 {{ total }} 条资产</span>
        <div v-if="canImport" class="ml-auto flex gap-2">
          <el-button
            :icon="Download"
            :loading="templateDownloading"
            @click="handleDownloadTemplate"
          >
            下载模板
          </el-button>
          <el-button :icon="Upload" @click="importVisible = true">批量导入</el-button>
          <el-button type="primary" :icon="Plus" @click="openCreate">新建资产</el-button>
        </div>
      </div>

      <!-- 插槽里的 row 是 Record<PropertyKey, any>，传给需要 Asset 的函数前
           必须经 asAsset 收敛（原因见 @/utils/table） -->
      <el-table v-loading="loading" :data="rows" stripe style="width: 100%">
        <el-table-column label="资产编号" min-width="140" fixed>
          <template #default="{ row }">
            <code v-if="row.asset_no" class="text-xs">{{ row.asset_no }}</code>
            <span v-else class="text-xs text-gray-400">未编号</span>
          </template>
        </el-table-column>

        <el-table-column prop="name" label="名称" min-width="180" show-overflow-tooltip />

        <el-table-column label="类型" min-width="130">
          <template #default="{ row }">{{ row.asset_type_name }}</template>
        </el-table-column>

        <el-table-column label="IP 地址" min-width="150">
          <template #default="{ row }">
            <span v-if="row.ip_address">{{ row.ip_address }}</span>
            <span v-else class="text-gray-400">—</span>
          </template>
        </el-table-column>

        <el-table-column label="端口" width="80">
          <template #default="{ row }">
            <!-- 后端的「未填写」是 0，只用于展示，不能回写 -->
            <span v-if="row.port">{{ row.port }}</span>
            <span v-else class="text-gray-400">—</span>
          </template>
        </el-table-column>

        <el-table-column label="主机名" min-width="150">
          <template #default="{ row }">{{ row.hostname || '—' }}</template>
        </el-table-column>

        <el-table-column label="资产组" min-width="130">
          <template #default="{ row }">
            <span v-if="row.group_name">{{ row.group_name }}</span>
            <span v-else class="text-gray-400">未分组</span>
          </template>
        </el-table-column>

        <el-table-column label="重要性" width="100">
          <template #default="{ row }">
            <el-tag :type="importanceTagType(row.importance)" size="small" effect="plain">
              {{ importanceLabel(row.importance) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="statusTagType(asAsset(row))" size="small">
              {{ statusLabel(asAsset(row)) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="标签" min-width="160">
          <template #default="{ row }">
            <template v-if="row.tags.length">
              <el-tag
                v-for="tag in row.tags"
                :key="tag"
                class="mr-1"
                size="small"
                type="info"
                effect="plain"
              >
                {{ tag }}
              </el-tag>
            </template>
            <span v-else class="text-gray-400">—</span>
          </template>
        </el-table-column>

        <el-table-column label="负责人" min-width="100">
          <template #default="{ row }">{{ row.owner || '—' }}</template>
        </el-table-column>

        <el-table-column label="更新时间" width="170">
          <template #default="{ row }">{{ formatDateTime(row.updated_at) }}</template>
        </el-table-column>

        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <template v-if="canWrite">
              <el-button link type="primary" size="small" @click="openEdit(asAsset(row))">
                编辑
              </el-button>
              <el-button link type="danger" size="small" @click="handleDelete(asAsset(row))">
                删除
              </el-button>
            </template>
            <span v-else class="text-xs text-gray-400">只读</span>
          </template>
        </el-table-column>

        <template #empty>
          <el-empty description="没有符合条件的资产" />
        </template>
      </el-table>

      <div class="mt-4 flex justify-end">
        <el-pagination
          v-model:current-page="query.page"
          v-model:page-size="query.pageSize"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          background
          @current-change="load"
          @size-change="handleSearch"
        />
      </div>
    </div>

    <!-- ── 新建 / 编辑 ───────────────────────────────────────────── -->
    <el-dialog
      v-model="dialogVisible"
      :title="isCreate ? '新建资产' : '编辑资产'"
      width="720px"
      destroy-on-close
    >
      <el-form ref="formRef" :model="form" :rules="rules" label-width="96px">
        <div class="flex gap-4">
          <el-form-item class="flex-1" label="名称" prop="name">
            <el-input v-model="form.name" placeholder="例如 核心交换机-01" />
          </el-form-item>
          <el-form-item class="flex-1" label="资产编号" prop="assetNo">
            <el-input v-model="form.assetNo" placeholder="可留空，留空即「未编号」" />
          </el-form-item>
        </div>

        <div class="flex gap-4">
          <el-form-item class="flex-1" label="资产类型" prop="assetType">
            <el-select v-model="form.assetType" class="w-full" placeholder="请选择">
              <el-option
                v-for="item in assetTypes"
                :key="item.code"
                :label="item.name"
                :value="item.code"
              />
            </el-select>
          </el-form-item>
          <el-form-item class="flex-1" label="所属分组">
            <el-tree-select
              v-model="form.groupId"
              class="w-full"
              :data="groupTree"
              :props="groupTreeProps"
              node-key="id"
              check-strictly
              clearable
              default-expand-all
              :render-after-expand="false"
              placeholder="不分组"
            />
          </el-form-item>
        </div>

        <div class="flex gap-4">
          <el-form-item class="flex-1" label="IP / 网段" prop="ipAddress">
            <el-input v-model="form.ipAddress" placeholder="IPv4 / IPv6 / CIDR / 主机名" />
          </el-form-item>
          <el-form-item class="flex-1" label="端口">
            <el-input-number
              v-model="form.port"
              class="w-full"
              :min="1"
              :max="65535"
              :value-on-clear="null"
              placeholder="留空表示未填写"
            />
          </el-form-item>
        </div>

        <div class="flex gap-4">
          <el-form-item class="flex-1" label="主机名" prop="hostname">
            <el-input v-model="form.hostname" placeholder="可留空" />
          </el-form-item>
          <el-form-item class="flex-1" label="操作系统" prop="osType">
            <el-input v-model="form.osType" placeholder="可留空" />
          </el-form-item>
        </div>

        <div class="flex gap-4">
          <el-form-item class="flex-1" label="重要性">
            <el-slider v-model="form.importance" :min="1" :max="5" show-stops />
            <span class="text-xs text-gray-400">
              资产价值 A（{{ importanceLabel(form.importance) }}）。省略按「中等」
            </span>
          </el-form-item>
          <el-form-item class="flex-1" label="状态">
            <el-radio-group v-model="form.status">
              <el-radio v-for="status in STATUS_OPTIONS" :key="status" :value="status">
                {{ ASSET_STATUS_LABELS[status] }}
              </el-radio>
            </el-radio-group>
          </el-form-item>
        </div>

        <div class="flex gap-4">
          <el-form-item class="flex-1" label="负责人" prop="owner">
            <el-input v-model="form.owner" placeholder="可留空" />
          </el-form-item>
          <el-form-item class="flex-1" label="归属部门" prop="department">
            <el-input v-model="form.department" placeholder="可留空" />
          </el-form-item>
        </div>

        <el-form-item label="标签" prop="tags">
          <el-select
            v-model="form.tags"
            class="w-full"
            multiple
            filterable
            allow-create
            default-first-option
            :reserve-keyword="false"
            placeholder="输入后回车创建，最多 10 个"
          />
          <span class="text-xs text-gray-400">用于跨类型归集，例如「等保三级」「涉密」</span>
        </el-form-item>

        <el-form-item label="备注" prop="description">
          <el-input v-model="form.description" type="textarea" :rows="2" placeholder="可留空" />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmit">保存</el-button>
      </template>
    </el-dialog>

    <!-- ── 批量导入 ─────────────────────────────────────────────── -->
    <AssetImportDialog v-model="importVisible" @imported="handleImported" />
  </div>
</template>
