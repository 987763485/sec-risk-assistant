<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { Connection, Plus, Refresh } from '@element-plus/icons-vue'

import {
  createIntegration,
  lastStatusLabel,
  lastStatusTagType,
  listIntegrations,
  updateIntegration,
} from '@/api/integrations'
import type {
  Integration,
  IntegrationList,
  IntegrationType,
  IntegrationTypeOption,
} from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'

/**
 * 情报源集成配置页。
 *
 * 这一页只做一件事：登记「从哪里取 CVE 情报」。它刻意**不做**「立即拉取」——
 * 拉取的入参是（漏洞, 可选 CVE），而这一页没有「当前漏洞」这个上下文；
 * 硬塞一个漏洞选择框只会让这里变成一个伪装成配置页的拉取入口。
 * 触发拉取的入口在漏洞详情里（情报是漏洞的属性，见 docs/01 §2.7）。
 */

const auth = useAuthStore()

/**
 * 建 / 改配置按 `system:write` 显隐，而不是 `integration:write`。
 *
 * 这两条权限的分界是「管理动作 vs 业务动作」：把一个能向外发请求的出站
 * 目标写进系统配置属于前者。评估员持有 `integration:read/write`，
 * 但在这一页里只能看、不能改。
 *
 * ⚠️ 这只是体验层：真正的拦阻在后端路由的 RequirePermission 上。
 */
const canManage = computed(() => auth.can('system:write'))

// ------------------------------------------------------------------ 列表

const loading = ref(false)
const data = ref<IntegrationList | null>(null)

const rows = computed<Integration[]>(() => data.value?.items ?? [])
const supportedTypes = computed<IntegrationTypeOption[]>(() => data.value?.supported_types ?? [])
const credentialPrefix = computed(() => data.value?.credential_env_prefix ?? '')

async function load() {
  loading.value = true
  try {
    data.value = await listIntegrations()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载集成配置失败')
    data.value = null
  } finally {
    loading.value = false
  }
}

onMounted(() => void load())

// ------------------------------------------------------------------ 新建 / 编辑

const dialogVisible = ref(false)
const editingId = ref(0)
const submitting = ref(false)
const formRef = ref<FormInstance>()

const isCreate = computed(() => editingId.value === 0)

/**
 * 表单里的 `type` 刻意是 `string` 而不是契约的联合类型。
 *
 * 契约把类型写成了枚举，但**它的权威来源是后端**：新增一个适配器时
 * 后端下发新的 `supported_types`，而前端的联合类型要等重新生成才会跟上。
 * 若这里用联合类型，就得在「后端已经支持、前端类型还没重新生成」的窗口期
 * 做一次断言——断言在这里只会掩盖问题。改为提交前用后端下发的列表核对
 * （见 `resolveType`），把「非法类型」变成一个能说清的界面提示。
 */
const form = reactive({
  name: '',
  type: '' as string,
  baseUrl: '',
  credentialEnv: '',
  enabled: true,
  timeoutMs: 10000,
})

/**
 * 上一个选中的类型。
 *
 * 为什么需要这个变量：`@change` 触发时 v-model 已经把 `form.type` 改成新值了，
 * 在事件处理里读 `form.type` 拿到的永远是「新值」，于是「这次改动之前地址是不是
 * 默认值」这个判断恒为假 —— 表现为选了类型地址却不跟着预填。
 */
const lastType = ref('')

/** 编辑中该集成原本的凭据变量名；`null` 表示它本来就没有凭据 */
const originalCredentialEnv = ref<string | null>(null)

const selectedType = computed(() => supportedTypes.value.find((t) => t.type === form.type))

const rules = computed<FormRules<typeof form>>(() => ({
  name: [
    { required: true, message: '请输入配置名称', trigger: 'blur' },
    { max: 64, message: '名称不得超过 64 个字符', trigger: 'blur' },
  ],
  type: [{ required: true, message: '请选择情报源类型', trigger: 'change' }],
  baseUrl: [{ max: 255, message: '地址不得超过 255 个字符', trigger: 'blur' }],
  credentialEnv: [
    { max: 64, message: '变量名不得超过 64 个字符', trigger: 'blur' },
    {
      // 前缀是后端定的，这里只用它做即时提示；真正的校验在后端
      // （前端拦一道只是为了不让人白填一遍再吃 400）
      validator: (_rule, value: string, callback) => {
        const prefix = credentialPrefix.value
        if (!value || !prefix || value.startsWith(prefix)) {
          callback()
          return
        }
        callback(new Error(`变量名必须以 ${prefix} 开头`))
      },
      trigger: 'blur',
    },
  ],
}))

/** 类型下拉选中项的推荐默认地址；没选类型时为 '' */
function defaultBaseUrl(type: string): string {
  return supportedTypes.value.find((t) => t.type === type)?.default_base_url ?? ''
}

function openCreate() {
  editingId.value = 0
  originalCredentialEnv.value = null
  // 默认选中第一个可用类型，省掉一次无意义的点击；没有可选项时留空，
  // 由 type 的 required 规则挡住提交
  const first = supportedTypes.value[0]?.type ?? ''
  lastType.value = first
  Object.assign(form, {
    name: '',
    type: first,
    baseUrl: defaultBaseUrl(first),
    credentialEnv: '',
    enabled: true,
    timeoutMs: 10000,
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

function openEdit(row: Integration) {
  editingId.value = row.id
  originalCredentialEnv.value = row.credential_env || null
  lastType.value = row.type
  Object.assign(form, {
    name: row.name,
    type: row.type,
    baseUrl: row.base_url,
    credentialEnv: row.credential_env,
    enabled: row.enabled,
    timeoutMs: row.timeout_ms,
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

/**
 * 切换类型时同步预填地址。
 *
 * 只在这个字段「空着」或「还是上一个类型的默认值」时才覆盖：用户已经
 * 手填过的地址不能被一次误点抹掉——那会静默丢掉他刚输入的内容。
 */
function onTypeChange(next: string) {
  const wasDefault = !form.baseUrl || form.baseUrl === defaultBaseUrl(lastType.value)
  if (wasDefault) form.baseUrl = defaultBaseUrl(next)
  lastType.value = next
}

/**
 * 把表单里的类型字符串收敛成契约类型。
 *
 * 判据是「后端下发的可选项里有没有这一项」而不是「像不像一个类型名」：
 * 新增适配器时前端零改动，而伪造的类型也进不了请求体。
 */
function resolveType(raw: string): IntegrationType | null {
  const hit = supportedTypes.value.find((t) => t.type === raw)
  return hit ? (hit.type as IntegrationType) : null
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  const type = resolveType(form.type)
  if (!type) {
    ElMessage.error('请选择一个当前支持的情报源类型')
    return
  }

  const baseUrl = form.baseUrl.trim()
  const credentialEnv = form.credentialEnv.trim()

  submitting.value = true
  try {
    if (isCreate.value) {
      await createIntegration({
        name: form.name.trim(),
        type,
        base_url: baseUrl || undefined,
        credential_env: credentialEnv || undefined,
        enabled: form.enabled,
        timeout_ms: form.timeoutMs,
      })
      ElMessage.success('集成已创建')
    } else {
      await updateIntegration(editingId.value, {
        name: form.name.trim(),
        type,
        base_url: baseUrl,
        // 三态：没动过就不传；清空了就显式传 null；否则传新变量名。
        // 「不传」与「传空串」在后端是两个不同的意思，不能混用 `|| undefined`。
        credential_env:
          credentialEnv === (originalCredentialEnv.value ?? '') ? undefined : credentialEnv || null,
        enabled: form.enabled,
        timeout_ms: form.timeoutMs,
      })
      ElMessage.success('已保存')
    }
    dialogVisible.value = false
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

// ------------------------------------------------------------------ 行内操作

/**
 * 启用 / 停用。
 *
 * 本页**没有删除**：集成配置是审计记录指向的对象（`integration.fetch`
 * 的明细里记着 integration_id 与 base_url），删掉会让历史审计变成
 * 「一条指向不存在的配置的记录」。停用已经覆盖了「不再使用」这个
 * 真实需求，而且可逆、可追溯。
 */
async function toggleEnabled(row: Integration) {
  const next = !row.enabled
  try {
    await updateIntegration(row.id, { enabled: next })
    ElMessage.success(next ? '已启用' : '已停用（历史拉取记录仍可追溯）')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '操作失败')
  }
}

// ------------------------------------------------------------------ 展示辅助

function asIntegration(row: TableRow): Integration {
  return asRow<Integration>(row)
}

/** 最近一次拉取的耗时，未拉取过时给占位符 */
function latencyLabel(row: Integration): string {
  return row.last_latency_ms == null ? '—' : `${row.last_latency_ms} ms`
}
</script>

<template>
  <div class="app-page">
    <div class="app-panel">
      <div class="mb-4 flex items-start gap-3">
        <el-icon class="mt-1 text-lg text-gray-400"><Connection /></el-icon>
        <div class="flex-1">
          <h2 class="mb-1 text-base font-medium mbs-auto">情报源集成</h2>
          <p class="text-xs leading-5 text-gray-500">
            登记「从哪里取 CVE 情报」。这里只存放配置与运行态，
            <strong>凭据本身永不入库</strong>——登记的是凭据所在的
            <em>环境变量名</em>，读取只发生在服务进程内。 触发拉取的入口在「漏洞管理 →
            漏洞清单 → 详情」：情报是漏洞的属性。
          </p>
        </div>
        <div class="flex gap-2">
          <el-button :icon="Refresh" @click="load">刷新</el-button>
          <el-button v-if="canManage" type="primary" :icon="Plus" @click="openCreate">
            新建集成
          </el-button>
        </div>
      </div>

      <el-alert class="mb-4" type="warning" :closable="false" show-icon>
        <template #title>两个容易踩的坑</template>
        <ul class="ml-4 list-disc text-xs leading-5">
          <li>
            凭据变量名必须以
            <code v-if="credentialPrefix">{{ credentialPrefix }}</code>
            <code v-else>SR_INTEL_</code>
            开头。这<strong>不是</strong>格式洁癖：允许任意变量名等于开出一个
            「读取任意环境变量」的原语，可以把服务自身的密钥发到外部地址。
          </li>
          <li>
            上游地址会过 SSRF 校验——域名解析出的<strong>每一个</strong> IP
            都不得落在回环、私有、 链路本地、CGNAT
            或保留网段，并且请求时会再复核一次实际连接的对端地址 （防 DNS
            rebinding）。内网自建情报源目前会被拒绝。
          </li>
        </ul>
      </el-alert>

      <!-- 插槽里的 row 是 Record<PropertyKey, any>，传给需要具名类型的函数前
           必须经 asIntegration 收敛（原因见 @/utils/table） -->
      <el-table v-loading="loading" :data="rows" stripe style="width: 100%">
        <el-table-column prop="name" label="名称" min-width="150" fixed>
          <template #default="{ row }">
            <span>{{ row.name }}</span>
            <el-tag
              v-if="!row.enabled"
              class="ml-2"
              size="small"
              type="info"
              effect="plain"
            >
              已停用
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ row.type_label }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="上游地址" min-width="230">
          <template #default="{ row }">
            <code v-if="row.base_url" class="text-xs">{{ row.base_url }}</code>
            <span v-else class="text-xs text-gray-400">无需地址（离线驱动）</span>
          </template>
        </el-table-column>

        <el-table-column label="凭据变量" min-width="200">
          <template #default="{ row }">
            <template v-if="row.credential_env">
              <code class="text-xs">{{ row.credential_env }}</code>
              <el-tag
                class="ml-2"
                size="small"
                :type="row.credential_present ? 'success' : 'warning'"
                effect="plain"
              >
                {{ row.credential_present ? "变量已设置" : "变量未设置" }}
              </el-tag>
            </template>
            <span v-else class="text-xs text-gray-400">无需凭据</span>
          </template>
        </el-table-column>

        <el-table-column label="最近拉取" width="200">
          <template #default="{ row }">
            <div class="flex items-center gap-2">
              <el-tag
                size="small"
                :type="lastStatusTagType(asIntegration(row).last_status)"
                effect="plain"
              >
                {{ lastStatusLabel(asIntegration(row).last_status) }}
              </el-tag>
              <el-tooltip
                :disabled="!row.last_error"
                :content="row.last_error"
                placement="top"
              >
                <span class="text-xs text-gray-500">{{
                  latencyLabel(asIntegration(row))
                }}</span>
              </el-tooltip>
            </div>
            <div class="text-xs text-gray-400">
              {{ row.last_run_at ? formatDateTime(row.last_run_at) : "—" }}
            </div>
          </template>
        </el-table-column>

        <el-table-column label="记录更新时间" width="170">
          <template #default="{ row }">
            <!-- ⚠️ 这个时间**包含运行态写入**：一次拉取也会刷新它。
                 标成「最后修改」会让用户看到「我没改配置，时间怎么变了」 -->
            <el-tooltip
              content="配置变更与拉取都会刷新这一列，因此它不是「配置最后修改时间」"
              placement="top"
            >
              <span>{{ formatDateTime(row.updated_at) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <template v-if="canManage">
              <el-button
                link
                type="primary"
                size="small"
                @click="openEdit(asIntegration(row))"
              >
                编辑
              </el-button>
              <el-button
                link
                :type="row.enabled ? 'warning' : 'success'"
                size="small"
                @click="toggleEnabled(asIntegration(row))"
              >
                {{ row.enabled ? "停用" : "启用" }}
              </el-button>
            </template>
            <span v-else class="text-xs text-gray-400">只读</span>
          </template>
        </el-table-column>

        <template #empty>
          <el-empty description="还没有配置情报源集成">
            <el-button v-if="canManage" type="primary" @click="openCreate"
              >新建集成</el-button
            >
          </el-empty>
        </template>
      </el-table>

      <p class="mt-3 text-xs text-gray-400">
        本页没有「删除」：集成配置是审计记录指向的对象，删除会让历史拉取记录指向一个不存在的配置。
        不再使用时请改为「停用」。
      </p>
    </div>

    <!-- ── 新建 / 编辑 ───────────────────────────────────────────── -->
    <el-dialog
      v-model="dialogVisible"
      :title="isCreate ? '新建情报源集成' : '编辑情报源集成'"
      width="560px"
      destroy-on-close
    >
      <el-form ref="formRef" :model="form" :rules="rules" label-width="104px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="例如 NVD 官方（主）" />
          <span class="text-xs text-gray-400">用于区分同类型的多个实例，全局唯一</span>
        </el-form-item>

        <el-form-item label="类型" prop="type">
          <el-select
            v-model="form.type"
            class="w-full"
            placeholder="请选择"
            @change="onTypeChange"
          >
            <el-option
              v-for="option in supportedTypes"
              :key="option.type"
              :label="option.label"
              :value="option.type"
            />
          </el-select>
          <span class="text-xs text-gray-400">
            由后端下发。新增适配器时这里会自动多出一项，无需改前端
          </span>
        </el-form-item>

        <el-form-item label="上游地址" prop="baseUrl">
          <el-input v-model="form.baseUrl" placeholder="https://..." />
          <span class="text-xs text-gray-400">
            必须是 http/https，且解析结果不得指向内网。留空时按类型取默认地址
          </span>
        </el-form-item>

        <el-form-item label="凭据变量" prop="credentialEnv">
          <el-input
            v-model="form.credentialEnv"
            :placeholder="`${credentialPrefix}EXAMPLE_KEY`"
          />
          <span class="text-xs text-gray-400">
            填变量<strong>名</strong>，不填值。留空表示无需凭据
          </span>
          <span
            v-if="selectedType?.credential_recommended"
            class="text-xs text-orange-500"
          >
            该类型建议配置凭据：不配也能调，但会被严格限流
          </span>
        </el-form-item>

        <el-form-item label="超时">
          <el-input-number
            v-model="form.timeoutMs"
            :min="1000"
            :max="30000"
            :step="500"
          />
          <span class="ml-2 text-xs text-gray-400"
            >毫秒，服务端会把越界值收敛到该区间</span
          >
        </el-form-item>

        <el-form-item label="状态">
          <el-switch v-model="form.enabled" active-text="启用" inactive-text="停用" />
          <div class="text-xs text-gray-400">
            停用后不会被选作拉取来源，历史情报不受影响
          </div>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmit"
          >保存</el-button
        >
      </template>
    </el-dialog>
  </div>
</template>
