<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { ArrowLeft, Refresh } from '@element-plus/icons-vue'

import { RISK_LEVEL_LABELS, RISK_LEVEL_TAG_TYPE } from '@/api/assessments'
import {
  REMEDIATION_LOG_ACTION_LABELS,
  REMEDIATION_STATUS_LABELS,
  REMEDIATION_STATUS_ORDER,
  REMEDIATION_STATUS_TAG_TYPE,
  getRemediation,
  remediationTimingTagType,
  remediationTimingText,
  updateRemediation,
} from '@/api/remediations'
import type { Remediation, RemediationDetail, RemediationStatus, RiskLevel } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'
import AssigneeSelect from './components/AssigneeSelect.vue'
import TransitionDialog from './components/TransitionDialog.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const canWrite = computed(() => auth.can('remediation:write'))
const remediationId = computed(() => Number(route.params.id))

const loading = ref(true)
const detail = ref<RemediationDetail | null>(null)

const current = computed<Remediation | null>(() => detail.value?.remediation ?? null)
const logs = computed(() => detail.value?.logs ?? [])

async function load() {
  loading.value = true
  try {
    detail.value = await getRemediation(remediationId.value)
    const row = detail.value.remediation
    form.value = {
      title: row.title,
      description: row.description,
      resolution: row.resolution,
      assigneeId: row.assignee_id,
      dueDate: row.due_date ?? '',
    }
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载整改单失败')
    detail.value = null
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
})

// ------------------------------------------------------------------ 编辑字段

const form = ref({
  title: '',
  description: '',
  resolution: '',
  assigneeId: null as number | null,
  dueDate: '',
})

const saving = ref(false)

/**
 * 保存字段。
 *
 * 五个字段**全部**随请求发出（含显式 `null`），不区分「不传」与「null」：
 * 这是一个「所见即所得」的整体表单，用户看到的就是要提交的最终状态。
 * 三态语义留给需要它的场景（比如只改一项），那是另一个交互。
 *
 * 状态不在这里改——它走流转对话框。混在一起的话，审计里只能看到
 * 一个 update，「改了个期限」与「把单子打回了」再也分不清。
 */
async function handleSave() {
  const row = current.value
  if (!row) return
  if (!form.value.title.trim()) {
    ElMessage.warning('标题不能为空')
    return
  }

  saving.value = true
  try {
    await updateRemediation(row.id, {
      title: form.value.title.trim(),
      description: form.value.description.trim(),
      resolution: form.value.resolution.trim(),
      assignee_id: form.value.assigneeId,
      due_date: form.value.dueDate || null,
    })
    ElMessage.success('已保存')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    saving.value = false
  }
}

// ------------------------------------------------------------------ 流转

const transitionVisible = ref(false)
const transitionPreset = ref<RemediationStatus | ''>('')

function openTransition(preset: RemediationStatus | '' = '') {
  transitionPreset.value = preset
  transitionVisible.value = true
}

async function handleTransitioned() {
  await load()
}

// ------------------------------------------------------------------ 展示

function handleBack() {
  void router.push({ name: 'remediations-list' })
}

/** 出处跳转：只跳到那次评估的结果页，不试图定位到具体风险项 */
function openAssessment() {
  const id = current.value?.assessment_id
  if (!id) return
  void router.push({ name: 'assessment-result', params: { id: String(id) } })
}

/**
 * 出处是否可能已失效。
 *
 * 评估重算后 `risk_item_id` 指向的行已不存在（这是设计允许的：
 * 整改单的身份是 (资产, 漏洞)，不是风险项 ID）。界面不隐藏这个出处，
 * 而是加一句提示——用户需要知道「这条是从哪来的」，也需要知道
 * 「为什么点进去找不到那一条了」。
 */
const hasSource = computed(() => current.value?.risk_item_id !== null)
</script>

<template>
  <div v-loading="loading" class="p-4">
    <template v-if="current">
      <!-- ── 头部 ─────────────────────────────────────────────────── -->
      <div class="app-panel mb-4">
        <div class="flex flex-wrap items-center gap-3">
          <el-button :icon="ArrowLeft" text @click="handleBack">返回列表</el-button>
          <span class="text-lg font-semibold">{{ current.title }}</span>
          <el-tag :type="REMEDIATION_STATUS_TAG_TYPE[current.status]" size="small">
            {{ REMEDIATION_STATUS_LABELS[current.status] }}
          </el-tag>
          <el-tag :type="remediationTimingTagType(current)" size="small" effect="plain">
            {{ remediationTimingText(current) }}
          </el-tag>

          <div class="ml-auto flex items-center gap-2">
            <el-button :icon="Refresh" @click="load">刷新</el-button>
            <el-dropdown v-if="canWrite && current.transitions.length" @command="openTransition">
              <el-button type="primary">状态流转</el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item
                    v-for="opt in current.transitions"
                    :key="opt.to_status"
                    :command="opt.to_status"
                  >
                    {{ REMEDIATION_STATUS_LABELS[opt.to_status] }}
                    <span v-if="opt.note_required" class="ml-1 text-xs text-gray-400">需说明</span>
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </div>

        <div class="mt-2 text-xs text-gray-400">
          建单人 {{ current.created_by_name || '—' }} · 创建于
          {{ formatDateTime(current.created_at) }}
          <span v-if="current.closed_at"> · 结束于 {{ formatDateTime(current.closed_at) }}</span>
        </div>
      </div>

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <!-- ── 左：目标与来源 ─────────────────────────────────────── -->
        <div class="lg:col-span-1">
          <div class="app-panel mb-4">
            <h2 class="mb-3 text-sm font-semibold">整改目标</h2>
            <el-descriptions :column="1" size="small" border>
              <el-descriptions-item label="资产">
                {{ current.asset_name }}
                <span v-if="current.asset_ip" class="text-xs text-gray-400">
                  （{{ current.asset_ip }}）
                </span>
              </el-descriptions-item>
              <el-descriptions-item label="漏洞">{{ current.vuln_title }}</el-descriptions-item>
              <el-descriptions-item label="CVE">
                {{ current.vuln_cve_ids || '—' }}
              </el-descriptions-item>
              <el-descriptions-item label="风险">
                <span class="font-semibold">R = {{ current.risk_value_r.toFixed(1) }}</span>
                <el-tag
                  size="small"
                  class="ml-2"
                  :type="RISK_LEVEL_TAG_TYPE[current.risk_level as RiskLevel]"
                >
                  {{ RISK_LEVEL_LABELS[current.risk_level as RiskLevel] }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="期限">
                {{ current.due_date ?? '未设期限' }}
              </el-descriptions-item>
              <el-descriptions-item label="负责人">
                {{ current.assignee_name || '未分派' }}
              </el-descriptions-item>
            </el-descriptions>

            <div class="mt-3 text-xs text-gray-500">
              <template v-if="current.assessment_id">
                来源评估：
                <el-button link type="primary" size="small" @click="openAssessment">
                  #{{ current.assessment_id }}
                </el-button>
                <span v-if="!hasSource">（该来源风险项已随评估重算失效）</span>
              </template>
              <template v-else>来源评估已不可考</template>
              <div class="mt-1 text-gray-400">
                整改单的身份是「资产 + 漏洞」而不是风险项 ID：评估重算会整批替换
                风险项，用后者做身份会让单子在重算后静默断链。
              </div>
            </div>
          </div>

          <!-- ── 时间态说明 ─────────────────────────────────────── -->
          <div class="app-panel">
            <h2 class="mb-2 text-sm font-semibold">时间态</h2>
            <ul class="space-y-1 text-xs text-gray-500">
              <li>逾期 {{ current.overdue ? `是（${current.overdue_days} 天）` : '否' }}</li>
              <li>
                距到期
                {{
                  current.due_in_days === null
                    ? '—（未设期限或已结束）'
                    : current.due_in_days === 0
                      ? '今天到期'
                      : `还有 ${current.due_in_days} 天`
                }}
              </li>
            </ul>
            <div class="mt-2 text-xs text-gray-400">
              这三个值由后端按「今天」（服务端时区）算好，前端不做任何日期比较：
              本地时区再算一遍会让同一张单子在列表页与仪表盘上一个逾期、 一个不逾期。
            </div>
          </div>
        </div>

        <!-- ── 右：内容与时间线 ───────────────────────────────────── -->
        <div class="lg:col-span-2">
          <div class="app-panel mb-4">
            <h2 class="mb-3 text-sm font-semibold">内容</h2>

            <el-form label-width="72px">
              <el-form-item label="标题">
                <el-input v-model="form.title" maxlength="255" :disabled="!canWrite" />
              </el-form-item>
              <el-form-item label="说明">
                <el-input
                  v-model="form.description"
                  type="textarea"
                  :rows="2"
                  maxlength="1000"
                  show-word-limit
                  :disabled="!canWrite"
                  placeholder="要改成什么、有哪些前置条件"
                />
              </el-form-item>
              <el-form-item label="整改结论">
                <el-input
                  v-model="form.resolution"
                  type="textarea"
                  :rows="3"
                  maxlength="1000"
                  show-word-limit
                  :disabled="!canWrite"
                  placeholder="怎么修的。闭环时必填——通过「状态流转」的说明字段写下"
                />
              </el-form-item>
              <el-form-item label="负责人">
                <AssigneeSelect v-model="form.assigneeId" />
              </el-form-item>
              <el-form-item label="期限">
                <el-date-picker
                  v-model="form.dueDate"
                  type="date"
                  value-format="YYYY-MM-DD"
                  placeholder="留空表示不设期限（永远不算逾期）"
                  :disabled="!canWrite"
                  class="w-full"
                />
              </el-form-item>
              <el-form-item v-if="canWrite">
                <el-button type="primary" :loading="saving" @click="handleSave">保存</el-button>
                <span class="ml-3 text-xs text-gray-400">
                  保存只改字段，不改状态。状态变化走「状态流转」——它会单独留一条
                  审计记录，也能带上理由。
                </span>
              </el-form-item>
            </el-form>
          </div>

          <!-- ── 时间线 ──────────────────────────────────────────── -->
          <div class="app-panel">
            <h2 class="mb-3 text-sm font-semibold">流转记录</h2>

            <el-timeline v-if="logs.length">
              <el-timeline-item
                v-for="log in logs"
                :key="log.id"
                :timestamp="formatDateTime(log.created_at)"
                placement="top"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <el-tag size="small" effect="plain">
                    {{ REMEDIATION_LOG_ACTION_LABELS[log.action] ?? log.action }}
                  </el-tag>
                  <template v-if="log.action === 'transition'">
                    <span class="text-sm">
                      {{
                        REMEDIATION_STATUS_LABELS[log.from_status as RemediationStatus] ??
                        log.from_status
                      }}
                      →
                      {{
                        REMEDIATION_STATUS_LABELS[log.to_status as RemediationStatus] ??
                        log.to_status
                      }}
                    </span>
                  </template>
                  <template v-else-if="log.action === 'create'">
                    <span class="text-sm">
                      创建为「{{
                        REMEDIATION_STATUS_LABELS[log.to_status as RemediationStatus] ??
                        log.to_status
                      }}」
                    </span>
                  </template>
                  <span class="text-xs text-gray-400">{{ log.operator_name || '—' }}</span>
                </div>
                <div v-if="log.note" class="mt-1 text-sm text-gray-600">{{ log.note }}</div>
              </el-timeline-item>
            </el-timeline>

            <el-empty v-else description="没有流转记录" :image-size="60" />

            <div class="mt-2 text-xs text-gray-400">
              操作人姓名是当时的快照，不是实时查用户表——时间线要回答「当时是谁做的」，
              账号后来改名不该改写历史。
            </div>
          </div>
        </div>
      </div>

      <!-- ── 状态说明 ─────────────────────────────────────────────── -->
      <div class="app-panel mt-4">
        <h2 class="mb-2 text-sm font-semibold">状态说明</h2>
        <div class="flex flex-wrap gap-3 text-xs text-gray-500">
          <span
            v-for="status in REMEDIATION_STATUS_ORDER"
            :key="status"
            class="flex items-center gap-1"
          >
            <el-tag :type="REMEDIATION_STATUS_TAG_TYPE[status]" size="small">
              {{ REMEDIATION_STATUS_LABELS[status] }}
            </el-tag>
          </span>
        </div>
        <div class="mt-2 text-xs text-gray-400">
          「已闭环」与「风险接受」是**终态且不可逆**。漏洞复发时新建一张单，
          而不是重新打开旧单——允许重新打开会与「同一 (资产, 漏洞) 只允许一张
          未闭环单」的唯一约束争取同一把锁。
        </div>
      </div>
    </template>

    <el-empty v-else-if="!loading" description="整改单不存在或已被删除" />

    <TransitionDialog
      v-model="transitionVisible"
      :remediation="current"
      :preset="transitionPreset"
      @done="handleTransitioned"
    />
  </div>
</template>
