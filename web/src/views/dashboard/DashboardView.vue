<script setup lang="ts">
/**
 * 总览（首页）。
 *
 * ▍这个页面最重要的一件事：把「口径」写在数字旁边
 *
 * 同一句「很高风险有多少条」，在四种口径下是四个不同的数字。
 * 因此风险区块的标题右侧永远显示它依附的那一次评估（ID / 名称 / 计算时间），
 * 并且可以切换。**不显示口径的汇总数字没有意义**——它看起来精确，
 * 实际上无法回答「这是什么时候的结论」。
 *
 * 资产 / 漏洞 / 整改单是全局当前态，与口径无关，因此它们不受上面的选择影响。
 *
 * ▍这里不做任何计算
 *
 * 所有数字（含逾期条数、即将到期条数）都由后端算好。前端只做：
 * 查表取色、把数字排进图里。任何「按今天日期算剩余天数」的写法都会
 * 在本地时区与服务端时区不一致时，让首页与整改列表页给出不同的答案。
 */
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'

import { RISK_LEVEL_LABELS, RISK_LEVEL_ORDER, listAssessments } from '@/api/assessments'
import {
  REMEDIATION_STATUS_COLORS,
  REMEDIATION_STATUS_LABELS,
  REMEDIATION_STATUS_ORDER,
  REMEDIATION_STATUS_TAG_TYPE,
  remediationTimingTagType,
  remediationTimingText,
} from '@/api/remediations'
import { SEVERITY_COLORS, SEVERITY_LABELS, getDashboardSummary } from '@/api/dashboard'
import type {
  Assessment,
  DashboardSummary,
  DashboardTopAsset,
  Remediation,
  RiskLevel,
} from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'
import DonutChart from './components/DonutChart.vue'
import HBarChart from './components/HBarChart.vue'

const router = useRouter()
const auth = useAuthStore()

/** 列出评估任务要 assessment:read，而仪表盘对三个读权限任一即可访问 */
const canReadAssessments = computed(() => auth.can('assessment:read'))
const canReadRemediations = computed(() => auth.can('remediation:read'))

const loading = ref(false)
const summary = ref<DashboardSummary | null>(null)

/**
 * 口径选择。
 *
 * `undefined` = 不传 `assessment_id`，由后端取「最近一次**已计算**的评估」
 * （按 `calculated_at` 排序，不是按 id——手工补算过的老任务 id 更大，
 * 但它不是最新结论）。这一点前端不自己挑，否则就多了一条会分叉的口径规则。
 */
const selectedAssessmentId = ref<number | undefined>(undefined)
const assessments = ref<Assessment[]>([])
const assessmentsLoading = ref(false)

async function loadSummary() {
  loading.value = true
  try {
    summary.value = await getDashboardSummary(selectedAssessmentId.value)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载总览失败')
    summary.value = null
  } finally {
    loading.value = false
  }
}

async function loadAssessments() {
  if (!canReadAssessments.value) return
  assessmentsLoading.value = true
  try {
    const page = await listAssessments({ page: 1, pageSize: 100 })
    assessments.value = page.items
  } catch {
    // 拉不到候选不阻断总览：默认的「最近一次已计算评估」本来就是最常用的口径
    assessments.value = []
  } finally {
    assessmentsLoading.value = false
  }
}

function handleAssessmentChange() {
  void loadSummary()
}

function handleRefresh() {
  void loadSummary()
  void loadAssessments()
}

onMounted(() => {
  void loadSummary()
  void loadAssessments()
})

// ------------------------------------------------------------------ 图表数据
//
// 全部是**查表 + 变换形状**，没有一处数值比较。

/** 口径评估：可能是 null（库里一次都没算过，合法空场景） */
const latest = computed(() => summary.value?.assessments.latest ?? null)

const levelItems = computed(() => {
  const counts = latest.value?.level_counts
  return RISK_LEVEL_ORDER.map((level) => ({
    label: RISK_LEVEL_LABELS[level],
    value: counts?.[level] ?? 0,
    color: levelColor(level),
  }))
})

/** 风险等级底色。与结果页矩阵同一套色板，避免同一等级在两个页面颜色不同 */
function levelColor(level: (typeof RISK_LEVEL_ORDER)[number]): string {
  const palette: Record<string, string> = {
    very_high: '#c45656',
    high: '#e6a23c',
    medium: '#d9b64a',
    low: '#79bbff',
    very_low: '#dcdcdc',
  }
  return palette[level] ?? '#79bbff'
}

/** 资产类型分布：字典里查不到的码退化为显示原始码，而不是留空 */
const assetTypeItems = computed(
  () =>
    summary.value?.assets.by_type.map((item) => ({
      label: item.name || item.code,
      value: item.count,
    })) ?? [],
)

const severityItems = computed(
  () =>
    summary.value?.vulnerabilities.by_severity.map((item) => ({
      label: SEVERITY_LABELS[item.severity] ?? `${item.severity} 档`,
      value: item.count,
      color: SEVERITY_COLORS[item.severity],
    })) ?? [],
)

/** 整改状态分布：按流程顺序，而不是「数量多的排前面」——
 *  状态是有序的，把它按数量重排会让读者看不出这是一条流水线。 */
const statusItems = computed(() => {
  const byStatus = summary.value?.remediations.by_status ?? {}
  return REMEDIATION_STATUS_ORDER.map((status) => ({
    label: REMEDIATION_STATUS_LABELS[status],
    value: byStatus[status] ?? 0,
    color: REMEDIATION_STATUS_COLORS[status],
  }))
})

// ------------------------------------------------------------------ 行为

/**
 * 表格插槽的类型收敛。
 *
 * el-table 把插槽里的 row 放宽成带索引签名的 `DefaultRow`，而带索引签名的
 * 对象**不能**赋给具名 interface（隐式索引签名只给匿名类型）。与其它页面
 * 一样在这里收敛一次，而不是在模板里写断言——模板里的断言写错了不会有提示。
 */
function asTopAsset(row: TableRow): DashboardTopAsset {
  return asRow<DashboardTopAsset>(row)
}

function asRecentRemediation(row: TableRow): Remediation {
  return asRow<Remediation>(row)
}

function openRemediation(id: number) {
  void router.push({ name: 'remediation-detail', params: { id: String(id) } })
}

function openRemediations() {
  void router.push({ name: 'remediations-list' })
}

function openAssessmentResult() {
  if (!latest.value) return
  void router.push({ name: 'assessment-result', params: { id: String(latest.value.id) } })
}

/** 风险区块是否「尚未计算」（草稿，或库里一次都没算过） */
const riskPending = computed(() => {
  if (!summary.value) return false
  if (!latest.value) return true
  return latest.value.status !== 'calculated'
})
</script>

<template>
  <div v-loading="loading" class="app-page">
    <!-- ── 头部 ─────────────────────────────────────────────────── -->
    <div class="mb-5 flex flex-wrap items-center gap-3">
      <div>
        <h1 class="text-xl font-semibold">总览</h1>
        <p class="mt-1 text-sm text-gray-500">
          <template v-if="summary">
            数据生成于 {{ formatDateTime(summary.generated_at) }}
          </template>
          <template v-else>加载中…</template>
        </p>
      </div>

      <div class="ml-auto flex flex-wrap items-center gap-2">
        <!-- 口径切换：只有能列评估任务的人才有这个下拉 -->
        <el-select
          v-if="canReadAssessments"
          v-model="selectedAssessmentId"
          clearable
          filterable
          :loading="assessmentsLoading"
          placeholder="风险数字口径：最近一次已计算评估"
          class="!w-80"
          @change="handleAssessmentChange"
        >
          <el-option
            v-for="item in assessments"
            :key="item.id"
            :label="`${item.name}（${item.status === 'calculated' ? '已计算' : '草稿'}）`"
            :value="item.id"
          />
        </el-select>
        <el-button :icon="Refresh" :loading="loading" @click="handleRefresh">刷新</el-button>
      </div>
    </div>

    <template v-if="summary">
      <!-- ── 关键数字 ─────────────────────────────────────────────── -->
      <div class="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div class="app-panel">
          <div class="text-xs text-gray-500">资产总数</div>
          <div class="mt-1 text-2xl font-semibold">{{ summary.assets.total }}</div>
          <div class="mt-1 text-xs text-gray-400">含已报废 {{ summary.assets.scrapped }} 台</div>
        </div>

        <div class="app-panel">
          <div class="text-xs text-gray-500">漏洞总数</div>
          <div class="mt-1 text-2xl font-semibold">{{ summary.vulnerabilities.total }}</div>
          <div class="mt-1 text-xs text-gray-400">不随评估口径变化</div>
        </div>

        <div class="app-panel">
          <div class="text-xs text-gray-500">评估任务</div>
          <div class="mt-1 text-2xl font-semibold">{{ summary.assessments.total }}</div>
          <div class="mt-1 text-xs text-gray-400">
            已计算 {{ summary.assessments.calculated }} · 草稿
            {{ summary.assessments.draft }}
          </div>
        </div>

        <div class="app-panel">
          <div class="text-xs text-gray-500">整改单</div>
          <div class="mt-1 text-2xl font-semibold">{{ summary.remediations.total }}</div>
          <div class="mt-1 text-xs text-gray-400">未闭环 {{ summary.remediations.active }}</div>
        </div>
      </div>

      <!-- ── 整改提醒 ─────────────────────────────────────────────── -->
      <div class="app-panel mb-4">
        <div class="mb-3 flex flex-wrap items-center gap-3">
          <h2 class="text-base font-semibold">整改提醒</h2>
          <span class="text-xs text-gray-400">
            逾期与即将到期的区间不重叠：今天到期的算「即将到期」，不算逾期
          </span>
          <el-button
            v-if="canReadRemediations"
            class="ml-auto"
            size="small"
            link
            type="primary"
            @click="openRemediations"
          >
            打开整改清单
          </el-button>
        </div>

        <div class="grid gap-3 sm:grid-cols-3">
          <button
            type="button"
            class="rounded-md border border-red-200 bg-red-50 p-3 text-left transition hover:border-red-300"
            @click="openRemediations"
          >
            <div class="text-xs text-red-600">已逾期</div>
            <div class="mt-1 text-2xl font-semibold text-red-700">
              {{ summary.remediations.overdue }}
            </div>
            <div class="mt-1 text-xs text-red-500">期限已过且未闭环</div>
          </button>

          <button
            type="button"
            class="rounded-md border border-amber-200 bg-amber-50 p-3 text-left transition hover:border-amber-300"
            @click="openRemediations"
          >
            <div class="text-xs text-amber-600">
              即将到期（{{ summary.remediations.due_within_days }} 天内）
            </div>
            <div class="mt-1 text-2xl font-semibold text-amber-700">
              {{ summary.remediations.due_soon }}
            </div>
            <div class="mt-1 text-xs text-amber-500">含今天到期，不含已逾期</div>
          </button>

          <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
            <div class="text-xs text-gray-500">未闭环合计</div>
            <div class="mt-1 text-2xl font-semibold">{{ summary.remediations.active }}</div>
            <div class="mt-1 text-xs text-gray-400">待处理 / 处理中 / 待复核</div>
          </div>
        </div>
      </div>

      <!-- ── 风险区块（绑定口径）───────────────────────────────────── -->
      <div class="mb-4 grid gap-4 xl:grid-cols-3">
        <div class="app-panel xl:col-span-2">
          <div class="mb-1 flex flex-wrap items-center gap-2">
            <h2 class="text-base font-semibold">风险等级分布</h2>
            <!-- ⚠️ 口径必须显示，且必须显眼：不注明口径的汇总数字没有意义 -->
            <template v-if="latest">
              <el-tag size="small" type="info" effect="plain">
                口径：{{ latest.name }}（#{{ latest.id }}）
              </el-tag>
              <el-button link type="primary" size="small" @click="openAssessmentResult">
                查看结果
              </el-button>
            </template>
            <el-tag v-else size="small" type="warning" effect="plain">尚未计算过任何评估</el-tag>
          </div>
          <div class="mb-3 text-xs text-gray-500">
            <template v-if="latest?.calculated_at">
              该评估计算于 {{ formatDateTime(latest.calculated_at) }} · 覆盖
              {{ latest.assets_count }} 台资产、{{ latest.risk_items_count }} 条风险项
              <span v-if="latest.max_risk !== null">
                · 最高 R = {{ latest.max_risk.toFixed(1) }}
              </span>
            </template>
            <template v-else-if="latest">
              这份评估还是草稿，没有落库结果。切换到已计算的评估，或先执行一次计算。
            </template>
            <template v-else>
              系统里还没有任何已计算的评估。资产与漏洞的数字照常可用，
              风险相关的数字要等第一次计算之后才有。
            </template>
          </div>

          <HBarChart v-if="!riskPending" :items="levelItems" empty-text="这次评估没有任何风险项" />
          <el-empty v-else description="尚未计算" :image-size="60" />
        </div>

        <div class="app-panel">
          <h2 class="mb-3 text-base font-semibold">整改状态分布</h2>
          <DonutChart :items="statusItems" center-label="整改单总数" />
        </div>
      </div>

      <!-- ── 高风险资产 ───────────────────────────────────────────── -->
      <div v-if="latest && latest.top_assets.length" class="app-panel mb-4">
        <div class="mb-3 flex items-center gap-2">
          <h2 class="text-base font-semibold">风险最高的资产</h2>
          <span class="text-xs text-gray-400">
            取每台资产下**最严重**的一条风险项的 R，不是平均值
          </span>
        </div>

        <el-table :data="latest.top_assets" size="small" style="width: 100%">
          <el-table-column label="资产" min-width="160" show-overflow-tooltip>
            <template #default="{ row }">
              {{ asTopAsset(row).asset_name }}
              <span v-if="asTopAsset(row).asset_ip" class="text-xs text-gray-400">
                （{{ asTopAsset(row).asset_ip }}）
              </span>
            </template>
          </el-table-column>
          <el-table-column label="R" width="90" align="right">
            <template #default="{ row }">
              <span class="font-semibold">{{ asTopAsset(row).risk_value.toFixed(1) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="等级" width="90">
            <template #default="{ row }">
              <el-tag
                size="small"
                :style="{
                  backgroundColor: levelColor(asTopAsset(row).risk_level as RiskLevel),
                  border: 'none',
                }"
              >
                {{ RISK_LEVEL_LABELS[asTopAsset(row).risk_level as RiskLevel] }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="risk_items_count" label="风险项" width="90" align="center" />
        </el-table>
      </div>

      <!-- ── 两个分布 ─────────────────────────────────────────────── -->
      <div class="mb-4 grid gap-4 lg:grid-cols-2">
        <div class="app-panel">
          <h2 class="mb-3 text-base font-semibold">资产类型分布</h2>
          <HBarChart :items="assetTypeItems" empty-text="还没有资产" :label-width="96" />
        </div>

        <div class="app-panel">
          <h2 class="mb-3 text-base font-semibold">漏洞严重程度分布</h2>
          <div class="mb-2 text-xs text-gray-500">
            漏斗里的严重程度（1–5 档），与风险等级（R 算出来的五档）是两套刻度
          </div>
          <HBarChart :items="severityItems" empty-text="还没有漏洞" />
        </div>
      </div>

      <!-- ── 最近整改动态 ─────────────────────────────────────────── -->
      <div class="app-panel">
        <div class="mb-3 flex items-center gap-2">
          <h2 class="text-base font-semibold">最近整改动态</h2>
          <span class="text-xs text-gray-400">按更新时间倒序，最多 5 条</span>
        </div>

        <el-table
          v-if="summary.recent_remediations.length"
          :data="summary.recent_remediations"
          size="small"
          style="width: 100%"
        >
          <el-table-column label="整改单" min-width="220" show-overflow-tooltip>
            <template #default="{ row }">
              <el-button link type="primary" @click="openRemediation(asRecentRemediation(row).id)">
                {{ asRecentRemediation(row).title }}
              </el-button>
              <div class="text-xs text-gray-400">
                {{ asRecentRemediation(row).asset_name }}
                <span v-if="asRecentRemediation(row).asset_ip">
                  · {{ asRecentRemediation(row).asset_ip }}
                </span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag
                :type="REMEDIATION_STATUS_TAG_TYPE[asRecentRemediation(row).status]"
                size="small"
              >
                {{ REMEDIATION_STATUS_LABELS[asRecentRemediation(row).status] }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="时间态" width="120">
            <template #default="{ row }">
              <el-tag
                :type="remediationTimingTagType(asRecentRemediation(row))"
                size="small"
                effect="plain"
              >
                {{ remediationTimingText(asRecentRemediation(row)) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="最近更新" width="170">
            <template #default="{ row }">
              {{ formatDateTime(asRecentRemediation(row).updated_at) }}
            </template>
          </el-table-column>
        </el-table>

        <el-empty v-else description="还没有整改单" :image-size="60" />
      </div>
    </template>

    <el-empty v-else-if="!loading" description="加载总览数据失败" />
  </div>
</template>
