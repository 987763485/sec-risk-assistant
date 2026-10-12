<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, ArrowLeft, Download, Refresh } from '@element-plus/icons-vue'

import {
  RISK_LEVEL_COLORS,
  RISK_LEVEL_LABELS,
  RISK_LEVEL_TEXT_COLORS,
  THREAT_SOURCE_LABELS,
  exportAssessmentData,
  getAssessment,
  getAssessmentMatrix,
  levelCountEntries,
  listRiskItems,
  setRiskItemThreat,
} from '@/api/assessments'
import { listDictionaries } from '@/api/dictionaries'
import { REPORT_FORMAT_OPTIONS, exportReport } from '@/api/reports'
import {
  NO_REMEDIATION_TEXT,
  REMEDIATION_STATUS_LABELS,
  REMEDIATION_STATUS_TAG_TYPE,
  loadActiveRemediationMap,
  remediationTargetKey,
} from '@/api/remediations'
import type {
  Assessment,
  Dictionary,
  Remediation,
  ReportFormat,
  RiskItem,
  RiskLevel,
  RiskMatrix,
} from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { saveBlob } from '@/utils/download'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'
import BatchCreateDialog from '../remediations/components/BatchCreateDialog.vue'
import CreateRemediationDialog from '../remediations/components/CreateRemediationDialog.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const canWrite = computed(() => auth.can('assessment:write'))
/** 建整改单按 remediation:write 显隐——它可能和评估的写权限不是同一批人 */
const canWriteRemediation = computed(() => auth.can('remediation:write'))
const assessmentId = computed(() => Number(route.params.id))

const loading = ref(true)
const assessment = ref<Assessment | null>(null)
const matrix = ref<RiskMatrix | null>(null)
const threats = ref<Dictionary[]>([])

// ------------------------------------------------------------------ 矩阵
//
// 横轴是资产重要性、纵轴是漏洞严重程度——两个**原始档位**。
// 用原始档位而不是 A / T / V：档位不受权重配置影响，改一次权重系数
// 不会让矩阵里的格子整体位移，结构稳定，只有颜色变。
//
// 后端返回的 level 已经判好了，这里只做「查色板」，**没有任何比较运算**。

const selected = reactive<{ importance: number | null; severity: number | null }>({
  importance: null,
  severity: null,
})

/** 纵轴从上到下 5 → 1：严重程度高的排在视觉上方，符合「先看最糟的」直觉 */
const SEVERITY_AXIS = [5, 4, 3, 2, 1]
const IMPORTANCE_AXIS = [1, 2, 3, 4, 5]

function cellOf(importance: number, severity: number) {
  return matrix.value?.cells.find((c) => c.importance === importance && c.severity === severity)
}

function toggleCell(importance: number, severity: number) {
  if (selected.importance === importance && selected.severity === severity) {
    selected.importance = null
    selected.severity = null
  } else {
    selected.importance = importance
    selected.severity = severity
  }
  page.page = 1
  void loadItems()
}

function isSelected(importance: number, severity: number): boolean {
  return selected.importance === importance && selected.severity === severity
}

// ------------------------------------------------------------------ 风险项

const items = ref<RiskItem[]>([])
const total = ref(0)
const itemsLoading = ref(false)

const page = reactive({ page: 1, pageSize: 20 })

async function loadItems() {
  itemsLoading.value = true
  try {
    const res = await listRiskItems(assessmentId.value, {
      page: page.page,
      pageSize: page.pageSize,
      importance: selected.importance ?? undefined,
      severity: selected.severity ?? undefined,
    })
    items.value = res.items
    total.value = res.total
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载风险项失败')
    items.value = []
    total.value = 0
  } finally {
    itemsLoading.value = false
  }
}

// ------------------------------------------------------------------ 初始化

/**
 * 未闭环整改单索引，键是 `assetId:vulnId`。
 *
 * ▍为什么在前端建这个索引而不是加一个接口
 *
 * 风险项逐页返回、整改单是另一个接口，两者没有共享的连接键（整改单的真
 * 实身份是「资产 + 漏洞」，不是风险项 ID——后者在评估重算后整批失效）。
 * 加一个「按目标批量查整改状态」的接口当然更省，但那意味着多一份需要双向
 * 维护的契约；而未闭环单的规模天然有限（它就是工作清单本身），一次翻页
 * 取回的代价可控。
 *
 * ⚠️ 取的是**未闭环**单：漏洞复发会新建一张单（终态不可逆），
 * 上一张「已闭环」对当前这条风险项没有意义。取不到时这一列显示「未建单」，
 * 这也是**准确**的——因为那张单子确实不能再被复用。
 */
const remediationMap = ref<Map<string, Remediation>>(new Map())
/** 整改单太多、只加载了一部分时为 true，界面上会明说状态列可能不完整 */
const remediationTruncated = ref(false)

async function loadRemediations() {
  try {
    const { map, truncated } = await loadActiveRemediationMap()
    remediationMap.value = map
    remediationTruncated.value = truncated
  } catch {
    // 拉不到整改单不影响评估结果本身的阅读，静默降级为「未建单」
    remediationMap.value = new Map()
    remediationTruncated.value = false
  }
}

function remediationOf(item: RiskItem): Remediation | undefined {
  return remediationMap.value.get(remediationTargetKey(item.asset_id, item.vuln_id))
}

async function loadAll() {
  loading.value = true
  try {
    const [detail, grid, threatList] = await Promise.all([
      getAssessment(assessmentId.value),
      getAssessmentMatrix(assessmentId.value),
      listDictionaries('threat', true),
    ])
    assessment.value = detail
    matrix.value = grid
    threats.value = threatList
    await Promise.all([loadItems(), loadRemediations()])
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载评估结果失败')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadAll()
})

// ------------------------------------------------------------ 逐项覆盖威胁

const threatDialogVisible = ref(false)
const editingItem = ref<RiskItem | null>(null)
const editingThreatCode = ref('')
const savingThreat = ref(false)

function openThreatDialog(item: RiskItem) {
  editingItem.value = item
  editingThreatCode.value = item.threat_code ?? ''
  threatDialogVisible.value = true
}

async function saveThreat() {
  const item = editingItem.value
  if (!item) return
  savingThreat.value = true
  try {
    const updated = await setRiskItemThreat(assessmentId.value, item.id, {
      threat_code: editingThreatCode.value,
    })
    // 就地替换这一行：一条风险项的威胁变了，它的 R、等级，乃至整个评估的
    // 汇总都会变，所以顺便把矩阵与任务详情一起刷新，避免页面上同时出现
    // 「新的一行」和「旧的汇总」。
    const idx = items.value.findIndex((it) => it.id === updated.id)
    if (idx >= 0) items.value[idx] = updated
    threatDialogVisible.value = false
    ElMessage.success(
      `已更新：R = ${updated.risk_value_r.toFixed(1)}，等级「${RISK_LEVEL_LABELS[updated.risk_level as RiskLevel]}」`,
    )
    await refreshSummary()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '更新失败')
  } finally {
    savingThreat.value = false
  }
}

async function refreshSummary() {
  try {
    const [detail, grid] = await Promise.all([
      getAssessment(assessmentId.value),
      getAssessmentMatrix(assessmentId.value),
    ])
    assessment.value = detail
    matrix.value = grid
  } catch {
    // 汇总刷新失败不影响已经成功的写操作，静默即可——
    // 再弹一次错误只会让用户以为刚才那一步没成功。
  }
}

// ------------------------------------------------------------------ 导出

const exporting = ref(false)

/**
 * 下拉选项的回调。
 *
 * 参数类型收敛成 `unknown` 而不是 `ReportFormat`：`el-dropdown` 的
 * `command` 声明是 `string | number | object`，直接标成联合类型等于
 * 让模板里的一次手误（比如把 command 写成中文标签）静默通过。
 */
async function handleExportCommand(command: unknown) {
  if (command === 'json') {
    await handleExportData()
    return
  }
  await handleExportReport(command as ReportFormat)
}

/**
 * 导出报告文件（Word / Excel / PDF）。
 *
 * 文件名由服务端在 `Content-Disposition` 里给出（含任务名与导出时间），
 * 这里不拼名字——见 `@/api/reports` 里对兜底命名的说明。
 */
async function handleExportReport(format: ReportFormat) {
  const current = assessment.value
  if (!current) return

  exporting.value = true
  try {
    const file = await exportReport(current.id, format, current.name)
    saveBlob(file.blob, file.fileName)
    const label = REPORT_FORMAT_OPTIONS.find((o) => o.value === format)?.label ?? format
    ElMessage.success(`已导出 ${label}`)
  } catch (err) {
    // 后端的 message 在这里是有用的：409 会说「任务尚未计算」、
    // 503 会说「渲染服务暂不可用」——比一句笼统的「导出失败」更能让用户
    // 知道该去做什么。因此优先用 err.message。
    ElMessage.error(err instanceof HttpError ? err.message : '导出失败')
  } finally {
    exporting.value = false
  }
}

/**
 * 导出报告数据（JSON）。
 *
 * 导出的不是文档，而是**报告渲染器消费的那份数据**：它与页面上的数字、
 * 库里的记录三者同源（服务端只有一条计算路径）。用途是核对与留档——
 * 报告里的每一个数字都能在这份 JSON 里找到出处。
 */
async function handleExportData() {
  if (!assessment.value) return
  exporting.value = true
  try {
    const data = await exportAssessmentData(assessmentId.value)
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    saveBlob(blob, `评估报告数据-${assessment.value.name}.json`)
    ElMessage.success('已导出报告数据')
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '导出失败')
  } finally {
    exporting.value = false
  }
}

// ------------------------------------------------------------ 整改单入口

const createRemediationVisible = ref(false)
const creatingItem = ref<RiskItem | null>(null)

function openCreateRemediation(item: RiskItem) {
  creatingItem.value = item
  createRemediationVisible.value = true
}

/** 建单成功后只刷新整改状态列：风险项本身没有变化，不必重算整页 */
async function handleRemediationCreated() {
  await loadRemediations()
}

const batchCreateVisible = ref(false)

async function handleBatchCreated() {
  await loadRemediations()
}

function openRemediationDetail(row: Remediation) {
  void router.push({ name: 'remediation-detail', params: { id: String(row.id) } })
}

// ------------------------------------------------------------------ 展示

const levelEntries = computed(() => levelCountEntries(assessment.value?.level_counts))

function asRiskItem(row: TableRow): RiskItem {
  return asRow<RiskItem>(row)
}

async function handleBack() {
  await router.push({ name: 'assessments-list' })
}

/** 下钻范围提示文案 */
const drillHint = computed(() => {
  if (selected.importance === null || selected.severity === null) {
    return '全部风险项（点击矩阵中的格子可下钻）'
  }
  return `下钻：资产重要度 ${selected.importance} × 漏洞严重程度 ${selected.severity}`
})

/** 覆盖对话框里提示本条当前的分解式 */
const currentBreakdown = computed(() => {
  const item = editingItem.value
  if (!item) return ''
  return `A=${item.asset_value_a.toFixed(3)} × T=${item.threat_weight_t.toFixed(3)} × V=${item.vuln_weight_v.toFixed(3)} = R ${item.risk_value_r.toFixed(3)}`
})

/** 覆盖会影响整份评估，先让用户确认——它不是「看一眼」级别的小操作 */
async function confirmAndSave() {
  const item = editingItem.value
  if (!item) return
  try {
    await ElMessageBox.confirm(
      '这条风险项的威胁被逐项指定后，它的风险值、所在资产的风险等级，' +
        '以及整份评估的汇总都会立即重算。确认继续吗？',
      '确认覆盖威胁',
      { type: 'warning', confirmButtonText: '确认覆盖', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  await saveThreat()
}
</script>

<template>
  <div v-loading="loading" class="p-4">
    <!-- ── 头部与汇总 ─────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-center gap-3">
        <el-button :icon="ArrowLeft" text @click="handleBack">返回列表</el-button>
        <span class="text-lg font-semibold">{{ assessment?.name ?? '—' }}</span>
        <span class="text-xs text-gray-500">
          最近计算：{{ formatDateTime(assessment?.calculated_at) }}
        </span>
        <div class="ml-auto flex items-center gap-2">
          <!--
            批量建单以「本评估」为预设：结果页是发起整改最自然的入口，
            用户刚看完哪几条风险高。真正的等级筛选在对话框里改。
          -->
          <el-button v-if="canWriteRemediation" @click="batchCreateVisible = true">
            批量建整改单
          </el-button>
          <el-button :icon="Refresh" @click="loadAll">刷新</el-button>
          <!--
            只有已计算的任务能导出：未计算时后端返回 409
            REPORT_NOT_CALCULATED。这里按 status 判而不是按 risk_items_count，
            因为后者是「算出来有几条」，不是「有没有算过」——一份范围内
            零风险项的评估同样可以出一份报告。
          -->
          <el-dropdown v-if="assessment?.status === 'calculated'" @command="handleExportCommand">
            <el-button type="primary" :icon="Download" :loading="exporting">
              导出报告
              <el-icon class="ml-1"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item
                  v-for="opt in REPORT_FORMAT_OPTIONS"
                  :key="opt.value"
                  :command="opt.value"
                >
                  导出 {{ opt.label }}（.{{ opt.ext }}）
                </el-dropdown-item>
                <el-dropdown-item divided command="json">导出报告数据（.json）</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>

      <div class="mt-4 grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
          <div class="text-xs text-gray-500">资产数</div>
          <div class="mt-1 text-xl font-semibold">{{ assessment?.assets_count ?? 0 }}</div>
        </div>
        <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
          <div class="text-xs text-gray-500">风险项</div>
          <div class="mt-1 text-xl font-semibold">{{ assessment?.risk_items_count ?? 0 }}</div>
        </div>
        <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
          <div class="text-xs text-gray-500">最高风险值</div>
          <div class="mt-1 text-xl font-semibold">
            {{
              assessment?.max_risk === null || assessment?.max_risk === undefined
                ? '—'
                : assessment.max_risk.toFixed(1)
            }}
          </div>
        </div>
        <div
          v-for="entry in levelEntries"
          :key="entry.level"
          class="rounded-md border border-gray-200 p-3"
        >
          <div class="flex items-center gap-1 text-xs text-gray-500">
            <i
              class="inline-block h-2.5 w-2.5 rounded-sm"
              :style="{ backgroundColor: RISK_LEVEL_COLORS[entry.level] }"
            ></i>
            {{ entry.label }}
          </div>
          <div class="mt-1 text-xl font-semibold">{{ entry.count }}</div>
        </div>
      </div>

      <div v-if="assessment?.config_snapshot" class="mt-3 text-xs text-gray-500">
        本次计算使用的阈值： 很高 ≥ {{ assessment.config_snapshot.thresholds.very_high }}、 高 ≥
        {{ assessment.config_snapshot.thresholds.high }}、 中 ≥
        {{ assessment.config_snapshot.thresholds.medium }}、 低 ≥
        {{ assessment.config_snapshot.thresholds.low }}； 权重系数
        {{ assessment.config_snapshot.asset_weight }}。
        <span class="text-gray-400">（改系统设置不会影响这份已计算的评估）</span>
      </div>
    </div>

    <div class="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <!-- ── 矩阵 ──────────────────────────────────────────────── -->
      <div class="app-panel">
        <div class="mb-1 text-sm font-semibold">风险矩阵</div>
        <div class="mb-3 text-xs text-gray-500">
          横轴：资产重要度 · 纵轴：漏洞严重程度 · 格内：风险项数
        </div>

        <div class="inline-flex flex-col gap-1">
          <!-- 表头行 -->
          <div class="flex gap-1">
            <div class="w-14 shrink-0"></div>
            <div
              v-for="a in IMPORTANCE_AXIS"
              :key="`h-${a}`"
              class="flex h-7 w-16 items-center justify-center text-xs text-gray-500"
            >
              A{{ a }}
            </div>
          </div>

          <div v-for="v in SEVERITY_AXIS" :key="`r-${v}`" class="flex gap-1">
            <div class="flex h-14 w-14 shrink-0 items-center justify-center text-xs text-gray-500">
              V{{ v }}
            </div>
            <button
              v-for="a in IMPORTANCE_AXIS"
              :key="`c-${a}-${v}`"
              type="button"
              class="flex h-14 w-16 flex-col items-center justify-center rounded transition"
              :class="isSelected(a, v) ? 'ring-2 ring-blue-500 ring-offset-1' : ''"
              :style="{
                backgroundColor: cellOf(a, v)?.count
                  ? RISK_LEVEL_COLORS[(cellOf(a, v)?.level ?? 'very_low') as RiskLevel]
                  : '#f5f5f5',
                color: cellOf(a, v)?.count
                  ? RISK_LEVEL_TEXT_COLORS[(cellOf(a, v)?.level ?? 'very_low') as RiskLevel]
                  : '#999999',
              }"
              @click="toggleCell(a, v)"
            >
              <span class="text-sm font-semibold">{{ cellOf(a, v)?.count ?? 0 }}</span>
              <span v-if="cellOf(a, v)?.count" class="text-xs opacity-80">
                {{ (cellOf(a, v)?.max_risk ?? 0).toFixed(0) }}
              </span>
            </button>
          </div>
        </div>

        <div class="mt-3 flex flex-wrap gap-3">
          <span
            v-for="entry in levelEntries"
            :key="entry.level"
            class="flex items-center gap-1 text-xs"
          >
            <i
              class="inline-block h-2.5 w-2.5 rounded-sm"
              :style="{ backgroundColor: RISK_LEVEL_COLORS[entry.level] }"
            ></i>
            {{ entry.label }}
          </span>
        </div>

        <div class="mt-2 text-xs text-gray-400">
          底色 = 该格内最大 R 的等级，角标 = 最大 R 的数值。
        </div>
      </div>

      <!-- ── 下钻列表 ───────────────────────────────────────────── -->
      <div class="xl:col-span-2">
        <div class="app-panel">
          <div class="mb-3 flex flex-wrap items-center gap-2">
            <span class="text-sm font-semibold">{{ drillHint }}</span>
            <span class="text-xs text-gray-500">共 {{ total }} 条</span>
            <el-button
              v-if="selected.importance !== null"
              class="ml-auto"
              size="small"
              text
              @click="toggleCell(selected.importance, selected.severity ?? 0)"
            >
              清除下钻
            </el-button>
          </div>

          <el-alert
            v-if="remediationTruncated"
            class="mb-3"
            type="warning"
            :closable="false"
            show-icon
            title="未闭环整改单数量较多，只加载了一部分"
          >
            <template #default>
              「整改」列显示的是未闭环整改单的**当前状态**。因为单子太多，
              这一列可能把已有单子的条目显示成「未建单」——点「建单」时若提示
              已存在，请到整改跟踪页处理那张单子。
            </template>
          </el-alert>

          <el-table v-loading="itemsLoading" :data="items" size="small" style="width: 100%">
            <el-table-column label="资产" min-width="140" show-overflow-tooltip>
              <template #default="{ row }">
                {{ asRiskItem(row).asset_name }}
                <span v-if="asRiskItem(row).asset_ip" class="text-xs text-gray-400">
                  （{{ asRiskItem(row).asset_ip }}）
                </span>
              </template>
            </el-table-column>

            <el-table-column label="漏洞" min-width="200" show-overflow-tooltip>
              <template #default="{ row }">
                <div>{{ asRiskItem(row).vuln_title }}</div>
                <div v-if="asRiskItem(row).vuln_cve_ids" class="text-xs text-gray-400">
                  {{ asRiskItem(row).vuln_cve_ids }}
                </div>
              </template>
            </el-table-column>

            <el-table-column label="威胁" min-width="140" show-overflow-tooltip>
              <template #default="{ row }">
                <span v-if="asRiskItem(row).threat_name">{{ asRiskItem(row).threat_name }}</span>
                <span v-else class="text-gray-400">未指定</span>
                <el-tag
                  v-if="asRiskItem(row).threat_source === 'manual'"
                  size="small"
                  type="warning"
                  class="ml-1"
                >
                  {{ THREAT_SOURCE_LABELS.manual }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column label="A × T × V" width="150" align="center">
              <template #default="{ row }">
                <span class="text-xs text-gray-500">
                  {{ asRiskItem(row).asset_value_a.toFixed(1) }} ×
                  {{ asRiskItem(row).threat_weight_t.toFixed(1) }} ×
                  {{ asRiskItem(row).vuln_weight_v.toFixed(1) }}
                </span>
              </template>
            </el-table-column>

            <el-table-column label="R" width="80" align="right">
              <template #default="{ row }">
                <span class="font-semibold">{{ asRiskItem(row).risk_value_r.toFixed(1) }}</span>
              </template>
            </el-table-column>

            <el-table-column label="等级" width="90">
              <template #default="{ row }">
                <el-tag
                  size="small"
                  effect="dark"
                  :style="{
                    backgroundColor: RISK_LEVEL_COLORS[asRiskItem(row).risk_level as RiskLevel],
                    color: RISK_LEVEL_TEXT_COLORS[asRiskItem(row).risk_level as RiskLevel],
                    border: 'none',
                  }"
                >
                  {{ RISK_LEVEL_LABELS[asRiskItem(row).risk_level as RiskLevel] }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column label="整改" width="140" fixed="right">
              <template #default="{ row }">
                <!--
                  这一列是**只读**的状态显示 + 一个建单入口。
                  状态来自后端（未闭环单的当前状态），前端不推断任何东西：
                  「能不能建单」由后端按 (资产, 漏洞) 的唯一约束判定，
                  前端只负责把 409 的文案原样呈现出来。
                -->
                <template v-if="remediationOf(asRiskItem(row))">
                  <el-button
                    link
                    type="primary"
                    size="small"
                    @click="openRemediationDetail(remediationOf(asRiskItem(row)) as Remediation)"
                  >
                    <el-tag
                      :type="REMEDIATION_STATUS_TAG_TYPE[remediationOf(asRiskItem(row))!.status]"
                      size="small"
                    >
                      {{ REMEDIATION_STATUS_LABELS[remediationOf(asRiskItem(row))!.status] }}
                    </el-tag>
                  </el-button>
                </template>
                <template v-else>
                  <el-button
                    v-if="canWriteRemediation"
                    link
                    type="primary"
                    size="small"
                    @click="openCreateRemediation(asRiskItem(row))"
                  >
                    建单
                  </el-button>
                  <span v-else class="text-xs text-gray-400">{{ NO_REMEDIATION_TEXT }}</span>
                </template>
              </template>
            </el-table-column>

            <el-table-column label="操作" width="100" fixed="right">
              <template #default="{ row }">
                <el-button
                  v-if="canWrite"
                  link
                  type="primary"
                  size="small"
                  @click="openThreatDialog(asRiskItem(row))"
                >
                  指定威胁
                </el-button>
                <span v-else class="text-xs text-gray-400">只读</span>
              </template>
            </el-table-column>
            <template #empty>
              <div class="py-8 text-sm text-gray-400">该范围内没有风险项</div>
            </template>
          </el-table>

          <div class="mt-4 flex justify-end">
            <el-pagination
              v-model:current-page="page.page"
              v-model:page-size="page.pageSize"
              :total="total"
              :page-sizes="[10, 20, 50, 100]"
              layout="total, sizes, prev, pager, next"
              @current-change="loadItems"
              @size-change="loadItems"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- ── 覆盖威胁对话框 ─────────────────────────────────────────── -->
    <el-dialog v-model="threatDialogVisible" title="逐项指定威胁" width="520px" append-to-body>
      <template v-if="editingItem">
        <el-descriptions :column="1" size="small" border class="mb-3">
          <el-descriptions-item label="资产">
            {{ editingItem.asset_name }}
            <span v-if="editingItem.asset_ip" class="text-xs text-gray-400">
              （{{ editingItem.asset_ip }}）
            </span>
          </el-descriptions-item>
          <el-descriptions-item label="漏洞">{{ editingItem.vuln_title }}</el-descriptions-item>
          <el-descriptions-item label="当前计算">{{ currentBreakdown }}</el-descriptions-item>
        </el-descriptions>

        <el-select v-model="editingThreatCode" clearable filterable class="w-full">
          <el-option
            v-for="item in threats"
            :key="item.code"
            :label="`${item.name}（T=${item.weight}）`"
            :value="item.code"
          />
        </el-select>
        <div class="mt-2 text-xs text-gray-500">
          取值来自威胁字典，因此 T 就是字典里配置的权重——改字典权重会影响所有
          引用它的风险项。留空表示清除逐项覆盖，回落为任务级默认威胁。
        </div>
      </template>

      <template #footer>
        <el-button @click="threatDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="savingThreat" @click="confirmAndSave">
          覆盖并重算
        </el-button>
      </template>
    </el-dialog>

    <!-- ── 整改单入口 ─────────────────────────────────────────────── -->
    <CreateRemediationDialog
      v-model="createRemediationVisible"
      :item="creatingItem"
      @created="handleRemediationCreated"
    />
    <BatchCreateDialog
      v-model="batchCreateVisible"
      :preset-assessment-id="assessmentId"
      @done="handleBatchCreated"
    />
  </div>
</template>
