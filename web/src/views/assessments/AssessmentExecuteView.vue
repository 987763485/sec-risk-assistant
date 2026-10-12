<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowLeft, Edit, RefreshRight } from '@element-plus/icons-vue'

import {
  ASSESSMENT_STATUS_LABELS,
  ASSESSMENT_STATUS_TAG_TYPE,
  RISK_LEVEL_COLORS,
  RISK_LEVEL_LABELS,
  RISK_LEVEL_TEXT_COLORS,
  SCOPE_TYPE_LABELS,
  THREAT_SOURCE_LABELS,
  calculateAssessment,
  getAssessment,
  levelCountEntries,
  previewAssessment,
  updateAssessment,
} from '@/api/assessments'
import { listDictionaries } from '@/api/dictionaries'
import { getSystemConfigs } from '@/api/systemConfigs'
import type {
  Assessment,
  Dictionary,
  PreviewAssessmentResult,
  RiskLevel,
  SystemConfigView,
} from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const canWrite = computed(() => auth.can('assessment:write'))

const assessmentId = computed(() => Number(route.params.id))

const loading = ref(true)
const assessment = ref<Assessment | null>(null)
const config = ref<SystemConfigView | null>(null)
const threats = ref<Dictionary[]>([])

async function loadBasics() {
  loading.value = true
  try {
    const [detail, cfg, threatList] = await Promise.all([
      getAssessment(assessmentId.value),
      // 阈值读接口对 assessment:read 也放行，评估员能看到自己结果的计算依据
      getSystemConfigs(),
      listDictionaries('threat', true),
    ])
    assessment.value = detail
    config.value = cfg
    threats.value = threatList

    threatOverride.value = detail.default_threat_code ?? ''
    if (cfg) {
      tempConfig.assetWeight = cfg.asset_weight
      tempConfig.veryHigh = cfg.thresholds.very_high
      tempConfig.high = cfg.thresholds.high
      tempConfig.medium = cfg.thresholds.medium
      tempConfig.low = cfg.thresholds.low
    }
    await runPreview()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载评估任务失败')
  } finally {
    loading.value = false
  }
}

// ------------------------------------------------------------------ 试算
//
// 防抖 300ms 的原因：这一页右侧是「参数一动、结果跟着变」。
// 不防抖的话，用户在阈值输入框里敲「20」会触发两次请求（「2」和「20」），
// 而先发出的那次可能后返回，屏幕上最终显示的就是一个不存在的中间态。

const previewing = ref(false)
const preview = ref<PreviewAssessmentResult | null>(null)

let previewTimer: number | undefined

function schedulePreview() {
  if (previewTimer) window.clearTimeout(previewTimer)
  previewTimer = window.setTimeout(() => void runPreview(), 300)
}

onBeforeUnmount(() => {
  if (previewTimer) window.clearTimeout(previewTimer)
})

async function runPreview() {
  previewing.value = true
  try {
    preview.value = await previewAssessment({
      assessment_id: assessmentId.value,
      // 勾选「临时阈值」时才覆盖：不勾选就让后端用当前系统配置，
      // 这样页面上显示的数字与「什么都不改直接计算」完全一致。
      asset_weight: useTempConfig.value ? tempConfig.assetWeight : undefined,
      thresholds: useTempConfig.value
        ? {
            very_high: tempConfig.veryHigh,
            high: tempConfig.high,
            medium: tempConfig.medium,
            low: tempConfig.low,
          }
        : undefined,
    })
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '试算失败')
    preview.value = null
  } finally {
    previewing.value = false
  }
}

// ------------------------------------------------------------------ 参数

const threatOverride = ref('')
const savingThreat = ref(false)

/** 保存任务级默认威胁。保存后**不自动重算**，由用户显式点「计算」。 */
async function saveThreat() {
  if (!assessment.value) return
  savingThreat.value = true
  try {
    const saved = await updateAssessment(assessment.value.id, {
      default_threat_code: threatOverride.value,
    })
    assessment.value = saved
    ElMessage.success('默认威胁已保存')
    await runPreview()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    savingThreat.value = false
  }
}

const useTempConfig = ref(false)

const tempConfig = reactive({
  assetWeight: 1,
  veryHigh: 20,
  high: 12,
  medium: 6,
  low: 2,
})

/** 临时阈值的单调性检查。只做提示，不阻止提交——后端才是判定方。 */
const tempConfigHint = computed(() => {
  const { veryHigh, high, medium, low } = tempConfig
  if (!(veryHigh > high && high > medium && medium > low)) {
    return '四个阈值必须严格递减（很高 > 高 > 中 > 低），否则后端会拒绝这次试算'
  }
  if (low < 1) return '「低」的下界不能小于 1，否则「很低」这一档永远为空'
  return ''
})

// ------------------------------------------------------------------ 计算

const calculating = ref(false)

async function handleCalculate() {
  if (!assessment.value) return

  if (useTempConfig.value) {
    try {
      await ElMessageBox.confirm(
        '当前勾选了「临时阈值」——它只影响试算预览，不会写入系统设置。' +
          '计算将使用**系统设置里的当前阈值**，因此落库结果可能与你看到的预览不同。',
        '临时阈值不会参与计算',
        { type: 'warning', confirmButtonText: '继续计算', cancelButtonText: '取消' },
      )
    } catch {
      return
    }
  }

  calculating.value = true
  try {
    const saved = await calculateAssessment(assessment.value.id)
    assessment.value = saved
    ElMessage.success(`计算完成：${saved.assets_count} 个资产、${saved.risk_items_count} 条风险项`)
    await router.push({ name: 'assessment-result', params: { id: String(saved.id) } })
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '计算失败')
  } finally {
    calculating.value = false
  }
}

// ------------------------------------------------------------------ 展示

const levelEntries = computed(() => levelCountEntries(preview.value?.level_counts))

/** 阈值表：四个档位 + 各自的下界。顺序从高到低，与判定顺序一致。 */
const thresholdRows = computed(() => {
  const cfg = config.value
  if (!cfg) return []
  return [
    { level: 'very_high' as RiskLevel, value: cfg.thresholds.very_high },
    { level: 'high' as RiskLevel, value: cfg.thresholds.high },
    { level: 'medium' as RiskLevel, value: cfg.thresholds.medium },
    { level: 'low' as RiskLevel, value: cfg.thresholds.low },
  ]
})

function barWidth(level: RiskLevel): string {
  const total = preview.value?.risk_items_count ?? 0
  if (!total) return '0%'
  const count = preview.value?.level_counts?.[level] ?? 0
  return `${Math.round((count / total) * 100)}%`
}

onMounted(() => {
  void loadBasics()
})
</script>

<template>
  <div v-loading="loading" class="p-4">
    <!-- ── 头部 ─────────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-center gap-3">
        <el-button :icon="ArrowLeft" text @click="router.push({ name: 'assessments-list' })">
          返回列表
        </el-button>
        <span class="text-lg font-semibold">{{ assessment?.name ?? '—' }}</span>
        <el-tag
          v-if="assessment"
          :type="ASSESSMENT_STATUS_TAG_TYPE[assessment.status]"
          size="small"
        >
          {{ ASSESSMENT_STATUS_LABELS[assessment.status] }}
        </el-tag>
        <span v-if="assessment" class="text-xs text-gray-500">
          最近计算：{{ formatDateTime(assessment.calculated_at) }}
        </span>
        <div class="ml-auto flex items-center gap-2">
          <el-button v-if="canWrite" type="primary" :loading="calculating" @click="handleCalculate">
            计算并落库
          </el-button>
          <el-button
            v-if="assessment?.risk_items_count"
            @click="
              router.push({ name: 'assessment-result', params: { id: String(assessmentId) } })
            "
          >
            查看结果
          </el-button>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <!-- ── 左栏：参数 ─────────────────────────────────────────── -->
      <div class="flex flex-col gap-4">
        <div class="app-panel">
          <div class="mb-3 text-sm font-semibold">评估参数</div>

          <el-descriptions :column="1" size="small" border>
            <el-descriptions-item label="评估范围">
              {{ assessment ? SCOPE_TYPE_LABELS[assessment.scope_type] : '—' }}
              <span
                v-if="assessment && assessment.scope_type !== 'all'"
                class="ml-1 text-xs text-gray-400"
              >
                （{{ assessment.scope_ref.length }} 项）
              </span>
            </el-descriptions-item>
            <el-descriptions-item label="模型">
              {{ assessment?.model_key ?? '—' }}
            </el-descriptions-item>
          </el-descriptions>

          <div class="mt-4">
            <div class="mb-1 text-xs text-gray-500">任务级默认威胁</div>
            <div class="flex items-center gap-2">
              <el-select v-model="threatOverride" clearable filterable class="flex-1">
                <el-option
                  v-for="item in threats"
                  :key="item.code"
                  :label="`${item.name}（T=${item.weight}）`"
                  :value="item.code"
                />
              </el-select>
              <el-button
                v-if="canWrite"
                :loading="savingThreat"
                :disabled="threatOverride === (assessment?.default_threat_code ?? '')"
                @click="saveThreat"
              >
                保存
              </el-button>
            </div>
            <div class="mt-1 text-xs text-gray-400">
              留空表示未指定，按中档 T=3 计算。可在结果页对单条风险项逐项覆盖。
            </div>
          </div>

          <div class="mt-4 flex items-center gap-2">
            <el-button
              v-if="canWrite"
              :icon="Edit"
              size="small"
              @click="router.push({ name: 'assessments-list' })"
            >
              去列表页编辑范围
            </el-button>
          </div>
        </div>

        <!-- 阈值：只读展示 + 可选临时试算 -->
        <div class="app-panel">
          <div class="mb-3 flex items-center gap-2">
            <span class="text-sm font-semibold">风险阈值</span>
            <el-link
              v-if="auth.can('system:write')"
              type="primary"
              class="!text-xs"
              @click="router.push({ name: 'system-risk-model' })"
            >
              前往系统设置
            </el-link>
          </div>

          <template v-if="config">
            <div class="mb-2 flex items-center gap-2 text-xs text-gray-500">
              <span>资产价值权重系数</span>
              <span class="font-semibold text-gray-700">{{ config.asset_weight }}</span>
            </div>

            <div class="flex flex-col gap-1">
              <div
                v-for="item in thresholdRows"
                :key="item.level"
                class="flex items-center gap-2 text-xs"
              >
                <i
                  class="inline-block h-2.5 w-2.5 rounded-sm"
                  :style="{ backgroundColor: RISK_LEVEL_COLORS[item.level] }"
                ></i>
                <span class="text-gray-500">{{ RISK_LEVEL_LABELS[item.level] }}</span>
                <span class="ml-auto font-semibold">R ≥ {{ item.value }}</span>
              </div>
            </div>
            <div class="mt-1 text-xs text-gray-400">低于最低阈值判「很低」。</div>
          </template>

          <el-divider />

          <el-checkbox v-model="useTempConfig" @change="schedulePreview">
            用临时阈值试算
          </el-checkbox>
          <template v-if="useTempConfig">
            <div class="mt-3 grid grid-cols-2 gap-2">
              <div>
                <div class="mb-1 text-xs text-gray-500">权重系数</div>
                <el-input-number
                  v-model="tempConfig.assetWeight"
                  :min="0.001"
                  :max="100"
                  :step="0.1"
                  :precision="3"
                  controls-position="right"
                  class="!w-full"
                  @change="schedulePreview"
                />
              </div>
              <div>
                <div class="mb-1 text-xs text-gray-500">很高 ≥</div>
                <el-input-number
                  v-model="tempConfig.veryHigh"
                  :min="1"
                  controls-position="right"
                  class="!w-full"
                  @change="schedulePreview"
                />
              </div>
              <div>
                <div class="mb-1 text-xs text-gray-500">高 ≥</div>
                <el-input-number
                  v-model="tempConfig.high"
                  :min="1"
                  controls-position="right"
                  class="!w-full"
                  @change="schedulePreview"
                />
              </div>
              <div>
                <div class="mb-1 text-xs text-gray-500">中 ≥</div>
                <el-input-number
                  v-model="tempConfig.medium"
                  :min="1"
                  controls-position="right"
                  class="!w-full"
                  @change="schedulePreview"
                />
              </div>
              <div>
                <div class="mb-1 text-xs text-gray-500">低 ≥</div>
                <el-input-number
                  v-model="tempConfig.low"
                  :min="1"
                  controls-position="right"
                  class="!w-full"
                  @change="schedulePreview"
                />
              </div>
            </div>
            <div v-if="tempConfigHint" class="mt-2 text-xs text-red-500">{{ tempConfigHint }}</div>
            <div class="mt-2 text-xs text-gray-400">临时阈值只影响本页预览，不会写入系统设置。</div>
          </template>
        </div>
      </div>

      <!-- ── 右栏：试算结果 ───────────────────────────────────────── -->
      <div class="lg:col-span-2">
        <div v-loading="previewing" class="app-panel">
          <div class="mb-3 flex items-center gap-2">
            <span class="text-sm font-semibold">实时试算</span>
            <span class="text-xs text-gray-400">
              （参考：与「计算并落库」用的是同一套算法，数字逐条一致）
            </span>
            <el-button class="ml-auto" size="small" :icon="RefreshRight" text @click="runPreview">
              刷新
            </el-button>
          </div>

          <template v-if="preview">
            <div class="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
              <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
                <div class="text-xs text-gray-500">资产数</div>
                <div class="mt-1 text-xl font-semibold">{{ preview.assets_count }}</div>
              </div>
              <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
                <div class="text-xs text-gray-500">风险项</div>
                <div class="mt-1 text-xl font-semibold">{{ preview.risk_items_count }}</div>
              </div>
              <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
                <div class="text-xs text-gray-500">最高风险值</div>
                <div class="mt-1 text-xl font-semibold">{{ preview.max_risk.toFixed(1) }}</div>
              </div>
              <div class="rounded-md border border-gray-200 bg-gray-50 p-3">
                <div class="text-xs text-gray-500">无漏洞资产</div>
                <div class="mt-1 text-xl font-semibold">{{ preview.unmatched_assets }}</div>
              </div>
            </div>

            <div class="mb-4">
              <div class="mb-2 text-xs text-gray-500">等级分布</div>
              <div class="flex flex-col gap-1">
                <div
                  v-for="entry in levelEntries"
                  :key="entry.level"
                  class="flex items-center gap-2"
                >
                  <span class="w-10 text-xs text-gray-500">{{ entry.label }}</span>
                  <div class="h-4 flex-1 overflow-hidden rounded bg-gray-100">
                    <div
                      class="h-full rounded"
                      :style="{
                        width: barWidth(entry.level),
                        backgroundColor: RISK_LEVEL_COLORS[entry.level],
                      }"
                    ></div>
                  </div>
                  <span class="w-10 text-right text-xs">{{ entry.count }}</span>
                </div>
              </div>
            </div>

            <el-alert
              v-if="preview.risk_items_count === 0"
              type="info"
              :closable="false"
              show-icon
              title="范围内没有可评估的风险项"
              description="只有「已关联到资产的漏洞」才会产生风险项。请先在漏洞清单里把漏洞挂到资产上，或调整评估范围。"
            />

            <template v-else>
              <div class="mb-2 text-xs text-gray-500">
                风险最高的资产（展示前 {{ preview.assets.length }} 个）
              </div>
              <el-table :data="preview.assets" size="small" class="mb-4" max-height="260">
                <el-table-column
                  prop="asset_name"
                  label="资产"
                  min-width="140"
                  show-overflow-tooltip
                />
                <el-table-column prop="asset_ip" label="IP" width="130" show-overflow-tooltip />
                <el-table-column label="重要度" width="80" align="center">
                  <template #default="{ row }">{{ row.importance }}</template>
                </el-table-column>
                <el-table-column label="风险值" width="90" align="right">
                  <template #default="{ row }">{{ row.risk_value.toFixed(1) }}</template>
                </el-table-column>
                <el-table-column label="等级" width="90">
                  <template #default="{ row }">
                    <el-tag
                      size="small"
                      effect="dark"
                      :style="{
                        backgroundColor: RISK_LEVEL_COLORS[row.risk_level as RiskLevel],
                        color: RISK_LEVEL_TEXT_COLORS[row.risk_level as RiskLevel],
                        border: 'none',
                      }"
                    >
                      {{ RISK_LEVEL_LABELS[row.risk_level as RiskLevel] }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="risk_items_count" label="风险项" width="80" align="center" />
              </el-table>

              <div class="mb-2 text-xs text-gray-500">风险值最高的条目</div>
              <el-table :data="preview.top_items" size="small" max-height="320">
                <el-table-column
                  prop="asset_name"
                  label="资产"
                  min-width="120"
                  show-overflow-tooltip
                />
                <el-table-column
                  prop="vuln_title"
                  label="漏洞"
                  min-width="180"
                  show-overflow-tooltip
                />
                <el-table-column label="威胁" min-width="110" show-overflow-tooltip>
                  <template #default="{ row }">
                    <span v-if="row.threat_name">{{ row.threat_name }}</span>
                    <span v-else class="text-gray-400">未指定</span>
                    <el-tag
                      v-if="row.threat_source === 'manual'"
                      size="small"
                      type="warning"
                      class="ml-1"
                    >
                      {{ THREAT_SOURCE_LABELS.manual }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="A×T×V" width="120" align="center">
                  <template #default="{ row }">
                    <span class="text-xs text-gray-500">
                      {{ row.asset_value_a.toFixed(1) }} × {{ row.threat_weight_t.toFixed(1) }} ×
                      {{ row.vuln_weight_v.toFixed(1) }}
                    </span>
                  </template>
                </el-table-column>
                <el-table-column label="R" width="70" align="right">
                  <template #default="{ row }">
                    <span class="font-semibold">{{ row.risk_value_r.toFixed(1) }}</span>
                  </template>
                </el-table-column>
                <el-table-column label="等级" width="90">
                  <template #default="{ row }">
                    <el-tag
                      size="small"
                      effect="dark"
                      :style="{
                        backgroundColor: RISK_LEVEL_COLORS[row.risk_level as RiskLevel],
                        color: RISK_LEVEL_TEXT_COLORS[row.risk_level as RiskLevel],
                        border: 'none',
                      }"
                    >
                      {{ RISK_LEVEL_LABELS[row.risk_level as RiskLevel] }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
            </template>
          </template>

          <el-empty v-else description="暂无试算结果" />
        </div>
      </div>
    </div>
  </div>
</template>
