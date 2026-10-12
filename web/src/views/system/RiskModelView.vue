<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, Select } from '@element-plus/icons-vue'

import { getSystemConfigs, updateSystemConfigs } from '@/api/systemConfigs'
import type { SystemConfigView } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'

const auth = useAuthStore()

/** 保存按钮按 system:write 显隐。真正的拦阻在后端路由上。 */
const canWrite = computed(() => auth.can('system:write'))

const loading = ref(false)
const saving = ref(false)
const config = ref<SystemConfigView | null>(null)

const form = reactive({
  assetWeight: 1,
  veryHigh: 20,
  high: 12,
  medium: 6,
  low: 2,
})

/** 记录加载时的原值，用于「值没变就不该可保存」与重置 */
const pristine = reactive({ ...form })

function applyConfig(view: SystemConfigView) {
  config.value = view
  form.assetWeight = view.asset_weight
  form.veryHigh = view.thresholds.very_high
  form.high = view.thresholds.high
  form.medium = view.thresholds.medium
  form.low = view.thresholds.low
  Object.assign(pristine, {
    assetWeight: form.assetWeight,
    veryHigh: form.veryHigh,
    high: form.high,
    medium: form.medium,
    low: form.low,
  })
}

async function load() {
  loading.value = true
  try {
    applyConfig(await getSystemConfigs())
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载系统配置失败')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
})

/**
 * 前端做一次单调性检查只是为了「早点告诉用户哪里不对」。
 *
 * 真正的判定在后端（服务端会与现值合并后再校验并返回 `RISK_CONFIG_INVALID`），
 * 这里不阻止提交——两处各写一套规则，迟早会漂移，而漂移之后
 * 用户看到的是「界面说没问题、后端拒绝」。
 */
const orderHint = computed(() => {
  const { veryHigh, high, medium, low } = form
  if (!(veryHigh > high && high > medium && medium > low)) {
    return '四个阈值必须严格递减（很高 > 高 > 中 > 低）。相等会让中间那一档永远判不出来。'
  }
  if (low < 1) {
    return '「低」的下界不能小于 1，否则「很低」这一档永远为空。'
  }
  return ''
})

const dirty = computed(
  () =>
    form.assetWeight !== pristine.assetWeight ||
    form.veryHigh !== pristine.veryHigh ||
    form.high !== pristine.high ||
    form.medium !== pristine.medium ||
    form.low !== pristine.low,
)

async function handleSave() {
  saving.value = true
  try {
    const view = await updateSystemConfigs({
      asset_weight: form.assetWeight,
      thresholds: {
        very_high: form.veryHigh,
        high: form.high,
        medium: form.medium,
        low: form.low,
      },
    })
    applyConfig(view)
    ElMessage.success('已保存。改动只影响之后的计算，已计算的评估仍用各自的快照。')
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    saving.value = false
  }
}

function handleReset() {
  Object.assign(form, pristine)
}
</script>

<template>
  <div v-loading="loading" class="p-4">
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-center gap-3">
        <span class="text-lg font-semibold">风险模型</span>
        <span class="text-xs text-gray-500"> 模型：{{ config?.model ?? '—' }} </span>
        <span class="text-xs text-gray-500">
          最近变更：{{ formatDateTime(config?.updated_at) }}
        </span>
        <div class="ml-auto flex items-center gap-2">
          <el-button :icon="Refresh" @click="load">刷新</el-button>
          <template v-if="canWrite">
            <el-button :disabled="!dirty" @click="handleReset">撤销</el-button>
            <el-button
              type="primary"
              :icon="Select"
              :loading="saving"
              :disabled="!dirty"
              @click="handleSave"
            >
              保存
            </el-button>
          </template>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="app-panel">
        <div class="mb-3 text-sm font-semibold">权重与阈值</div>

        <el-form label-width="150px">
          <el-form-item label="资产价值权重系数">
            <el-input-number
              v-model="form.assetWeight"
              :min="0.001"
              :max="100"
              :step="0.1"
              :precision="3"
              controls-position="right"
              :disabled="!canWrite"
              class="!w-full"
            />
            <div class="mt-1 text-xs text-gray-500">
              R = A × T × V，其中 A = 资产重要性 × 该系数。默认 1.000 表示不缩放。
            </div>
          </el-form-item>

          <el-divider content-position="left">等级阈值（R ≥ 下界即判定为该等级）</el-divider>

          <el-form-item label="很高 ≥">
            <el-input-number
              v-model="form.veryHigh"
              :min="1"
              controls-position="right"
              :disabled="!canWrite"
              class="!w-full"
            />
          </el-form-item>
          <el-form-item label="高 ≥">
            <el-input-number
              v-model="form.high"
              :min="1"
              controls-position="right"
              :disabled="!canWrite"
              class="!w-full"
            />
          </el-form-item>
          <el-form-item label="中 ≥">
            <el-input-number
              v-model="form.medium"
              :min="1"
              controls-position="right"
              :disabled="!canWrite"
              class="!w-full"
            />
          </el-form-item>
          <el-form-item label="低 ≥">
            <el-input-number
              v-model="form.low"
              :min="1"
              controls-position="right"
              :disabled="!canWrite"
              class="!w-full"
            />
            <div class="mt-1 text-xs text-gray-500">低于该值判「很低」。</div>
          </el-form-item>
        </el-form>

        <el-alert v-if="orderHint" type="error" :closable="false" show-icon :title="orderHint" />

        <el-alert
          class="mt-3"
          type="warning"
          :closable="false"
          show-icon
          title="改动只影响之后的计算"
          description="已计算过的评估使用它自己的配置快照，阈值调整不会改写历史结论——这是为了让已发出的报告与库里的数据始终对得上。"
        />
      </div>

      <div class="app-panel">
        <div class="mb-3 text-sm font-semibold">配置项明细</div>
        <el-table :data="config?.items ?? []" size="small" style="width: 100%">
          <el-table-column prop="key" label="键" min-width="190" show-overflow-tooltip />
          <el-table-column prop="value" label="值" width="100" />
          <el-table-column prop="description" label="说明" min-width="200" show-overflow-tooltip />
          <el-table-column label="可改" width="70" align="center">
            <template #default="{ row }">
              <span v-if="row.editable" class="text-green-600">是</span>
              <span v-else class="text-gray-400">否</span>
            </template>
          </el-table-column>
        </el-table>
        <div class="mt-2 text-xs text-gray-400">
          模型标识不允许在界面修改：代码认识它、用户不该改它——只读展示比对着一个
          可改的输入框解释它为什么不能改要好。
        </div>
      </div>
    </div>
  </div>
</template>
