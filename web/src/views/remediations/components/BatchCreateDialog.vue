<script setup lang="ts">
/**
 * 按评估任务批量建单。
 *
 * ▍为什么这个对话框要专门说明「幂等」
 *
 * 单张建单遇到同一 (资产, 漏洞) 的未闭环单会 409 拒绝；批量建单**跳过不报错**
 * （结果里的 `skipped`）。理由是批量建单的典型用法是「算完一次评估后把高
 * 风险的都开一次单」，用户会在评估重算后再点一次——那时若整批失败，
 * 这个功能就没法用了。
 *
 * 界面上必须把这件事说清楚，否则用户看到「命中 30、新建 0、跳过 30」
 * 会以为出了问题。所以结果区同时展示这三个数字，并把「0 新建」解释成
 * 「这些单子已经存在」。
 */
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'

import { RISK_LEVEL_LABELS, RISK_LEVEL_ORDER, listAssessments } from '@/api/assessments'
import { batchCreateRemediations } from '@/api/remediations'
import type { Assessment, BatchCreateRemediationResult, RiskLevel } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import AssigneeSelect from './AssigneeSelect.vue'

const props = defineProps<{
  modelValue: boolean
  /** 由结果页进入时预选该评估；列表页进入时留空由用户挑 */
  presetAssessmentId?: number
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  done: [result: BatchCreateRemediationResult]
}>()

const auth = useAuthStore()

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

/** 批量建单要先挑评估任务，而列出评估任务要 assessment:read */
const canReadAssessments = computed(() => auth.can('assessment:read'))

const assessments = ref<Assessment[]>([])
const loading = ref(false)

const form = ref({
  assessmentId: undefined as number | undefined,
  levels: ['very_high', 'high'] as RiskLevel[],
  dueInDays: undefined as number | undefined,
  assigneeId: null as number | null,
})

/** 上一次的建单结果。留在对话框里而不是弹个 toast 就消失——
 *  「命中 / 新建 / 跳过」三个数字是用户判断下一步该做什么的唯一依据。 */
const result = ref<BatchCreateRemediationResult | null>(null)
const submitting = ref(false)

async function loadAssessments() {
  if (!canReadAssessments.value) return
  loading.value = true
  try {
    // 只列已计算的：草稿没有任何风险项，按它建单只会得到「命中 0 条」
    const page = await listAssessments({ page: 1, pageSize: 100, status: 'calculated' })
    assessments.value = page.items
  } catch (err) {
    assessments.value = []
    if (err instanceof HttpError) ElMessage.warning(`加载评估任务失败：${err.message}`)
  } finally {
    loading.value = false
  }
}

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    result.value = null
    form.value = {
      assessmentId: props.presetAssessmentId,
      levels: ['very_high', 'high'],
      dueInDays: undefined,
      assigneeId: null,
    }
    void loadAssessments()
  },
)

async function handleSubmit() {
  if (!form.value.assessmentId) {
    ElMessage.warning('请先选择评估任务')
    return
  }
  if (form.value.levels.length === 0) {
    ElMessage.warning('请至少选择一个风险等级')
    return
  }

  submitting.value = true
  try {
    const res = await batchCreateRemediations({
      assessment_id: form.value.assessmentId,
      levels: form.value.levels,
      // 空列表会被后端退化为「很高 + 高」，这里显式判空是为了让提示
      // 出现在用户点按钮的那一刻而不是提交之后
      due_in_days: form.value.dueInDays ?? null,
      assignee_id: form.value.assigneeId,
    })
    result.value = res
    if (res.created > 0) {
      ElMessage.success(`已新建 ${res.created} 张整改单`)
    } else {
      ElMessage.info('没有新建整改单：命中的目标都已有未闭环单')
    }
    emit('done', res)
  } catch (err) {
    // 400 的文案会给出准确的命中条数（先数后取），比「超过上限」有用得多
    ElMessage.error(err instanceof HttpError ? err.message : '批量建单失败')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <el-dialog
    v-model="visible"
    title="按评估任务批量建单"
    width="620px"
    append-to-body
    destroy-on-close
  >
    <el-alert
      v-if="!canReadAssessments"
      type="warning"
      :closable="false"
      show-icon
      title="当前账号没有「读取评估任务」权限"
      class="mb-3"
    >
      <template #default>
        批量建单需要先选一个已计算的评估任务。可以改用评估结果页逐条建单。
      </template>
    </el-alert>

    <el-form v-else label-width="110px">
      <el-form-item label="评估任务">
        <el-select
          v-model="form.assessmentId"
          filterable
          :loading="loading"
          placeholder="选择一份已计算的评估任务"
          class="w-full"
        >
          <el-option v-for="item in assessments" :key="item.id" :label="item.name" :value="item.id">
            <span>{{ item.name }}</span>
            <span class="ml-2 text-xs text-gray-400">{{ item.risk_items_count }} 条风险项</span>
          </el-option>
        </el-select>
      </el-form-item>

      <el-form-item label="风险等级">
        <el-select v-model="form.levels" multiple collapse-tags class="w-full">
          <el-option
            v-for="level in RISK_LEVEL_ORDER"
            :key="level"
            :label="RISK_LEVEL_LABELS[level]"
            :value="level"
          />
        </el-select>
        <div class="mt-1 text-xs text-gray-500">
          只为所选等级下的风险项建单。一次最多 500 张——超过时后端会拒绝并
          给出准确的命中条数，请收窄等级后分批建单。
        </div>
      </el-form-item>

      <el-form-item label="整改期限">
        <el-input-number
          v-model="form.dueInDays"
          :min="0"
          :max="3650"
          placeholder="不设期限"
          class="!w-40"
        />
        <span class="ml-2 text-xs text-gray-500">天后到期（留空表示不设期限）</span>
      </el-form-item>

      <el-form-item label="负责人">
        <AssigneeSelect v-model="form.assigneeId" />
      </el-form-item>
    </el-form>

    <!-- ── 结果 ──────────────────────────────────────────────────── -->
    <div v-if="result" class="mt-2 rounded-md border border-gray-200 bg-gray-50 p-3">
      <div class="mb-2 text-sm font-semibold">本次结果</div>
      <div class="flex flex-wrap gap-4 text-sm">
        <span
          >命中 <b>{{ result.matched }}</b> 条风险项</span
        >
        <span
          >新建 <b class="text-green-600">{{ result.created }}</b> 张</span
        >
        <span
          >跳过 <b>{{ result.skipped }}</b> 张</span
        >
      </div>
      <div class="mt-2 text-xs text-gray-500">
        跳过表示该资产上的这个漏洞已经有一张未闭环的整改单。同一个评估连续点击
        两次时，第二次会是「新建 0 / 跳过全部」——这是幂等，不是失败。
      </div>
    </div>

    <template #footer>
      <el-button @click="visible = false">
        {{ result ? '完成' : '取消' }}
      </el-button>
      <el-button
        v-if="canReadAssessments"
        type="primary"
        :loading="submitting"
        @click="handleSubmit"
      >
        开始建单
      </el-button>
    </template>
  </el-dialog>
</template>
