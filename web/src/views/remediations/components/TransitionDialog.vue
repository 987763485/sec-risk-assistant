<script setup lang="ts">
/**
 * 状态流转对话框。
 *
 * ▍这里**没有**任何状态机规则
 *
 * 可选项直接来自 `remediation.transitions` —— 那是后端状态机与
 * 必填校验规则的投影。前端另写一份「pending 能到哪」会制造第二条
 * 真值源：它与后端分叉时不会报错，表现是按钮点了返回 409，
 * 而按钮看起来完全正常。整个组件里因此没有一处 if/else 判断状态合法性，
 * 也没有一处判断「这个目标要不要填说明」。
 */
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'

import {
  REMEDIATION_STATUS_LABELS,
  REMEDIATION_STATUS_TAG_TYPE,
  transitionRemediation,
} from '@/api/remediations'
import type { Remediation, RemediationStatus } from '@/api/endpoints'
import { HttpError } from '@/api/http'

const props = defineProps<{
  modelValue: boolean
  remediation: Remediation | null
  /** 快捷进入时的预选目标（列表页的行内按钮会带上它） */
  preset?: RemediationStatus | ''
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  done: [remediation: Remediation]
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

const toStatus = ref<RemediationStatus | ''>('')
const note = ref('')
const submitting = ref(false)

const options = computed(() => props.remediation?.transitions ?? [])

/** 当前选中目标是否要求写说明（同样来自后端投影，不是前端规则） */
const noteRequired = computed(
  () => options.value.find((o) => o.to_status === toStatus.value)?.note_required ?? false,
)

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    note.value = ''
    toStatus.value = props.preset || (options.value[0]?.to_status ?? '')
  },
)

/** 目标切换时清空说明：上一条说明是给另一个状态写的，留着会误导 */
watch(toStatus, () => {
  note.value = ''
})

const targetLabel = computed(() =>
  toStatus.value ? REMEDIATION_STATUS_LABELS[toStatus.value as RemediationStatus] : '',
)

async function handleSubmit() {
  const current = props.remediation
  if (!current || !toStatus.value) return
  if (noteRequired.value && !note.value.trim()) {
    ElMessage.warning('该流转必须填写说明')
    return
  }

  submitting.value = true
  try {
    const updated = await transitionRemediation(current.id, {
      to_status: toStatus.value as RemediationStatus,
      note: note.value.trim(),
    })
    ElMessage.success(`已流转为「${REMEDIATION_STATUS_LABELS[updated.status]}」`)
    emit('done', updated)
    visible.value = false
  } catch (err) {
    // 409 的文案会列出「当前可流转到：…」，比前端猜的准，因此优先用它
    ElMessage.error(err instanceof HttpError ? err.message : '流转失败')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="整改单状态流转" width="520px" append-to-body destroy-on-close>
    <template v-if="remediation">
      <el-descriptions :column="1" size="small" border class="mb-3">
        <el-descriptions-item label="整改单">{{ remediation.title }}</el-descriptions-item>
        <el-descriptions-item label="目标">
          {{ remediation.asset_name }}
          <span class="text-xs text-gray-400">（{{ remediation.asset_ip || '无 IP' }}）</span>
        </el-descriptions-item>
        <el-descriptions-item label="当前状态">
          <el-tag :type="REMEDIATION_STATUS_TAG_TYPE[remediation.status]" size="small">
            {{ REMEDIATION_STATUS_LABELS[remediation.status] }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <el-form label-width="80px">
        <el-form-item label="流转为">
          <el-select v-model="toStatus" class="w-full">
            <el-option
              v-for="opt in options"
              :key="opt.to_status"
              :label="REMEDIATION_STATUS_LABELS[opt.to_status]"
              :value="opt.to_status"
            >
              <span>{{ REMEDIATION_STATUS_LABELS[opt.to_status] }}</span>
              <span v-if="opt.note_required" class="ml-2 text-xs text-gray-400">需说明</span>
            </el-option>
          </el-select>
        </el-form-item>

        <el-form-item>
          <template #label>
            <span>说明</span>
          </template>
          <el-input
            v-model="note"
            type="textarea"
            :rows="3"
            maxlength="500"
            show-word-limit
            :placeholder="
              noteRequired ? '必填：写清结论或理由，否则这次变更事后无法解释' : '选填：补充说明'
            "
          />
        </el-form-item>
      </el-form>

      <el-alert
        v-if="noteRequired"
        type="info"
        :closable="false"
        show-icon
        :title="`流转为「${targetLabel}」时必须填写说明`"
      >
        <template #default>
          这是唯一能沉淀「决策理由」的地方：闭环时说清怎么修的，风险接受时说清
          为什么不修。否则过一段时间没人能解释这张单子为什么就这么结束了。
        </template>
      </el-alert>
    </template>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="handleSubmit">确认流转</el-button>
    </template>
  </el-dialog>
</template>
