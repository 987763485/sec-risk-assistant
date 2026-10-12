<script setup lang="ts">
/**
 * 从一条风险项建整改单（评估结果页的行内入口）。
 *
 * `risk_item_id` 由调用方给出、界面上不出现：整改单要有风险等级与风险值，
 * 而这两者只有风险项才有。让用户从下拉框里挑「资产 + 漏洞」看似更灵活，
 * 代价是能造出「等级为空」的单子——仪表盘的按等级统计与逾期清单都依赖它。
 */
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'

import { RISK_LEVEL_LABELS } from '@/api/assessments'
import { createRemediation } from '@/api/remediations'
import type { Remediation, RiskItem, RiskLevel } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import AssigneeSelect from './AssigneeSelect.vue'

const props = defineProps<{
  modelValue: boolean
  item: RiskItem | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  created: [remediation: Remediation]
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

const form = ref({ title: '', description: '', dueDate: '', assigneeId: null as number | null })
const submitting = ref(false)

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    // 标题默认取漏洞标题：绝大多数整改单的标题就是漏洞名，
    // 让人每次重打一遍只会得到一堆「修复漏洞」这类无信息的标题
    form.value = {
      title: props.item?.vuln_title ?? '',
      description: '',
      dueDate: '',
      assigneeId: null,
    }
  },
)

async function handleSubmit() {
  const item = props.item
  if (!item) return

  submitting.value = true
  try {
    const created = await createRemediation({
      risk_item_id: item.id,
      title: form.value.title.trim(),
      description: form.value.description.trim(),
      assignee_id: form.value.assigneeId,
      due_date: form.value.dueDate,
    })
    ElMessage.success('整改单已创建')
    emit('created', created)
    visible.value = false
  } catch (err) {
    // 409 的文案是「该资产上的这个漏洞已有一张未闭环的整改单，请直接处理那张单子」
    // ——它就是用户需要看到的下一步，不要替换成「创建失败」
    ElMessage.error(err instanceof HttpError ? err.message : '创建整改单失败')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="新建整改单" width="560px" append-to-body destroy-on-close>
    <template v-if="item">
      <el-descriptions :column="1" size="small" border class="mb-3">
        <el-descriptions-item label="资产">
          {{ item.asset_name }}
          <span class="text-xs text-gray-400">（{{ item.asset_ip || '无 IP' }}）</span>
        </el-descriptions-item>
        <el-descriptions-item label="漏洞">{{ item.vuln_title }}</el-descriptions-item>
        <el-descriptions-item label="风险">
          <span class="font-semibold">R = {{ item.risk_value_r.toFixed(1) }}</span>
          <el-tag size="small" class="ml-2">
            {{ RISK_LEVEL_LABELS[item.risk_level as RiskLevel] }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <el-form label-width="80px">
        <el-form-item label="标题">
          <el-input v-model="form.title" maxlength="255" show-word-limit />
        </el-form-item>

        <el-form-item label="说明">
          <el-input
            v-model="form.description"
            type="textarea"
            :rows="2"
            maxlength="1000"
            show-word-limit
            placeholder="选填：要改成什么、有哪些前置条件"
          />
        </el-form-item>

        <el-form-item label="负责人">
          <AssigneeSelect v-model="form.assigneeId" />
        </el-form-item>

        <el-form-item label="整改期限">
          <el-date-picker
            v-model="form.dueDate"
            type="date"
            value-format="YYYY-MM-DD"
            placeholder="留空表示不设期限（永远不算逾期）"
            class="w-full"
          />
        </el-form-item>
      </el-form>
    </template>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="handleSubmit">创建</el-button>
    </template>
  </el-dialog>
</template>
