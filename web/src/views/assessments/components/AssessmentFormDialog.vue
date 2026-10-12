<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'

import { SCOPE_TYPE_LABELS, createAssessment, updateAssessment } from '@/api/assessments'
import { flattenAssetGroups, listAssetGroupTree } from '@/api/assetGroups'
import { listAssets } from '@/api/assets'
import { listDictionaries } from '@/api/dictionaries'
import type { Assessment, AssessmentScopeType, Dictionary } from '@/api/endpoints'
import { HttpError } from '@/api/http'

const props = defineProps<{
  modelValue: boolean
  /** 为空表示新建；否则编辑该任务 */
  assessment?: Assessment | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  saved: [assessment: Assessment]
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

const isEdit = computed(() => Boolean(props.assessment?.id))

const form = reactive({
  name: '',
  description: '',
  scopeType: 'all' as AssessmentScopeType,
  scopeRef: [] as number[],
  defaultThreatCode: '',
})

const formRef = ref<FormInstance>()

/**
 * 表单校验只看「必填」。
 *
 * 业务规则（范围不能为空、条目上限、威胁必须存在且启用）全部在后端，
 * 前端再做一遍只会制造两处会各自漂移的真值源。校验失败时后端返回的是
 * 明确的错误码与文案，直接展示即可。
 */
const rules: FormRules = {
  name: [{ required: true, message: '请输入评估任务名称', trigger: 'blur' }],
}

// ------------------------------------------------------------------ 选项

const threats = ref<Dictionary[]>([])
const groupOptions = ref<{ id: number; label: string }[]>([])
const assetOptions = ref<{ id: number; label: string }[]>([])
const optionsLoading = ref(false)

async function loadOptions() {
  optionsLoading.value = true
  try {
    const [threatList, tree] = await Promise.all([
      listDictionaries('threat', true),
      listAssetGroupTree(),
    ])
    threats.value = threatList
    // 用「缩进 + 祖先路径」的扁平列表：下拉框里看不出层级关系的话，
    // 「华东区 / 生产」与另一个同名组会无法区分。
    groupOptions.value = flattenAssetGroups(tree).map((item) => ({
      id: item.group.id,
      label: item.parentPath ? `${item.parentPath} / ${item.group.name}` : item.group.name,
    }))
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载选项失败')
  } finally {
    optionsLoading.value = false
  }
}

/** 资产远程搜索。资产可能有上万条，不预加载全量。 */
async function searchAssets(keyword: string) {
  if (!keyword.trim()) return
  try {
    const page = await listAssets({ keyword: keyword.trim(), page: 1, pageSize: 50 })
    assetOptions.value = page.items.map((asset) => ({
      id: asset.id,
      label: asset.ip_address ? `${asset.name}（${asset.ip_address}）` : asset.name,
    }))
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '搜索资产失败')
  }
}

// ------------------------------------------------------------------ 打开与提交

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    void loadOptions()
    const current = props.assessment
    if (current) {
      form.name = current.name
      form.description = current.description ?? ''
      form.scopeType = current.scope_type
      form.scopeRef = [...(current.scope_ref ?? [])]
      form.defaultThreatCode = current.default_threat_code ?? ''
      // 编辑时把已选资产补进选项列表，否则标签会显示成裸 ID
      if (current.scope_type === 'custom') {
        const items = props.assessment?.scope_ref ?? []
        assetOptions.value = items.map((id) => ({ id, label: `资产 #${id}` }))
      }
    } else {
      form.name = ''
      form.description = ''
      form.scopeType = 'all'
      form.scopeRef = []
      form.defaultThreatCode = ''
    }
    formRef.value?.clearValidate()
  },
)

/** 切换范围类型时清空已选明细：`all` 不允许带明细，后端会直接拒绝 */
watch(
  () => form.scopeType,
  (type) => {
    if (type === 'all') form.scopeRef = []
  },
)

const submitting = ref(false)

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    const payload = {
      name: form.name.trim(),
      description: form.description.trim(),
      scope_type: form.scopeType,
      scope_ref: form.scopeType === 'all' ? [] : form.scopeRef,
      default_threat_code: form.defaultThreatCode,
    }

    const saved = props.assessment?.id
      ? await updateAssessment(props.assessment.id, payload)
      : await createAssessment(payload)

    ElMessage.success(isEdit.value ? '已保存' : '评估任务已创建')
    emit('saved', saved)
    visible.value = false
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <el-dialog
    v-model="visible"
    :title="isEdit ? '编辑评估任务' : '新建评估任务'"
    width="620px"
    append-to-body
    destroy-on-close
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="110px">
      <el-form-item label="任务名称" prop="name">
        <el-input
          v-model="form.name"
          maxlength="128"
          show-word-limit
          placeholder="如：2026 年第三季度内网评估"
        />
      </el-form-item>

      <el-form-item label="说明">
        <el-input
          v-model="form.description"
          type="textarea"
          :rows="2"
          maxlength="512"
          show-word-limit
          placeholder="选填"
        />
      </el-form-item>

      <el-form-item label="评估范围">
        <el-radio-group v-model="form.scopeType">
          <el-radio-button v-for="(label, value) in SCOPE_TYPE_LABELS" :key="value" :value="value">
            {{ label }}
          </el-radio-button>
        </el-radio-group>
      </el-form-item>

      <el-form-item v-if="form.scopeType === 'group'" label="资产组">
        <el-select
          v-model="form.scopeRef"
          multiple
          filterable
          clearable
          collapse-tags
          collapse-tags-tooltip
          :loading="optionsLoading"
          placeholder="选择资产组（自动包含其子组）"
          class="w-full"
        >
          <el-option
            v-for="item in groupOptions"
            :key="item.id"
            :label="item.label"
            :value="item.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item v-if="form.scopeType === 'custom'" label="资产">
        <el-select
          v-model="form.scopeRef"
          multiple
          filterable
          remote
          clearable
          collapse-tags
          collapse-tags-tooltip
          :remote-method="searchAssets"
          placeholder="输入资产名称或 IP 搜索"
          class="w-full"
        >
          <el-option
            v-for="item in assetOptions"
            :key="item.id"
            :label="item.label"
            :value="item.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="默认威胁">
        <el-select
          v-model="form.defaultThreatCode"
          clearable
          filterable
          placeholder="留空表示未指定（按中档 T=3 计算）"
          class="w-full"
        >
          <el-option
            v-for="item in threats"
            :key="item.code"
            :label="`${item.name}（T=${item.weight}）`"
            :value="item.code"
          />
        </el-select>
        <div class="mt-1 text-xs text-gray-500">
          任务级默认威胁，可在结果页对单条风险项逐项覆盖。
        </div>
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="handleSubmit">
        {{ isEdit ? '保存' : '创建' }}
      </el-button>
    </template>
  </el-dialog>
</template>
