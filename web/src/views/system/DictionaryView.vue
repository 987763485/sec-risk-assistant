<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { Plus, Refresh } from '@element-plus/icons-vue'

import {
  createDictionary,
  deleteDictionary,
  DICTIONARY_CATEGORY_HINTS,
  DICTIONARY_CATEGORY_LABELS,
  listDictionaries,
  updateDictionary,
} from '@/api/dictionaries'
import type { Dictionary, DictionaryCategory } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'

const auth = useAuthStore()

/**
 * 写操作按 dictionary:write 权限显隐。
 *
 * ⚠️ 这只是体验层：真正的拦阻在后端路由的 RequirePermission 上。
 * 隐藏按钮是为了不让人点进去再吃一个 403，不是安全边界。
 */
const canWrite = computed(() => auth.can('dictionary:write'))

/**
 * 类别的固定顺序。
 *
 * 写成字面量数组而不是 `Object.keys(LABELS)`：Tab 的排列是设计决定，
 * 不该随标签表里键的书写顺序漂移；而且 `Object.keys` 给回的是
 * `string[]`，还得再断言一次才是 DictionaryCategory。
 */
const CATEGORIES: DictionaryCategory[] = ['asset_type', 'threat', 'vulnerability', 'measure']

const activeCategory = ref<DictionaryCategory>('asset_type')

// ------------------------------------------------------------------ 列表

const loading = ref(false)
const rows = ref<Dictionary[]>([])

async function load() {
  loading.value = true
  try {
    // 不传 enabledOnly：字典维护页必须看得到停用项。看不到的话，一个被停用的
    // 类型会从界面上凭空消失，用户既无法重新启用、也无法确认它还在——只能
    // 得出「数据丢了」这个结论。
    rows.value = await listDictionaries(activeCategory.value)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载字典失败')
    rows.value = []
  } finally {
    loading.value = false
  }
}

watch(activeCategory, () => void load())

onMounted(() => void load())

/** 当前类别的权重语义。四类共用一张表与一个 weight 列，界面上必须说清这一列的意思。 */
const weightHint = computed(() => DICTIONARY_CATEGORY_HINTS[activeCategory.value])

/** 资产类型的 weight 由后端固定为 1，编辑它没有意义 */
const weightEditable = computed(() => activeCategory.value !== 'asset_type')

// ------------------------------------------------------------------ 新建 / 编辑

const dialogVisible = ref(false)
const editingId = ref(0)
const submitting = ref(false)
const formRef = ref<FormInstance>()

const isCreate = computed(() => editingId.value === 0)

/** 编辑中的原始值：用于判断 code 有没有被改动（后端只允许原样回传） */
const originalCode = ref('')

const form = reactive({
  category: 'asset_type' as DictionaryCategory,
  code: '',
  name: '',
  weight: 1,
  description: '',
  sortOrder: 0,
  enabled: true,
})

const rules = computed<FormRules<typeof form>>(() => ({
  code: isCreate.value
    ? [
        { required: true, message: '请输入字典码', trigger: 'blur' },
        {
          pattern: /^[a-z][a-z0-9_]{0,63}$/,
          message: '以小写字母开头，只能包含小写字母、数字和下划线，最长 64 位',
          trigger: 'blur',
        },
      ]
    : [],
  name: [
    { required: true, message: '请输入显示名称', trigger: 'blur' },
    { max: 64, message: '名称不得超过 64 个字符', trigger: 'blur' },
  ],
  description: [{ max: 255, message: '说明不得超过 255 个字符', trigger: 'blur' }],
}))

/** 新建时的默认权重：资产类型恒为 1（不参与风险计算），其余类别取中档 3 */
function defaultWeight(category: DictionaryCategory): number {
  return category === 'asset_type' ? 1 : 3
}

function openCreate() {
  editingId.value = 0
  originalCode.value = ''
  Object.assign(form, {
    category: activeCategory.value,
    code: '',
    name: '',
    weight: defaultWeight(activeCategory.value),
    description: '',
    sortOrder: 0,
    enabled: true,
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

function openEdit(row: Dictionary) {
  editingId.value = row.id
  originalCode.value = row.code
  Object.assign(form, {
    category: row.category,
    code: row.code,
    name: row.name,
    weight: row.weight,
    description: row.description ?? '',
    sortOrder: row.sort_order,
    enabled: row.enabled,
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    if (isCreate.value) {
      await createDictionary({
        category: form.category,
        code: form.code.trim(),
        name: form.name.trim(),
        // 资产类型的权重后端固定为 1，这里不传，免得与后端规则打架
        weight: weightEditable.value ? form.weight : undefined,
        description: form.description.trim() || undefined,
        sort_order: form.sortOrder,
      })
      ElMessage.success('字典项已创建')
    } else {
      await updateDictionary(editingId.value, {
        // code 只能原样回传。没改动就不传——传了反而多一次「值变了没有」的判断
        code: form.code.trim() === originalCode.value ? undefined : form.code.trim(),
        name: form.name.trim(),
        weight: weightEditable.value ? form.weight : undefined,
        description: form.description.trim(),
        enabled: form.enabled,
        sort_order: form.sortOrder,
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
 * 启用 / 停用切换。
 *
 * 这是本页最常用的动作，所以做成行内开关而不是进编辑弹窗：内置项不允许删除，
 * 「停用」就是它们唯一的处置方式，不该藏在二级入口里。
 */
async function toggleEnabled(row: Dictionary) {
  const next = !row.enabled
  try {
    await updateDictionary(row.id, { enabled: next })
    ElMessage.success(next ? '已启用' : '已停用（历史数据仍能翻译出名称）')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '操作失败')
  }
}

async function handleDelete(row: Dictionary) {
  try {
    await ElMessageBox.confirm(
      `确定删除字典项「${row.name}」吗？\n\n` +
        '删除后无法恢复。如果只是想让它不再出现在新建表单里，请改用「停用」——' +
        '停用不破坏任何历史引用。',
      '删除字典项',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }

  try {
    await deleteDictionary(row.id)
    ElMessage.success('已删除')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '删除失败')
  }
}

// ------------------------------------------------------------------ 展示辅助

function asDictionary(row: TableRow): Dictionary {
  return asRow<Dictionary>(row)
}

function categoryLabel(category: DictionaryCategory) {
  return DICTIONARY_CATEGORY_LABELS[category] ?? category
}
</script>

<template>
  <div class="app-page">
    <div class="app-panel">
      <el-tabs v-model="activeCategory">
        <el-tab-pane
          v-for="category in CATEGORIES"
          :key="category"
          :label="categoryLabel(category)"
          :name="category"
        />
      </el-tabs>

      <el-alert class="mb-4" type="info" :closable="false" show-icon :title="weightHint" />

      <div class="mb-4 flex items-center gap-3">
        <span class="text-sm text-gray-500">
          共 {{ rows.length }} 项，其中停用 {{ rows.filter((r) => !r.enabled).length }} 项
        </span>
        <div class="ml-auto flex gap-2">
          <el-button :icon="Refresh" @click="load">刷新</el-button>
          <el-button v-if="canWrite" type="primary" :icon="Plus" @click="openCreate">
            新建字典项
          </el-button>
        </div>
      </div>

      <!-- 插槽里的 row 是 Record<PropertyKey, any>，传给需要 Dictionary 的
           函数前必须经 asDictionary 收敛（原因见 @/utils/table） -->
      <el-table v-loading="loading" :data="rows" stripe style="width: 100%">
        <el-table-column prop="code" label="字典码" min-width="160" fixed>
          <template #default="{ row }">
            <code class="text-xs">{{ row.code }}</code>
          </template>
        </el-table-column>

        <el-table-column prop="name" label="显示名称" min-width="160" />

        <el-table-column label="权重" width="110">
          <template #default="{ row }">
            <span v-if="weightEditable">{{ row.weight }}</span>
            <span v-else class="text-gray-400">不适用</span>
          </template>
        </el-table-column>

        <el-table-column prop="sort_order" label="排序" width="80" />

        <el-table-column label="来源" width="90">
          <template #default="{ row }">
            <el-tag v-if="row.is_builtin" size="small" type="info" effect="plain">内置</el-tag>
            <el-tag v-else size="small" type="primary" effect="plain">自定义</el-tag>
          </template>
        </el-table-column>

        <el-table-column prop="description" label="说明" min-width="200">
          <template #default="{ row }">{{ row.description || '—' }}</template>
        </el-table-column>

        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
              {{ row.enabled ? '启用' : '已停用' }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="更新时间" width="170">
          <template #default="{ row }">{{ formatDateTime(row.updated_at) }}</template>
        </el-table-column>

        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <template v-if="canWrite">
              <el-button link type="primary" size="small" @click="openEdit(asDictionary(row))">
                编辑
              </el-button>
              <el-button
                link
                :type="row.enabled ? 'warning' : 'success'"
                size="small"
                @click="toggleEnabled(asDictionary(row))"
              >
                {{ row.enabled ? '停用' : '启用' }}
              </el-button>
              <!-- 内置项禁用删除而不是隐藏后报错：按钮置灰 + tooltip 能让用户
                   立刻明白「不是不给我删，而是这个动作对内置项没有意义」 -->
              <el-tooltip
                :disabled="!row.is_builtin"
                content="内置项可以停用，但不可以删除"
                placement="top"
              >
                <span>
                  <el-button
                    link
                    type="danger"
                    size="small"
                    :disabled="row.is_builtin"
                    @click="handleDelete(asDictionary(row))"
                  >
                    删除
                  </el-button>
                </span>
              </el-tooltip>
            </template>
            <span v-else class="text-xs text-gray-400">只读</span>
          </template>
        </el-table-column>

        <template #empty>
          <el-empty :description="`「${categoryLabel(activeCategory)}」下还没有字典项`" />
        </template>
      </el-table>
    </div>

    <!-- ── 新建 / 编辑 ───────────────────────────────────────────── -->
    <el-dialog
      v-model="dialogVisible"
      :title="isCreate ? '新建字典项' : '编辑字典项'"
      width="520px"
      destroy-on-close
    >
      <el-form ref="formRef" :model="form" :rules="rules" label-width="88px">
        <el-form-item label="类别">
          <el-select v-model="form.category" class="w-full" :disabled="!isCreate">
            <el-option
              v-for="category in CATEGORIES"
              :key="category"
              :label="categoryLabel(category)"
              :value="category"
            />
          </el-select>
        </el-form-item>

        <el-form-item label="字典码" prop="code">
          <el-input
            v-model="form.code"
            :disabled="!isCreate"
            placeholder="例如 firewall，创建后不可修改"
          />
          <span v-if="!isCreate" class="text-xs text-gray-400">
            字典码被资产数据直接引用，创建后不可修改
          </span>
        </el-form-item>

        <el-form-item label="显示名称" prop="name">
          <el-input v-model="form.name" placeholder="例如 防火墙" />
        </el-form-item>

        <el-form-item v-if="weightEditable" label="权重">
          <el-slider v-model="form.weight" :min="1" :max="5" :step="0.5" show-stops />
          <span class="text-xs text-gray-400">{{ weightHint }}</span>
        </el-form-item>

        <el-form-item label="排序">
          <el-input-number v-model="form.sortOrder" :min="0" :max="9999" />
          <span class="ml-2 text-xs text-gray-400">数字小的排前面</span>
        </el-form-item>

        <el-form-item label="说明" prop="description">
          <el-input v-model="form.description" type="textarea" :rows="2" placeholder="可留空" />
        </el-form-item>

        <el-form-item v-if="!isCreate" label="状态">
          <el-switch v-model="form.enabled" active-text="启用" inactive-text="停用" />
          <div class="text-xs text-gray-400">
            停用后不再出现在新建表单里，但历史数据引用它时仍能翻译出名称
          </div>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>
