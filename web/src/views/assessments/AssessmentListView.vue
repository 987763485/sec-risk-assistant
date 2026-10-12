<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, Plus, Refresh, Search } from '@element-plus/icons-vue'

import {
  ASSESSMENT_STATUS_LABELS,
  ASSESSMENT_STATUS_TAG_TYPE,
  RISK_LEVEL_LABELS,
  SCOPE_TYPE_LABELS,
  deleteAssessment,
  levelCountEntries,
  listAssessments,
} from '@/api/assessments'
import { REPORT_FORMAT_OPTIONS, exportReport } from '@/api/reports'
import type { Assessment, ReportFormat } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { saveBlob } from '@/utils/download'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'
import AssessmentFormDialog from './components/AssessmentFormDialog.vue'

const auth = useAuthStore()
const router = useRouter()

/** 写操作按 assessment:write 显隐。真正的拦阻在后端，这里只为少一次 403。 */
const canWrite = computed(() => auth.can('assessment:write'))

const STATUS_OPTIONS = ['draft', 'calculated'] as const

// ------------------------------------------------------------------ 列表

const loading = ref(false)
const rows = ref<Assessment[]>([])
const total = ref(0)

const query = reactive({
  keyword: '',
  status: '' as '' | 'draft' | 'calculated',
  page: 1,
  pageSize: 20,
})

async function load() {
  loading.value = true
  try {
    const page = await listAssessments({
      page: query.page,
      pageSize: query.pageSize,
      keyword: query.keyword.trim(),
      status: query.status || undefined,
    })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载评估任务失败')
    rows.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  query.page = 1
  void load()
}

function handleReset() {
  Object.assign(query, { keyword: '', status: '', page: 1 })
  void load()
}

onMounted(() => {
  void load()
})

// ------------------------------------------------------------------ 新建与编辑

const formVisible = ref(false)
const editing = ref<Assessment | null>(null)

function openCreate() {
  editing.value = null
  formVisible.value = true
}

function openEdit(row: Assessment) {
  editing.value = row
  formVisible.value = true
}

async function handleSaved() {
  await load()
}

// ------------------------------------------------------------------ 进入与删除

function openExecute(row: Assessment) {
  void router.push({ name: 'assessment-execute', params: { id: String(row.id) } })
}

function openResult(row: Assessment) {
  void router.push({ name: 'assessment-result', params: { id: String(row.id) } })
}

async function handleDelete(row: Assessment) {
  const hint =
    row.status === 'calculated'
      ? `该任务已计算过（${row.risk_items_count} 条风险项），删除后这些结果一并消失，且无法恢复。`
      : '任务尚未计算，删除后不可恢复。'
  try {
    await ElMessageBox.confirm(`确定删除评估任务「${row.name}」吗？${hint}`, '删除评估任务', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
      confirmButtonClass: 'el-button--danger',
    })
  } catch {
    return
  }

  try {
    await deleteAssessment(row.id)
    ElMessage.success('已删除')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '删除失败')
  }
}

// ------------------------------------------------------------------ 导出报告

/**
 * 正在导出的那一行的 id。
 *
 * 用行 id 而不是一个布尔量：否则点了一行的导出，整张表的每一行都会转圈，
 * 用户会以为自己不小心触发了批量导出。
 */
const exportingId = ref<number | null>(null)

/**
 * 在列表里直接导出报告。
 *
 * 与结果页共用 `exportReport` 这一个方法——列表页的价值只是「不必为了拿
 * 一份文件先进去再点两下」，而不是第二条导出路径。
 */
async function handleExport(row: Assessment, command: unknown) {
  exportingId.value = row.id
  try {
    const file = await exportReport(row.id, command as ReportFormat, row.name)
    saveBlob(file.blob, file.fileName)
    ElMessage.success(`已导出「${row.name}」`)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '导出失败')
  } finally {
    exportingId.value = null
  }
}

// ------------------------------------------------------------------ 展示辅助

function asAssessment(row: TableRow): Assessment {
  return asRow<Assessment>(row)
}

/** 等级分布：按从高到低渲染成一排色块 + 数字，零值灰显 */
function levelEntries(row: Assessment) {
  return levelCountEntries(row.level_counts)
}

function hasAnyResult(row: Assessment): boolean {
  return row.risk_items_count > 0
}

function formatMaxRisk(row: Assessment): string {
  // 未计算时为 null，展示成「—」而不是 0——0 分与「还没算」是两件事
  return row.max_risk === null || row.max_risk === undefined ? '—' : row.max_risk.toFixed(1)
}
</script>

<template>
  <div class="p-4">
    <!-- ── 筛选 ─────────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-center gap-2">
        <el-input
          v-model="query.keyword"
          placeholder="按名称或说明搜索"
          clearable
          class="!w-64"
          @keyup.enter="handleSearch"
        />

        <el-select v-model="query.status" placeholder="全部状态" clearable class="!w-36">
          <el-option
            v-for="status in STATUS_OPTIONS"
            :key="status"
            :label="ASSESSMENT_STATUS_LABELS[status]"
            :value="status"
          />
        </el-select>

        <el-button type="primary" :icon="Search" @click="handleSearch">查询</el-button>
        <el-button :icon="Refresh" @click="handleReset">重置</el-button>
      </div>
    </div>

    <!-- ── 列表 ─────────────────────────────────────────────────── -->
    <div class="app-panel">
      <div class="mb-4 flex items-center gap-2">
        <span class="text-sm text-gray-500">共 {{ total }} 个评估任务</span>
        <div v-if="canWrite" class="ml-auto">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建评估</el-button>
        </div>
      </div>

      <el-table v-loading="loading" :data="rows" stripe style="width: 100%">
        <el-table-column label="任务名称" min-width="200" fixed show-overflow-tooltip>
          <template #default="{ row }">
            <el-button link type="primary" @click="openExecute(asAssessment(row))">
              {{ asAssessment(row).name }}
            </el-button>
          </template>
        </el-table-column>

        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="ASSESSMENT_STATUS_TAG_TYPE[asAssessment(row).status]" size="small">
              {{ ASSESSMENT_STATUS_LABELS[asAssessment(row).status] }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="范围" width="110">
          <template #default="{ row }">
            <span>{{ SCOPE_TYPE_LABELS[asAssessment(row).scope_type] }}</span>
            <span v-if="asAssessment(row).scope_type !== 'all'" class="ml-1 text-xs text-gray-400">
              {{ asAssessment(row).scope_ref.length }} 项
            </span>
          </template>
        </el-table-column>

        <el-table-column label="默认威胁" width="120" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="asAssessment(row).default_threat_name">
              {{ asAssessment(row).default_threat_name }}
            </span>
            <span v-else class="text-gray-400">未指定</span>
          </template>
        </el-table-column>

        <el-table-column label="资产 / 风险项" width="120" align="center">
          <template #default="{ row }">
            {{ asAssessment(row).assets_count }} / {{ asAssessment(row).risk_items_count }}
          </template>
        </el-table-column>

        <el-table-column label="最高风险" width="100" align="center">
          <template #default="{ row }">
            <span v-if="hasAnyResult(asAssessment(row))" class="font-semibold">
              {{ formatMaxRisk(asAssessment(row)) }}
            </span>
            <span v-else class="text-gray-400">—</span>
          </template>
        </el-table-column>

        <el-table-column label="等级分布" min-width="220">
          <template #default="{ row }">
            <div v-if="hasAnyResult(asAssessment(row))" class="flex flex-wrap items-center gap-2">
              <span
                v-for="entry in levelEntries(asAssessment(row))"
                :key="entry.level"
                class="flex items-center gap-1 text-xs"
                :class="entry.count === 0 ? 'text-gray-300' : ''"
              >
                <i
                  class="inline-block h-2.5 w-2.5 rounded-sm"
                  :style="{ backgroundColor: entry.count === 0 ? '#e5e7eb' : entry.color }"
                ></i>
                {{ RISK_LEVEL_LABELS[entry.level] }} {{ entry.count }}
              </span>
            </div>
            <span v-else class="text-xs text-gray-400">尚未计算</span>
          </template>
        </el-table-column>

        <el-table-column label="计算时间" width="170">
          <template #default="{ row }">{{
            formatDateTime(asAssessment(row).calculated_at)
          }}</template>
        </el-table-column>

        <el-table-column label="操作" width="290" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="openExecute(asAssessment(row))">
              执行
            </el-button>
            <el-button
              v-if="hasAnyResult(asAssessment(row))"
              link
              type="primary"
              size="small"
              @click="openResult(asAssessment(row))"
            >
              结果
            </el-button>
            <!-- 草稿不可导出：后端会以 409 REPORT_NOT_CALCULATED 拒绝 -->
            <el-dropdown
              v-if="asAssessment(row).status === 'calculated'"
              @command="handleExport(asAssessment(row), $event)"
            >
              <el-button
                link
                type="primary"
                size="small"
                :loading="exportingId === asAssessment(row).id"
              >
                导出<el-icon class="ml-0.5"><ArrowDown /></el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item
                    v-for="opt in REPORT_FORMAT_OPTIONS"
                    :key="opt.value"
                    :command="opt.value"
                  >
                    {{ opt.label }}（.{{ opt.ext }}）
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
            <template v-if="canWrite">
              <el-button link type="primary" size="small" @click="openEdit(asAssessment(row))">
                编辑
              </el-button>
              <el-button link type="danger" size="small" @click="handleDelete(asAssessment(row))">
                删除
              </el-button>
            </template>
          </template>
        </el-table-column>

        <template #empty>
          <div class="py-8 text-sm text-gray-400">还没有评估任务。点击右上角「新建评估」开始。</div>
        </template>
      </el-table>

      <div class="mt-4 flex justify-end">
        <el-pagination
          v-model:current-page="query.page"
          v-model:page-size="query.pageSize"
          :total="total"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next"
          @current-change="load"
          @size-change="handleSearch"
        />
      </div>
    </div>

    <AssessmentFormDialog v-model="formVisible" :assessment="editing" @saved="handleSaved" />
  </div>
</template>
