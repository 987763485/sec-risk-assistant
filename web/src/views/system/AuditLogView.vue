<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'

import {
  AUDIT_ACTION_LABELS,
  AUDIT_DANGER_ACTIONS,
  listAuditLogs,
  type AuditLogQuery,
} from '@/api/audit'
import type { AuditLog } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { formatDateTime } from '@/utils/format'

/**
 * 审计日志页。
 *
 * 只有读，没有编辑与删除 —— 后端也没有开放这两个接口，因为
 * 「可以被删掉的审计日志」在合规意义上等同于没有审计。
 */
const loading = ref(false)
const rows = ref<AuditLog[]>([])
const total = ref(0)

/** 日期区间控件绑定的是 [start, end]，与接口的两个标量参数互转 */
const dateRange = ref<[string, string] | null>(null)

const query = reactive<Omit<AuditLogQuery, 'start_at' | 'end_at'>>({
  action: '',
  resource: '',
  user_id: undefined,
  page: 1,
  pageSize: 20,
})

async function load() {
  loading.value = true
  try {
    const page = await listAuditLogs({
      ...query,
      start_at: dateRange.value?.[0],
      end_at: dateRange.value?.[1],
    })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载审计日志失败')
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
  query.action = ''
  query.resource = ''
  query.user_id = undefined
  query.page = 1
  dateRange.value = null
  void load()
}

onMounted(load)

function actionLabel(action: string) {
  return AUDIT_ACTION_LABELS[action] ?? action
}

function isDanger(action: string) {
  return AUDIT_DANGER_ACTIONS.has(action)
}

function statusTagType(code: number) {
  if (code >= 500) return 'danger'
  if (code >= 400) return 'warning'
  return 'success'
}

/** 把 detail 渲染成带缩进的 JSON，便于在展开行里直接读 */
function formatDetail(detail: unknown): string {
  if (detail === null || detail === undefined) return ''
  try {
    return JSON.stringify(detail, null, 2)
  } catch {
    return String(detail)
  }
}

/** 动作码下拉的选项，与契约中的枚举保持一致 */
const ACTION_OPTIONS = Object.keys(AUDIT_ACTION_LABELS)
</script>

<template>
  <div class="app-page">
    <!-- ── 筛选 ─────────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-center gap-3">
        <el-select v-model="query.action" class="w-44" placeholder="全部动作" clearable>
          <el-option v-for="a in ACTION_OPTIONS" :key="a" :label="actionLabel(a)" :value="a" />
        </el-select>

        <el-input v-model="query.resource" class="w-32" placeholder="资源类型" clearable />

        <el-input-number
          v-model="query.user_id"
          class="w-36"
          :min="1"
          :controls="false"
          placeholder="操作人 ID"
        />

        <el-date-picker
          v-model="dateRange"
          type="datetimerange"
          value-format="YYYY-MM-DD HH:mm:ss"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
        />

        <el-button type="primary" :icon="Search" @click="handleSearch">查询</el-button>
        <el-button :icon="Refresh" @click="handleReset">重置</el-button>
      </div>
    </div>

    <!-- ── 列表 ─────────────────────────────────────────────────── -->
    <div class="app-panel">
      <el-table v-loading="loading" :data="rows" stripe style="width: 100%">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="px-10 py-3 text-xs">
              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="请求 ID">
                  <code>{{ row.request_id || '—' }}</code>
                </el-descriptions-item>
                <el-descriptions-item label="User-Agent">
                  {{ row.user_agent || '—' }}
                </el-descriptions-item>
                <el-descriptions-item label="资源标识">
                  {{ row.resource_id || '—' }}
                </el-descriptions-item>
                <el-descriptions-item label="操作人 ID">
                  {{ row.user_id ?? '匿名' }}
                </el-descriptions-item>
              </el-descriptions>

              <div v-if="row.detail" class="mt-3">
                <div class="mb-1 text-gray-500">变更明细</div>
                <pre class="audit-detail">{{ formatDetail(row.detail) }}</pre>
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="时间" width="170">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>

        <el-table-column label="动作" min-width="150">
          <template #default="{ row }">
            <el-tag :type="isDanger(row.action) ? 'danger' : 'info'" size="small" effect="plain">
              {{ actionLabel(row.action) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="操作人" min-width="120">
          <template #default="{ row }">
            {{ row.username || '匿名' }}
          </template>
        </el-table-column>

        <el-table-column label="请求" min-width="240">
          <template #default="{ row }">
            <div class="flex items-center gap-2">
              <el-tag size="small" :type="statusTagType(row.status_code)">
                {{ row.status_code }}
              </el-tag>
              <code class="text-xs">{{ row.method }} {{ row.path }}</code>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="来源 IP" width="140">
          <template #default="{ row }">{{ row.client_ip || '—' }}</template>
        </el-table-column>

        <template #empty>
          <el-empty description="没有符合条件的审计记录" />
        </template>
      </el-table>

      <div class="mt-4 flex justify-end">
        <el-pagination
          v-model:current-page="query.page"
          v-model:page-size="query.pageSize"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          background
          @current-change="load"
          @size-change="handleSearch"
        />
      </div>

      <p class="mt-3 text-xs text-gray-400">
        审计日志只读：系统不提供修改与删除接口，以保证记录的完整性。
      </p>
    </div>
  </div>
</template>

<style scoped>
.audit-detail {
  max-height: 240px;
  margin: 0;
  padding: 10px 12px;
  overflow: auto;
  background-color: var(--el-fill-color-light);
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
}
</style>
