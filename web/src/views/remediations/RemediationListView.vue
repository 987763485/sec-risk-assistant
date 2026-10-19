<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'

import { RISK_LEVEL_LABELS, RISK_LEVEL_ORDER, RISK_LEVEL_TAG_TYPE } from '@/api/assessments'
import {
  REMEDIATION_STATUS_LABELS,
  REMEDIATION_STATUS_ORDER,
  REMEDIATION_STATUS_TAG_TYPE,
  deleteRemediation,
  listRemediations,
  remediationTimingTagType,
  remediationTimingText,
} from '@/api/remediations'
import type { Remediation, RemediationStatus, RiskLevel } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'
import BatchCreateDialog from './components/BatchCreateDialog.vue'
import TransitionDialog from './components/TransitionDialog.vue'

const auth = useAuthStore()
const router = useRouter()

/** 写操作按 remediation:write 显隐。真正的拦阻在后端，这里只为少一次 403 */
const canWrite = computed(() => auth.can('remediation:write'))

// ------------------------------------------------------------------ 列表

const loading = ref(false)
const rows = ref<Remediation[]>([])
const total = ref(0)

const query = reactive({
  keyword: '',
  status: '' as '' | RemediationStatus,
  active: false,
  overdue: false,
  level: '' as '' | RiskLevel,
  mine: false,
  page: 1,
  pageSize: 20,
})

async function load() {
  loading.value = true
  try {
    const page = await listRemediations({
      page: query.page,
      pageSize: query.pageSize,
      keyword: query.keyword.trim(),
      // status 与 active 同时给时以后端规则为准（active 优先），
      // 因此这里二选一：选了状态就不再加 active
      status: query.status || undefined,
      active: query.status ? undefined : query.active || undefined,
      overdue: query.overdue || undefined,
      level: query.level || undefined,
      // 「只看我负责的」直接用自己的 ID，不需要额外的用户清单接口——
      // 这也是评估员（没有 user:read）唯一能用的分派维度
      assignee_id: query.mine ? (auth.user?.user_id ?? undefined) : undefined,
    })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载整改单失败')
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
  Object.assign(query, {
    keyword: '',
    status: '',
    active: false,
    overdue: false,
    level: '',
    mine: false,
    page: 1,
  })
  void load()
}

onMounted(() => {
  void load()
})

// ------------------------------------------------------------------ 流转

const transitionVisible = ref(false)
const transitioning = ref<Remediation | null>(null)
/** 行内按钮点了哪个目标就先替用户选好；从「详情」进入时留空取第一个可选 */
const transitionPreset = ref<RemediationStatus | ''>('')

/**
 * 行内流转。
 *
 * 目标直接来自该行视图里的 `transitions`（后端投影）。列表不是详情，
 * 但两者返回的是同一个结构的 `Remediation`，因此这里不需要任何额外请求
 * 就能给出**准确**的下一步选项。
 */
function openTransition(row: Remediation, preset: RemediationStatus | '' = '') {
  transitioning.value = row
  transitionPreset.value = preset
  transitionVisible.value = true
}

async function handleTransitioned() {
  await load()
}

// ------------------------------------------------------------------ 删除

/**
 * 删除。
 *
 * 只有「待处理」且从未流转过的单子能删，第二条只有后端知道
 * （它看 `action='transition'` 的记录数）。所以确认框里把规则讲清楚，
 * 被拒绝时直接展示后端的文案——那句话里有替代动作（改成「风险接受」）。
 */
async function handleDelete(row: Remediation) {
  try {
    await ElMessageBox.confirm(
      `确定删除整改单「${row.title}」吗？删除后不可恢复。\n\n` +
        '只有「待处理」且从未流转过的单子可以删除。如果这张单子已经有人经手过，' +
        '它属于工作记录，应当流转为「风险接受」并写明理由，而不是删掉。',
      '删除整改单',
      {
        type: 'warning',
        confirmButtonText: '删除',
        cancelButtonText: '取消',
        confirmButtonClass: 'el-button--danger',
      },
    )
  } catch {
    return
  }

  try {
    await deleteRemediation(row.id)
    ElMessage.success('已删除')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '删除失败')
  }
}

// ------------------------------------------------------------------ 批量建单

const batchVisible = ref(false)

function openBatch() {
  batchVisible.value = true
}

async function handleBatchDone() {
  await load()
}

// ------------------------------------------------------------------ 展示辅助

function asRemediation(row: TableRow): Remediation {
  return asRow<Remediation>(row)
}

function openDetail(row: Remediation) {
  void router.push({ name: 'remediation-detail', params: { id: String(row.id) } })
}

/** 已闭环/风险接受的行整行弱化：它们在列表里的作用是「查得到」，不是「等你处理」 */
function isTerminal(row: Remediation): boolean {
  return row.status === 'closed' || row.status === 'accepted'
}
</script>

<template>
  <div class="p-4">
    <!-- ── 筛选 ─────────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-center gap-2">
        <el-input
          v-model="query.keyword"
          placeholder="按标题 / 资产 / IP / 漏洞 / CVE 搜索"
          clearable
          class="!w-72"
          @keyup.enter="handleSearch"
        />

        <el-select v-model="query.status" placeholder="全部状态" clearable class="!w-32">
          <el-option
            v-for="status in REMEDIATION_STATUS_ORDER"
            :key="status"
            :label="REMEDIATION_STATUS_LABELS[status]"
            :value="status"
          />
        </el-select>

        <el-select v-model="query.level" placeholder="全部等级" clearable class="!w-28">
          <el-option
            v-for="level in RISK_LEVEL_ORDER"
            :key="level"
            :label="RISK_LEVEL_LABELS[level]"
            :value="level"
          />
        </el-select>

        <el-checkbox v-model="query.active" :disabled="Boolean(query.status)">
          只看未闭环
        </el-checkbox>
        <el-checkbox v-model="query.overdue">只看逾期</el-checkbox>
        <el-checkbox v-model="query.mine">只看我负责的</el-checkbox>

        <el-button type="primary" :icon="Search" @click="handleSearch">查询</el-button>
        <el-button :icon="Refresh" @click="handleReset">重置</el-button>
      </div>

      <div class="mt-2 text-xs text-gray-400">
        列表按「期限近的靠前、未设期限的排最后」排序——它是一份工作清单，
        回答的是「先动哪一张」，而不是一份按创建时间倒排的时间线。
      </div>
    </div>

    <!-- ── 列表 ─────────────────────────────────────────────────── -->
    <div class="app-panel">
      <div class="mb-4 flex items-center gap-2">
        <span class="text-sm text-gray-500">共 {{ total }} 张整改单</span>
        <div v-if="canWrite" class="ml-auto">
          <el-button type="primary" :icon="Plus" @click="openBatch">批量建单</el-button>
        </div>
      </div>

      <el-table
        v-loading="loading"
        :data="rows"
        stripe
        style="width: 100%"
        :row-class-name="
          ({ row }) => (isTerminal(asRemediation(row)) ? 'opacity-60' : '')
        "
      >
        <el-table-column label="整改单" min-width="240" fixed show-overflow-tooltip>
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(asRemediation(row))">
              {{ asRemediation(row).title }}
            </el-button>
            <div class="text-xs text-gray-400">
              {{ asRemediation(row).asset_name }}
              <span v-if="asRemediation(row).asset_ip"
                >· {{ asRemediation(row).asset_ip }}</span
              >
            </div>
            <div class="text-xs text-gray-400" :title="asRemediation(row).vuln_title">
              {{ asRemediation(row).vuln_title }}
              <span v-if="asRemediation(row).vuln_cve_ids">
                · {{ asRemediation(row).vuln_cve_ids }}
              </span>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="等级" width="80">
          <template #default="{ row }">
            <el-tag
              size="small"
              :type="RISK_LEVEL_TAG_TYPE[asRemediation(row).risk_level as RiskLevel]"
            >
              {{ RISK_LEVEL_LABELS[asRemediation(row).risk_level as RiskLevel] }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="R" width="70" align="right">
          <template #default="{ row }">
            {{ asRemediation(row).risk_value_r.toFixed(1) }}
          </template>
        </el-table-column>

        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag
              :type="REMEDIATION_STATUS_TAG_TYPE[asRemediation(row).status]"
              size="small"
            >
              {{ REMEDIATION_STATUS_LABELS[asRemediation(row).status] }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="负责人" width="110" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="asRemediation(row).assignee_name">
              {{ asRemediation(row).assignee_name }}
            </span>
            <span v-else class="text-gray-400">未分派</span>
          </template>
        </el-table-column>

        <el-table-column label="期限" width="110">
          <template #default="{ row }">
            <span v-if="asRemediation(row).due_date">{{
              asRemediation(row).due_date
            }}</span>
            <span v-else class="text-gray-400">未设</span>
          </template>
        </el-table-column>

        <el-table-column label="时间态" width="120">
          <template #default="{ row }">
            <el-tag
              :type="remediationTimingTagType(asRemediation(row))"
              size="small"
              effect="plain"
            >
              {{ remediationTimingText(asRemediation(row)) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="最近更新" width="170">
          <template #default="{ row }">
            <div>{{ formatDateTime(asRemediation(row).updated_at) }}</div>
            <div class="text-xs text-gray-400">
              建单人 {{ asRemediation(row).created_by_name || "—" }}
            </div>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <div class="flex">
              <el-button
                link
                type="primary"
                size="small"
                @click="openDetail(asRemediation(row))"
              >
                详情
              </el-button>
              <!--
              流转按钮由该行视图里的 transitions 渲染：终态（已闭环 / 风险接受）
              的 transitions 是空数组，因此**不需要**在这里判状态——判了就等于
              在前端写下第二份状态机。
            -->
              <el-dropdown
                v-if="canWrite && asRemediation(row).transitions.length"
                @command="
                (cmd: unknown) => openTransition(asRemediation(row), cmd as RemediationStatus)
              "
              >
                <el-button link type="primary" size="small">流转</el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item
                      v-for="opt in asRemediation(row).transitions"
                      :key="opt.to_status"
                      :command="opt.to_status"
                    >
                      {{ REMEDIATION_STATUS_LABELS[opt.to_status] }}
                      <span v-if="opt.note_required" class="ml-1 text-xs text-gray-400"
                        >需说明</span
                      >
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
              <el-button
                v-if="canWrite && asRemediation(row).status === 'pending'"
                link
                type="danger"
                size="small"
                @click="handleDelete(asRemediation(row))"
              >
                删除
              </el-button>
            </div>
          </template>
        </el-table-column>

        <template #empty>
          <div class="py-8 text-sm text-gray-400">
            没有符合条件的整改单。可以从评估结果页对高风险的条目建单，
            或用右上角的「批量建单」按评估任务一次性建出来。
          </div>
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

    <TransitionDialog
      v-model="transitionVisible"
      :remediation="transitioning"
      :preset="transitionPreset"
      @done="handleTransitioned"
    />
    <BatchCreateDialog v-model="batchVisible" @done="handleBatchDone" />
  </div>
</template>
