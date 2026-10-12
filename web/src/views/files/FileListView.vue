<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, type UploadInstance } from 'element-plus'
import { Refresh, Search, Upload } from '@element-plus/icons-vue'

import {
  deleteScanFile,
  downloadScanFile,
  FILE_FORMAT_LABELS,
  listScanFiles,
  PARSE_STATUS_LABELS,
  PARSE_STATUS_TAG_TYPE,
  uploadScanFile,
} from '@/api/files'
import type { ScanFile, ScanParseStatus } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { saveBlob } from '@/utils/download'
import { formatDateTime } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'
import ParseWizardDialog from './components/ParseWizardDialog.vue'

const auth = useAuthStore()

/**
 * 写操作按 file:write 权限显隐。
 *
 * ⚠️ 这只是体验层：真正的拦阻在后端路由的 RequirePermission 上。
 * 隐藏按钮是为了不让人点进去再吃一个 403，不是安全边界。
 */
const canWrite = computed(() => auth.can('file:write'))

const STATUS_OPTIONS: ScanParseStatus[] = ['unparsed', 'parsed', 'failed']

// ------------------------------------------------------------------ 列表

const loading = ref(false)
const rows = ref<ScanFile[]>([])
const total = ref(0)

const query = reactive({
  keyword: '',
  parseStatus: '' as ScanParseStatus | '',
  page: 1,
  pageSize: 20,
})

async function load() {
  loading.value = true
  try {
    const page = await listScanFiles({
      page: query.page,
      pageSize: query.pageSize,
      keyword: query.keyword.trim(),
      parse_status: query.parseStatus || undefined,
    })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载文件列表失败')
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
  Object.assign(query, { keyword: '', parseStatus: '', page: 1 })
  void load()
}

onMounted(() => {
  void load()
})

// ------------------------------------------------------------------ 上传

const uploading = ref(false)
const uploadRef = ref<UploadInstance | null>(null)

/**
 * 上传扫描报告。
 *
 * 重复上传同一内容不报错（哈希去重幂等），只在提示里说明「已存在」——
 * 用户拿到的是已有记录，照常可以进入解析，不需要特殊处理。
 */
async function handleUpload(uploadFile: { raw?: File }) {
  const raw = uploadFile.raw
  if (!raw) return

  // 立刻清掉 el-upload 的内部列表：show-file-list 为 false 时它仍在记账，
  // 不清的话第二次选同一个文件不会触发 change 事件
  uploadRef.value?.clearFiles()

  uploading.value = true
  try {
    const result = await uploadScanFile(raw)
    if (result.duplicate) {
      ElMessage.warning(`该文件内容此前已上传过（${result.file.original_name}），已复用已有记录`)
    } else {
      ElMessage.success('上传成功')
    }
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '上传失败')
  } finally {
    uploading.value = false
  }
}

// ------------------------------------------------------------------ 解析

const wizardVisible = ref(false)
const parsingFile = ref<ScanFile | null>(null)

function openParse(row: ScanFile) {
  parsingFile.value = row
  wizardVisible.value = true
}

async function handleCommitted() {
  await load()
}

// ------------------------------------------------------------------ 下载与删除

async function handleDownload(row: ScanFile) {
  try {
    const blob = await downloadScanFile(row)
    saveBlob(blob, row.original_name)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '下载失败')
  }
}

/**
 * 删除扫描文件。
 *
 * `vuln_count > 0` 时默认删除会被后端以 409 `FILE_IN_USE` 拒绝——
 * 前端直接把选择权交给用户：要么只删文件（那是不可能的，有漏洞引用
 * 就删不掉），要么连带删掉全部解析出的漏洞（force）。两条路都说清楚，
 * 让用户带着完整信息做决定，而不是先吃一个 409 再猜该怎么办。
 */
async function handleDelete(row: ScanFile) {
  const cascade = row.vuln_count > 0

  try {
    if (cascade) {
      await ElMessageBox.confirm(
        `文件「${row.original_name}」已解析出 ${row.vuln_count} 条漏洞。\n\n` +
          '直接删除会被系统拒绝。选择「连漏洞一起删」将同时删除该文件解析出的' +
          `全部 ${row.vuln_count} 条漏洞及其资产关联，此操作无法恢复。\n\n` +
          '如果只想清理文件本身，请先保留（漏洞清单里仍可单独管理这些漏洞）。',
        '删除扫描文件',
        {
          type: 'warning',
          confirmButtonText: `连 ${row.vuln_count} 条漏洞一起删`,
          cancelButtonText: '取消',
          distinguishCancelAndClose: true,
        },
      )
    } else {
      await ElMessageBox.confirm(
        `确定删除文件「${row.original_name}」吗？删除后无法恢复。`,
        '删除扫描文件',
        { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
      )
    }
  } catch {
    return
  }

  try {
    await deleteScanFile(row.id, cascade)
    ElMessage.success(cascade ? '文件与关联漏洞已删除' : '已删除')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '删除失败')
  }
}

// ------------------------------------------------------------------ 展示辅助

function asScanFile(row: TableRow): ScanFile {
  return asRow<ScanFile>(row)
}

function parseStatusLabel(row: ScanFile) {
  return PARSE_STATUS_LABELS[row.parse_status]
}

function parseStatusTagType(row: ScanFile) {
  return PARSE_STATUS_TAG_TYPE[row.parse_status]
}

function formatLabel(row: ScanFile) {
  return FILE_FORMAT_LABELS[row.format] ?? row.format
}

/** 只有「还没成功解析过」的文件才显示解析入口；已解析的可以重新解析吗？
 *  可以——重新解析同一文件会产生重复漏洞（模型不做按文件去重），
 *  因此对已解析文件不提供该入口，重解析的正确姿势是删掉后重传。 */
function canParse(row: ScanFile) {
  return row.parse_status !== 'parsed'
}
</script>

<template>
  <div class="app-page">
    <!-- ── 筛选 ─────────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-end gap-3">
        <el-input
          v-model="query.keyword"
          class="w-60"
          placeholder="原始文件名"
          :prefix-icon="Search"
          clearable
          @keyup.enter="handleSearch"
        />

        <el-select v-model="query.parseStatus" class="w-40" placeholder="全部状态" clearable>
          <el-option
            v-for="status in STATUS_OPTIONS"
            :key="status"
            :label="PARSE_STATUS_LABELS[status]"
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
        <span class="text-sm text-gray-500">共 {{ total }} 个文件</span>
        <div v-if="canWrite" class="ml-auto">
          <el-upload
            ref="uploadRef"
            :show-file-list="false"
            :auto-upload="false"
            accept=".nessus,.xml,.xlsx,.csv"
            :on-change="handleUpload"
            :disabled="uploading"
          >
            <el-button type="primary" :icon="Upload" :loading="uploading">上传报告</el-button>
          </el-upload>
        </div>
      </div>

      <el-table v-loading="loading" :data="rows" stripe style="width: 100%">
        <el-table-column label="文件名" min-width="220" fixed show-overflow-tooltip>
          <template #default="{ row }">
            {{ asScanFile(row).original_name }}
          </template>
        </el-table-column>

        <el-table-column label="格式" width="120">
          <template #default="{ row }">{{ formatLabel(asScanFile(row)) }}</template>
        </el-table-column>

        <el-table-column label="大小" width="100">
          <template #default="{ row }">
            {{ (asScanFile(row).size_bytes / 1024).toFixed(1) }} KB
          </template>
        </el-table-column>

        <el-table-column label="解析状态" width="100">
          <template #default="{ row }">
            <el-tag :type="parseStatusTagType(asScanFile(row))" size="small">
              {{ parseStatusLabel(asScanFile(row)) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="漏洞数" width="90">
          <template #default="{ row }">
            <span v-if="asScanFile(row).vuln_count > 0" class="font-semibold">
              {{ asScanFile(row).vuln_count }}
            </span>
            <span v-else class="text-gray-400">—</span>
          </template>
        </el-table-column>

        <el-table-column label="上传人" min-width="110">
          <template #default="{ row }">
            <span v-if="asScanFile(row).uploaded_name">{{ asScanFile(row).uploaded_name }}</span>
            <span v-else class="text-gray-400">—</span>
          </template>
        </el-table-column>

        <el-table-column label="上传时间" width="170">
          <template #default="{ row }">{{ formatDateTime(asScanFile(row).created_at) }}</template>
        </el-table-column>

        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <template v-if="canWrite">
              <el-button
                v-if="canParse(asScanFile(row))"
                link
                type="primary"
                size="small"
                @click="openParse(asScanFile(row))"
              >
                解析
              </el-button>
              <el-button link type="primary" size="small" @click="handleDownload(asScanFile(row))">
                下载
              </el-button>
              <el-button link type="danger" size="small" @click="handleDelete(asScanFile(row))">
                删除
              </el-button>
            </template>
            <template v-else>
              <el-button link type="primary" size="small" @click="handleDownload(asScanFile(row))">
                下载
              </el-button>
              <span class="text-xs text-gray-400">只读</span>
            </template>
          </template>
        </el-table-column>

        <template #empty>
          <el-empty description="还没有上传过扫描报告" />
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
    </div>

    <!-- ── 解析向导 ─────────────────────────────────────────────── -->
    <ParseWizardDialog v-model="wizardVisible" :file="parsingFile" @committed="handleCommitted" />
  </div>
</template>
