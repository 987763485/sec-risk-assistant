<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'

import { commitParse, previewParse } from '@/api/files'
import type { ScanFile, VulnParsePreview, VulnParseResult } from '@/api/endpoints'
import { FILE_FORMAT_LABELS } from '@/api/files'
import { HttpError } from '@/api/http'

/**
 * 漏洞解析向导。
 *
 * 与资产导入向导（AssetImportDialog）的区别：文件**已经上传**，不存在
 * 「选文件」阶段——向导从预览直接开始。预览与 commit 都只带 file_id，
 * 各自**重新解析一遍**：服务端不持有会话状态，预览后台账可能已变
 * （比如用户补了几条资产），commit 的数字才是最终事实。
 */
const props = defineProps<{ modelValue: boolean; file: ScanFile | null }>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  /** 解析成功。父组件据此刷新文件列表（vuln_count、parse_status 都变了） */
  committed: [result: VulnParseResult]
}>()

type Stage = 'preview' | 'done'

const stage = ref<Stage>('preview')
const busy = ref(false)

const preview = ref<VulnParsePreview | null>(null)
const result = ref<VulnParseResult | null>(null)

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

/** 打开即预览；关闭时清状态，避免下次打开闪现上一次的结果 */
watch(visible, (open) => {
  if (open) {
    stage.value = 'preview'
    preview.value = null
    result.value = null
    void runPreview()
  } else {
    busy.value = false
  }
})

async function runPreview() {
  if (!props.file) return

  busy.value = true
  try {
    preview.value = await previewParse(props.file.id)
  } catch (err) {
    // 文件级失败（格式认不出、0 条漏洞、行数超限）在这里落地。
    ElMessage.error(err instanceof HttpError ? err.message : '解析文件失败')
    visible.value = false
  } finally {
    busy.value = false
  }
}

/**
 * 阻止提交的原因。空串表示可以提交。
 *
 * 服务端承诺 commit 是原子的（任一行不合格则一条不写），放过去只会
 * 得到一个 409。提前说清楚「还差什么」，比事后解释「为什么没导进去」
 * 有效得多。未匹配的 IP **不阻塞**——「先传报告、后补资产」是正常顺序。
 */
const blockReason = computed(() => {
  const p = preview.value
  if (!p) return '正在解析，请稍候'
  if (p.missing_columns.length > 0) {
    return `文件缺少必需列：${p.missing_columns.join('、')}`
  }
  if (p.error_rows > 0) return `还有 ${p.error_rows} 行不合格，请修正后重新上传文件`
  if (p.total === 0) return '文件中没有解析出漏洞'
  return ''
})

const canCommit = computed(() => blockReason.value === '')

async function handleCommit() {
  if (!props.file || !canCommit.value) return

  busy.value = true
  try {
    const outcome = await commitParse(props.file.id)

    if (!outcome.ok) {
      // 「预览通过、提交却没通过」：两个阶段各自重新解析，差异只可能
      // 来自服务端状态的变化。换上新的预览结果，让用户看到的是
      // **现在**的真实情况，而不是几分钟前的快照。
      preview.value = outcome.preview
      ElMessage.warning('校验发现了新的问题，请查看下方错误清单')
      return
    }

    result.value = outcome.result
    stage.value = 'done'
    emit('committed', outcome.result)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '解析入库失败')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <el-dialog
    v-model="visible"
    title="解析扫描报告"
    width="880px"
    :close-on-click-modal="false"
    destroy-on-close
  >
    <!-- ── ① 预览 ──────────────────────────────────────────────── -->
    <template v-if="stage === 'preview' && preview">
      <el-descriptions :column="4" border class="mb-4">
        <el-descriptions-item label="文件" :span="2">
          {{ preview.file_name }}
        </el-descriptions-item>
        <el-descriptions-item label="格式">
          {{ FILE_FORMAT_LABELS[preview.format] ?? preview.format }}
        </el-descriptions-item>
        <el-descriptions-item label="漏洞条数">
          <span class="font-semibold">{{ preview.total }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="可关联资产" :span="2">
          <span class="font-semibold text-green-600">{{ preview.matched_count }} 条</span>
          （按主机 IP 精确匹配）
        </el-descriptions-item>
        <el-descriptions-item label="行级错误" :span="2">
          <span :class="preview.error_rows > 0 ? 'font-semibold text-red-600' : ''">
            {{ preview.error_rows }} 行
          </span>
        </el-descriptions-item>
      </el-descriptions>

      <!-- 缺列时不必再渲染逐行错误：按列取值已经对不上，那些错误全是噪音 -->
      <el-alert
        v-if="preview.missing_columns.length"
        class="mb-4"
        type="error"
        :closable="false"
        show-icon
        :title="`文件缺少必需列：${preview.missing_columns.join('、')}`"
        description="请用「下载导入模板」重新整理表头后再上传。缺列时其它校验结果没有参考价值。"
      />

      <!-- 未匹配 IP 只是提示不是错误：先传报告、后补资产是正常顺序，
           这些漏洞入库后保持「未关联」，可随时在漏洞清单里手动补挂 -->
      <el-alert
        v-if="preview.unmatched_ips.length"
        class="mb-4"
        type="warning"
        :closable="false"
        show-icon
        :title="`有 ${preview.unmatched_ips.length} 个主机 IP 在资产台账中不存在，对应漏洞入库后保持「未关联」`"
      >
        <div class="text-xs">
          {{ preview.unmatched_ips.join('、') }}
        </div>
      </el-alert>

      <div class="mb-4">
        <el-button link type="primary" :disabled="busy" @click="visible = false">
          先去补资产，稍后再解析
        </el-button>
      </div>

      <template v-if="preview.errors.length">
        <div class="mb-2 text-sm font-semibold">
          错误明细（{{ preview.errors.length }} 条）
          <span
            v-if="preview.error_rows > preview.errors.length"
            class="ml-2 text-xs font-normal text-gray-500"
          >
            仅列出前 {{ preview.errors.length }} 条，共 {{ preview.error_rows }} 条
          </span>
        </div>

        <!-- 行号是源文件里的行号（含表头、从 1 开始），打开 Excel 直接跳过去就能改 -->
        <el-table :data="preview.errors" max-height="320" stripe size="small">
          <el-table-column label="行号" width="80" fixed>
            <template #default="{ row }">
              <span class="font-semibold">{{ row.row }}</span>
            </template>
          </el-table-column>
          <el-table-column label="列" width="130">
            <template #default="{ row }">
              <span v-if="row.column">{{ row.column }}</span>
              <span v-else class="text-gray-400">整行</span>
            </template>
          </el-table-column>
          <el-table-column label="原值" min-width="150" show-overflow-tooltip>
            <template #default="{ row }">
              <span v-if="row.value">{{ row.value }}</span>
              <span v-else class="text-gray-400">（空）</span>
            </template>
          </el-table-column>
          <el-table-column prop="message" label="原因" min-width="300" />
          <template #empty>
            <el-empty description="没有不合格的行" />
          </template>
        </el-table>
      </template>
    </template>

    <!-- ── ② 完成 ──────────────────────────────────────────────── -->
    <template v-else-if="stage === 'done' && result">
      <el-result icon="success" title="解析完成">
        <template #sub-title>
          <div>
            已入库 <span class="font-semibold">{{ result.imported }}</span> 条漏洞
            <template v-if="result.linked_auto > 0">
              ，其中 <span class="font-semibold">{{ result.linked_auto }}</span> 条 按主机 IP
              自动关联了资产
            </template>
            <template v-if="result.unmatched_ips > 0">
              ；<span class="font-semibold">{{ result.unmatched_ips }}</span> 个 IP
              没有匹配到资产，对应漏洞可在漏洞清单里手动补挂
            </template>
          </div>
        </template>
      </el-result>
    </template>

    <template #footer>
      <template v-if="stage === 'preview'">
        <el-button :disabled="busy" @click="visible = false">取消</el-button>
        <el-tooltip :disabled="canCommit" :content="blockReason" placement="top">
          <span>
            <el-button type="primary" :loading="busy" :disabled="!canCommit" @click="handleCommit">
              确认解析{{ preview ? `（${preview.total} 条）` : '' }}
            </el-button>
          </span>
        </el-tooltip>
      </template>

      <template v-else>
        <el-button type="primary" @click="visible = false">完成</el-button>
      </template>
    </template>
  </el-dialog>
</template>
