<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import type { UploadInstance } from 'element-plus'
import { Download, UploadFilled } from '@element-plus/icons-vue'

import { commitAssetImport, downloadImportTemplate, previewAssetImport } from '@/api/assets'
import type { AssetImportPreview, AssetImportResult } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { saveBlob } from '@/utils/download'

/**
 * 资产批量导入向导。
 *
 * 三个阶段：选文件 → 预览 → 完成。预览与确认**都要上传同一份文件**——
 * 服务端不持有导入会话状态（见契约里 commit 的说明），因此 `file` 必须
 * 一直留在内存里，用户在后两个阶段之间来回切换时不必重新选。
 */
const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  /** 导入成功。父组件据此刷新台账 —— 单条新增靠列表自己刷新就够了，
   *  一次导入可能进来 500 条，父组件需要知道「该重新拉数据了」 */
  imported: [result: AssetImportResult]
}>()

type Stage = 'select' | 'preview' | 'done'

const stage = ref<Stage>('select')
const busy = ref(false)

const uploadRef = ref<UploadInstance | null>(null)

/** 待导入的文件。选完之后一直留着，切换 create_missing_groups 时重新上传它。 */
const file = ref<File | null>(null)

const createMissingGroups = ref(false)
const preview = ref<AssetImportPreview | null>(null)
const result = ref<AssetImportResult | null>(null)

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

/** 关掉对话框时把状态清干净：留着的文件会在下一次打开时让人以为已经选好了 */
watch(visible, (open) => {
  if (!open) reset()
})

function reset() {
  stage.value = 'select'
  busy.value = false
  file.value = null
  createMissingGroups.value = false
  preview.value = null
  result.value = null
  uploadRef.value?.clearFiles()
}

// ------------------------------------------------------------------ 模板

const templateDownloading = ref(false)

async function handleDownloadTemplate() {
  templateDownloading.value = true
  try {
    const { blob, fileName } = await downloadImportTemplate()
    saveBlob(blob, fileName)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '下载模板失败')
  } finally {
    templateDownloading.value = false
  }
}

// ------------------------------------------------------------------ 选文件

function handleFileChange(uploadFile: { raw?: File }) {
  const raw = uploadFile.raw
  if (!raw) return

  file.value = raw
  // 立刻清掉 el-upload 的列表：它会把文件名展示一遍，而我们下面有更完整的
  // 摘要卡片。留着的话同一个文件第二次选择不会触发 change 事件。
  uploadRef.value?.clearFiles()
  void runPreview()
}

// ------------------------------------------------------------------ 预览

async function runPreview() {
  if (!file.value) return

  busy.value = true
  try {
    preview.value = await previewAssetImport(file.value, createMissingGroups.value)
    stage.value = 'preview'
  } catch (err) {
    // 文件级失败（缺列、格式不对、超过行数/体积上限）在这里落地。
    // 这类问题与「某几行填错了」不同，没有可渲染的错误表，只能弹提示。
    ElMessage.error(err instanceof HttpError ? err.message : '解析文件失败')
    preview.value = null
  } finally {
    busy.value = false
  }
}

/**
 * 切换「自动创建缺失分组」时重新预览。
 *
 * 不在前端自己把错误行分类：哪些行会因为开关翻转而从「错误」变成
 * 「待创建」，取决于系统里真实存在哪些组，那是后端的事实。
 * 重新问一次后端，界面上的每一个计数才与服务器看到的一致。
 */
function handleToggleMissingGroups() {
  void runPreview()
}

// ------------------------------------------------------------------ 确认导入

/**
 * 阻止提交的原因。空串表示可以提交。
 *
 * 三种情况都必须拦下 —— 服务端承诺导入是原子的（任一行不合格则一条都不写），
 * 放过去只会得到一个 409，而用户已经为这次点击等了一轮上传。
 * 提前说清楚「还差什么」，比事后解释「为什么没导进去」有效得多。
 */
const blockReason = computed(() => {
  const p = preview.value
  if (!p) return '请先选择文件'
  if (p.missing_columns.length > 0) {
    return `文件缺少必需列：${p.missing_columns.join('、')}`
  }
  if (p.error_rows > 0) return `还有 ${p.error_rows} 行不合格，请修正后重新上传`
  if (p.unmatched_groups.length > 0) {
    return `有 ${p.unmatched_groups.length} 个资产组在系统中不存在，请勾选「自动创建缺失分组」或先在台账里建好`
  }
  if (p.valid_rows === 0) return '文件中没有可导入的数据行'
  return ''
})

const canCommit = computed(() => blockReason.value === '')

async function handleCommit() {
  if (!file.value || !canCommit.value) return

  busy.value = true
  try {
    const outcome = await commitAssetImport(file.value, createMissingGroups.value)

    if (!outcome.ok) {
      // 走到了这里说明「预览通过、提交却没通过」。两个阶段的解析与校验
      // 是同一段代码，所以差异只可能来自服务端状态的变化（例如刚才
      // 另一台机器占用了同一个资产编号）。把新的预览结果换上，
      // 让用户看到的是**现在**的真实情况，而不是几分钟前的快照。
      preview.value = outcome.preview
      ElMessage.warning('校验发现了新的问题，可能期间台账发生了变化，请查看下方错误清单')
      return
    }

    result.value = outcome.result
    stage.value = 'done'
    emit('imported', outcome.result)
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '导入失败')
  } finally {
    busy.value = false
  }
}

// ------------------------------------------------------------------ 展示辅助

/** 格式名称：契约里是 xlsx / csv 两个枚举值 */
function formatLabel(format: string) {
  return format === 'xlsx' ? 'Excel (.xlsx)' : 'CSV (.csv)'
}
</script>

<template>
  <el-dialog
    v-model="visible"
    title="批量导入资产"
    width="880px"
    :close-on-click-modal="false"
    destroy-on-close
  >
    <!-- ── ① 选文件 ────────────────────────────────────────────── -->
    <template v-if="stage === 'select'">
      <el-alert
        class="mb-4"
        type="info"
        :closable="false"
        show-icon
        title="先下载模板，按模板列填好后再上传"
        description="模板的表头就是校验依据，改列名会让整份文件对不上。一次最多 5000 行、10 MB。"
      />

      <div class="mb-4 flex gap-2">
        <el-button :icon="Download" :loading="templateDownloading" @click="handleDownloadTemplate">
          下载导入模板
        </el-button>
      </div>

      <el-upload
        ref="uploadRef"
        drag
        :auto-upload="false"
        :show-file-list="false"
        :limit="1"
        accept=".xlsx,.csv"
        :on-change="handleFileChange"
      >
        <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
        <div class="el-upload__text">把 .xlsx 或 .csv 拖到这里，或<em>点击选择文件</em></div>
        <template #tip>
          <div class="el-upload__tip">
            格式按文件内容判断，不按扩展名 —— 把 xlsx 改名成 .csv 也能正确识别
          </div>
        </template>
      </el-upload>
    </template>

    <!-- ── ② 预览 ──────────────────────────────────────────────── -->
    <template v-else-if="stage === 'preview' && preview">
      <el-descriptions :column="4" border class="mb-4">
        <el-descriptions-item label="文件" :span="2">
          {{ preview.file_name }}
        </el-descriptions-item>
        <el-descriptions-item label="格式">{{ formatLabel(preview.format) }}</el-descriptions-item>
        <el-descriptions-item label="数据行数">{{ preview.total_rows }}</el-descriptions-item>
        <el-descriptions-item label="可导入">
          <span class="font-semibold text-green-600">{{ preview.valid_rows }} 行</span>
        </el-descriptions-item>
        <el-descriptions-item label="不合格">
          <span :class="preview.error_rows > 0 ? 'font-semibold text-red-600' : ''">
            {{ preview.error_rows }} 行
          </span>
        </el-descriptions-item>
        <el-descriptions-item label="待创建的资产组" :span="2">
          {{ preview.groups_to_create.length }} 个
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
        description="请用模板重新整理表头后再上传。缺列时其它校验结果没有参考价值。"
      />

      <el-alert
        v-if="preview.unmatched_groups.length"
        class="mb-4"
        type="warning"
        :closable="false"
        show-icon
        :title="`有 ${preview.unmatched_groups.length} 个资产组在系统中不存在`"
      >
        <div class="text-xs">{{ preview.unmatched_groups.join('、') }}</div>
      </el-alert>

      <el-alert
        v-if="preview.groups_to_create.length"
        class="mb-4"
        type="success"
        :closable="false"
        show-icon
        :title="`导入时会新建 ${preview.groups_to_create.length} 个资产组（含中间层级）`"
      >
        <div class="text-xs">{{ preview.groups_to_create.join('、') }}</div>
      </el-alert>

      <div class="mb-4 flex items-center gap-3">
        <el-checkbox
          :model-value="createMissingGroups"
          :disabled="busy"
          @change="
            (value: boolean | string | number) => {
              createMissingGroups = Boolean(value)
              handleToggleMissingGroups()
            }
          "
        >
          自动创建文件中引用但系统中不存在的资产组
        </el-checkbox>
        <el-button link type="primary" :disabled="busy" @click="reset">重新选择文件</el-button>
      </div>

      <template v-if="preview.errors.length">
        <div class="mb-2 text-sm font-semibold">
          错误明细（{{ preview.errors.length }} 条）
          <span v-if="preview.truncated_errors" class="ml-2 text-xs font-normal text-gray-500">
            仅列出前 {{ preview.errors.length }} 条，共 {{ preview.error_rows }} 条
          </span>
        </div>

        <!-- 行号是**源文件里的行号**（含表头、从 1 开始），
             用户打开 Excel 直接跳过去就能改，不需要自己换算 -->
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

    <!-- ── ③ 完成 ──────────────────────────────────────────────── -->
    <template v-else-if="stage === 'done' && result">
      <el-result icon="success" title="导入完成">
        <template #sub-title>
          <div>
            已写入 <span class="font-semibold">{{ result.imported }}</span> 条资产
            <template v-if="result.created_groups > 0">
              ，并新建了 <span class="font-semibold">{{ result.created_groups }}</span> 个资产组
            </template>
          </div>
        </template>
      </el-result>
    </template>

    <template #footer>
      <template v-if="stage === 'select'">
        <el-button :disabled="busy" @click="visible = false">取消</el-button>
      </template>

      <template v-else-if="stage === 'preview'">
        <el-button :disabled="busy" @click="reset">重新选择文件</el-button>
        <el-tooltip :disabled="canCommit" :content="blockReason" placement="top">
          <span>
            <el-button type="primary" :loading="busy" :disabled="!canCommit" @click="handleCommit">
              确认导入{{ preview && preview.valid_rows ? `（${preview.valid_rows} 行）` : '' }}
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
