#!/usr/bin/env bash
# ============================================================================
# P0 守门验证 —— docgen 服务最小渲染验证
#
# 验证什么：
#   把一份刻意构造的中文评估报告（含 40 行跨页表格、合并单元格、
#   全角/连续空格、中西文混排）发给 docgen，回收 docx，
#   然后**解包检查 OOXML 内部 XML**，逐项断言最容易静默失败的那几个点。
#
#   为什么检查 XML 而不是只看能否下载：
#   OpenXML 的失败几乎都是「编译通过、运行不报错、样式就是不生效」，
#   只有看到内部 XML 才能确定 —— 这也是排查 docx 问题最快的手工手段
#   （.docx 改名 .zip 直接看 XML），这里把它自动化了。
#
# 用法： bash scripts/verify-docgen.sh
# ============================================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="/Users/chunle/.workbuddy/binaries/python/versions/3.13.12/bin/python3"
OUT_DIR="${ROOT}/.verify"
SAMPLE="${ROOT}/services/docgen/samples/sample-request.json"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; RESET=$'\033[0m'

log()  { printf '%s\n' "${CYAN}[docgen]${RESET} $*"; }
ok()   { printf '%s\n' "${GREEN}✔${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW}!${RESET} $*"; }
err()  { printf '%s\n' "${RED}✖${RESET} $*" >&2; }

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------- 前置检查
command -v docker >/dev/null || { err "未安装 docker"; exit 1; }
docker info >/dev/null 2>&1 || { err "Docker 守护进程未运行"; exit 1; }
[[ -f "$SAMPLE" ]] || { err "样例不存在：$SAMPLE"; exit 1; }

# ---------------------------------------------------------------- 启动服务
log "启动 docgen 容器…"
export BUILDX_CONFIG="${ROOT}/.buildx"
docker compose up -d --build docgen

log "等待 docgen 就绪…"
for i in $(seq 1 60); do
  if docker compose exec -T docgen curl -fsS http://127.0.0.1:8090/health >/dev/null 2>&1; then
    ok "docgen 已就绪（${i}s）"
    break
  fi
  [[ $i -eq 60 ]] && { err "docgen 就绪超时"; docker compose logs --tail 40 docgen; exit 1; }
  sleep 1
done

# ---------------------------------------------------------------- 渲染
log "提交渲染请求…"
HTTP_CODE=$(docker compose exec -T docgen sh -c '
  curl -sS -o /tmp/render.docx -w "%{http_code}" \
    -H "X-Internal-Secret: ${DOCGEN_INTERNAL_SECRET}" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    http://127.0.0.1:8090/api/v1/render/docx
' < "$SAMPLE")

if [[ "$HTTP_CODE" != "200" ]]; then
  err "渲染失败，HTTP ${HTTP_CODE}，容器日志："
  docker compose logs --tail 40 docgen
  exit 1
fi
ok "HTTP 200"

DOCX="$OUT_DIR/report.docx"
docker compose cp docgen:/tmp/render.docx "$DOCX" >/dev/null
# ⚠️ 变量后若紧跟 CJK 字符，UTF-8 locale 下 bash 会把它并进变量名，
#    导致 "DOCX（: unbound variable"。所以非 ASCII 字符前必须用 ${VAR} 花括号。
ok "已取回 docx：${DOCX}（$(du -h "$DOCX" | cut -f1)）"

# ---------------------------------------------------------------- 断言
log "解包并检查 OOXML 内部 XML…"

"$PYTHON" - "$DOCX" <<'PYEOF'
import sys, zipfile, pathlib, re
import xml.etree.ElementTree as ET

W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'

path = pathlib.Path(sys.argv[1])
fails, passes = [], []

def check(ok, name, detail=''):
    (passes if ok else fails).append((name, detail))
    # 不用 ANSI 色码：日志被重定向或截断时容易残留 "2m" 之类的乱码
    mark = '\u2714' if ok else '\u2716'
    print(f'  {mark} {name}' + (f'\n      {detail}' if detail and not ok else ''))

try:
    z = zipfile.ZipFile(path)
except zipfile.BadZipFile:
    print('\u2716 不是合法的 zip/docx 文件')
    sys.exit(1)

names = set(z.namelist())

doc = z.read('word/document.xml').decode('utf-8')
styles = z.read('word/styles.xml').decode('utf-8')

# ── 1. 中文文本完整保留（无乱码、未被替换）
title_ok = '示例信息系统网络安全风险评估报告' in doc
check(title_ok, '中文标题完整写入 document.xml')

# ── 2. 样式已注册进 StyleDefinitionsPart（未注册 → 引用静默失效）
registered = all(
    f'w:styleId="{sid}"' in styles
    for sid in ['SecRiskReportTitle', 'SecRiskHeading1', 'SecRiskBodyText',
                'SecRiskTableHeaderCell', 'SecRiskTableCell']
)
check(registered, '全部自定义样式已注册到 styles.xml',
      '引用未注册的 StyleId 编译运行都不报错，但样式不生效')

# ── 3. 中文字体必须用英文名（写「宋体」不会报错但中文样式不生效）
east_asia_ok = 'w:eastAsia="SimSun"' in styles
chinese_font_leak = any(name in styles for name in ['宋体', '黑体', '微软雅黑'])
check(east_asia_ok and not chinese_font_leak,
      'EastAsia 字体使用英文名 SimSun，且未出现中文字体名',
      f'eastAsia="SimSun" 存在: {east_asia_ok}，中文字体名泄漏: {chinese_font_leak}')

# ── 4. 字号单位是 half-point：22pt 标题必须写成 44
half_point_ok = re.search(r'w:sz w:val="44"', styles) is not None
check(half_point_ok, '字号使用 half-point（22pt → 44）',
      '写 16 会让所有文字小一半')

# ── 5. 表格跨页表头重复（w:tblHeader）
tbl_header_ok = 'w:tblHeader' in doc
check(tbl_header_ok, '表头设置了跨页重复（w:tblHeader）',
      '长表格翻页后看不到列名，报告不可读')

# ── 6. 单行不跨页断开（w:cantSplit）
cant_split_ok = 'w:cantSplit' in doc
check(cant_split_ok, '表格行设置了不跨页断开（w:cantSplit）')

# ── 7. 横向合并单元格（w:gridSpan）—— 样例中合并 3 列
grid_span_ok = re.search(r'<w:gridSpan w:val="3"\s*/>', doc) is not None
check(grid_span_ok, '合并单元格生效（w:gridSpan val=3）',
      '风险矩阵与判定说明依赖横向合并，缺失则版式错乱')

# ── 8. 中文正文首行缩进 2 字符（firstLineChars，非 firstLine）
indent_ok = 'w:firstLineChars="200"' in doc
check(indent_ok, '正文首行缩进 2 字符（w:firstLineChars=200）',
      '用 firstLine 固定 twip 的话，字号变化时缩进不会跟随')

# ── 9. 连续空格与全角空格被保留
# ⚠️ OOXML 里该属性是 xml:space（xml: 前缀），不是 w:space —— 别写错
preserve_ok = 'xml:space="preserve"' in doc
fullwidth_ok = '\u3000' in doc
check(preserve_ok and fullwidth_ok, '空格保留（xml:space=preserve + 全角空格未丢失）',
      f'preserve 存在: {preserve_ok}，全角空格存在: {fullwidth_ok}')

# ── 10. 表格边框用的是 TableBorders 而非 ParagraphBorders
borders_ok = 'w:tblBorders' in doc
check(borders_ok, '表格边框正确使用 w:tblBorders',
      'ParagraphBorders 与 TableBorders 是不同的类，混用编译通过但无效果')

# ── 11. 页脚含页码域
footer_parts = [n for n in names if re.match(r'word/footer\d+\.xml$', n)]
page_field_ok = False
for n in footer_parts:
    if 'PAGE' in z.read(n).decode('utf-8'):
        page_field_ok = True
        break
check(page_field_ok, f'页脚包含页码域（PAGE）— {len(footer_parts)} 个页脚部件',
      '直接写文本不会自动更新页码')

# ── 12. w:sectPr 必须是 w:body 的最后一个子元素
root = ET.fromstring(doc)
body = root.find(f'{W}body')
sect_pr_ok = body is not None and len(body) > 0 and body[-1].tag == f'{W}sectPr'
check(sect_pr_ok, 'w:sectPr 是 w:body 的最后一个子元素',
      '顺序错误 Word 会判定文档结构非法而拒绝打开')

# ── 13. 页面为 A4 纵向
pgsz = body.find(f'{W}sectPr/{W}pgSz') if sect_pr_ok else None
a4_ok = pgsz is not None and pgsz.get(f'{W}w') == '11906' and pgsz.get(f'{W}h') == '16838'
check(a4_ok, '页面为 A4（11906 × 16838 twip）')

# ── 14. [Content_Types].xml 声明了主文档部件
ct_ok = any('wordprocessingml.document.main' in z.read(n).decode('utf-8')
            for n in names if n == '[Content_Types].xml')
check(ct_ok, '[Content_Types].xml 已声明主文档部件')

# ── 15. 分页符（P5 封面 / 章节另起一页）
page_break_ok = 'w:type="page"' in doc
check(page_break_ok, '分页符存在（w:br w:type="page"）',
      '缺了它封面、目录会与正文挤在同一页')
page_break_count = doc.count('w:type="page"')
# 精确断言而不是「≥ N」：样例结构是固定的（封面 1 + 目录 1 + 三个章节各 1），
# 数量变了说明渲染逻辑或样例动了，此时应当让断言失败并人工确认。
check(page_break_count == 5, f'分页符数量精确匹配（{page_break_count} 处 = 封面 1 + 目录 1 + 章节 3）',
      '第一节刻意不设 pageBreakBefore：目录后已有分页符，再设会多出一整页空白')

# ── 16. TOC 域（P5 目录页）
#
# 域必须是完整四段：begin → instrText → separate → 域结果 → end。
# 缺 separate 时 Word 把它当成「未计算完的域」，界面上什么都看不到，且不报错。
instr_texts = re.findall(r'<w:instrText[^>]*>(.*?)</w:instrText>', doc, flags=re.S)
toc_field_ok = any('TOC' in t for t in instr_texts)
separate_ok = 'w:fldCharType="separate"' in doc
check(toc_field_ok and separate_ok,
      f'TOC 域完整写入（{len(instr_texts)} 个域代码，separate 存在: {separate_ok}）',
      '缺 TOC 域则 Word 里没有目录；缺 separate 则目录一片空白且不报错')

# ── 17. 标题样式必须声明大纲级别
#
# TOC \o "1-2" 是按**大纲级别**收集段落的，不是按样式名。
# 标题样式没有 w:outlineLvl 时，更新域之后目录仍然是空的 —— 静默失败。
def style_block(sid):
    m = re.search(r'<w:style [^>]*w:styleId="%s".*?</w:style>' % re.escape(sid),
                  styles, flags=re.S)
    return m.group(0) if m else ''

h1_block = style_block('SecRiskHeading1')
h2_block = style_block('SecRiskHeading2')
outline_ok = (re.search(r'<w:outlineLvl[^>]*w:val="0"', h1_block) is not None
              and re.search(r'<w:outlineLvl[^>]*w:val="1"', h2_block) is not None)
check(outline_ok, '标题样式声明了大纲级别（Heading1 → 0、Heading2 → 1）',
      'TOC 按大纲级别收集标题；缺了它更新域后目录全空，且不报任何错')

# ── 18. 「目录」标题样式不带大纲级别
#
# 带了大纲级别的话，「目录」二字会把自己也列进目录，形成自引用。
toc_title_block = style_block('SecRiskTocTitle')
toc_registered = 'w:styleId="SecRiskTocTitle"' in styles
toc_no_outline = toc_title_block != '' and 'outlineLvl' not in toc_title_block
check(toc_registered and toc_no_outline,
      '「目录」标题样式已注册且不含大纲级别（避免自引用）',
      f'已注册: {toc_registered}，不含 outlineLvl: {toc_no_outline}')

print()
print(f"  通过 {len(passes)}/{len(passes) + len(fails)} 项")

if fails:
    print('\ndocgen 渲染验证未通过 \u2716')
    sys.exit(1)

print('\ndocgen 最小渲染验证全部通过 \u2705')
PYEOF
STATUS=$?

if [[ "$STATUS" -eq 0 ]]; then
  echo ""
  ok "产物位置：$DOCX"
  warn "请用 Word / WPS 打开上述文件做最终人工确认（中文、样式、合并单元格、跨页表头）"
fi

exit "$STATUS"
