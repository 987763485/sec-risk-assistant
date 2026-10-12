#!/usr/bin/env python3
"""
从 docx / xlsx 里把内容读回来（纯标准库：zipfile + xml）。

▍为什么需要它

P5 的验收标志是「Word 与 PDF 中文不乱码、图表正常、版式符合模板」。
「导出成功、文件能打开」证明不了其中任何一条 —— 一个所有汉字都变成方框、
或者表格整体缺失的 docx，同样能下载成功。

要真正证明，必须**解包到 OOXML 内部**把内容读回来。这也是排查这类问题
最快的手工手段（.docx / .xlsx 改名 .zip 直接看 XML），这里把它自动化。

沙箱里 python-docx / openpyxl 都没有，所以自己实现。两种格式都是
「zip + XML」，解析量远小于听起来的样子。

▍子命令

  docx-text      <file.docx>                全部文本（段落 + 表格单元格），一行一个
  docx-tables    <file.docx>                逐表输出：`#TABLE <n>` 后每行一个制表符分隔的行
  docx-structure <file.docx>                结构摘要（key=value），供版式断言
  xlsx-sheets    <file.xlsx>                工作表名，按工作簿内的顺序
  xlsx-tsv       <file.xlsx> <sheet-name>   该表的全部非空行，制表符分隔、按列序补齐
  xlsx-cell      <file.xlsx> <sheet> <ref>… 逐格输出「引用-类型-值」（类型用于「数字没被写成文本」这类断言）

▍为什么用制表符而不是 CSV

调用方是 bash。CSV 会逼着它在 shell 里实现引号与转义的解析规则，而
报告里的文本（资产名、漏洞名）完全可能含逗号和引号。制表符在本项目的
数据里不会出现（名称由用户录入，清洗过；数值与标签都是固定文本），
`IFS=$'\\t' read -r` 一行就能正确切分。
"""

import re
import sys
import zipfile

W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
S_NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
R_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
PKG_REL_NS = 'http://schemas.openxmlformats.org/package/2006/relationships'

# OOXML 里的两个字面量片段。抽成常量只为了避免在 f-string 里嵌引号 ——
# `doc.count('w:type="page"')` 本身没问题，但一旦写成 f-string 就会变成
# 需要转义的 `\"`，读起来很累。
PAGE_BREAK = 'w:type="page"'
TOC_SEPARATE = 'w:fldCharType="separate"'

# ⚠️ 不用 xml.etree 的命名空间查找：OOXML 里同名元素在多个命名空间下出现
#    （w:t 与 a:t、w:r 与 a:r），用 `findall('{ns}t')` 需要处处带着那串长
#    命名空间，可读性很差。这里统一用「去前缀后的本地名」匹配 —— 我们只
#    解析我们自己生成的文档，不存在同一文档里混用两套命名空间的情况。
TAG_RE = re.compile(r'<(?:[A-Za-z0-9_.-]+:)?([A-Za-z0-9_.-]+)((?:\s[^>]*)?)/?>')


def local_tag(tag: str) -> str:
    return tag.split(':', 1)[1] if ':' in tag else tag


def elements(xml: str, name: str):
    """返回 (起始位置, 结束位置, 起始标签原文, 内部 XML) 的四元组列表。

    自己扫标签而不用 xml.etree，是为了在**畸形或超大**的 document.xml 上
    也能给出可用结果：这份 XML 是别人（docgen / excelize）生成的，一旦它
    出了结构问题，etree 会直接抛异常，调用方只能得到「解析失败」四个字，
    而这个脚本存在的意义正是定位「哪一项不对」。
    """
    out = []
    for m in re.finditer(r'<([A-Za-z0-9_.-]+:)?' + re.escape(name) + r'(\s[^>]*?)?(/?)>', xml):
        if m.group(3) == '/':
            out.append((m.start(), m.end(), m.group(0), ''))
            continue
        prefix = m.group(1) or ''
        close = f'</{prefix}{name}>'
        end = xml.find(close, m.end())
        if end < 0:
            continue
        out.append((m.start(), end + len(close), m.group(0), xml[m.end():end]))
    return out


def text_of(xml: str) -> str:
    """拼接一段 XML 里全部 <w:t> / <t> 的文本。

    一个单元格里的文本常常被切成多个 run（换行、格式变化都会切），
    只取第一个 run 会得到半截内容 —— 而这种「半截」看起来很像数据本身
    就少了几个字，非常难判断。
    """
    parts = []
    for m in re.finditer(r'<(?:[A-Za-z0-9_.-]+:)?t(\s[^>]*)?>(.*?)</(?:[A-Za-z0-9_.-]+:)?t>', xml, re.S):
        parts.append(m.group(2))
    joined = ''.join(parts)
    for old, new in (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&apos;', "'"), ('&amp;', '&')):
        joined = joined.replace(old, new)
    return joined


def open_zip(path: str) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        print(f'不是合法的 zip/OOXML 文件：{path}', file=sys.stderr)
        sys.exit(3)


# ------------------------------------------------------------------ docx


def docx_text(path: str) -> None:
    z = open_zip(path)
    doc = z.read('word/document.xml').decode('utf-8')

    # 先记下所有表格的位置：表格单元格里也有 <w:p>，若不一并剔除，
    # 同一段文字会在「按行」与「按段」两处各输出一遍 —— 于是
    # 「报告里找得到某句话」的断言会在表格**之外**命中，看着对，其实是假绿。
    tbl_ranges = [(start, end) for start, end, _, _ in elements(doc, 'tbl')]
    def in_table(pos: int) -> bool:
        return any(start <= pos < end for start, end in tbl_ranges)

    for _, _, _, tbl_inner in elements(doc, 'tbl'):
        for _, _, _, row_inner in elements(tbl_inner, 'tr'):
            cells = []
            for _, _, _, cell_inner in elements(row_inner, 'tc'):
                cells.append(text_of(cell_inner).replace('\n', ' '))
            print('\t'.join(cells))

    for start, _, _, para_inner in elements(doc, 'p'):
        if in_table(start):
            continue
        text = text_of(para_inner).strip()
        if text:
            print(text)


def docx_tables(path: str) -> None:
    z = open_zip(path)
    doc = z.read('word/document.xml').decode('utf-8')
    for idx, (_, _, _, tbl_inner) in enumerate(elements(doc, 'tbl'), start=1):
        print(f'#TABLE {idx}')
        for _, _, _, row_inner in elements(tbl_inner, 'tr'):
            cells = [text_of(c).replace('\n', ' ') for _, _, _, c in elements(row_inner, 'tc')]
            print('\t'.join(cells))


def docx_structure(path: str) -> None:
    z = open_zip(path)
    names = z.namelist()
    doc = z.read('word/document.xml').decode('utf-8')
    styles = z.read('word/styles.xml').decode('utf-8') if 'word/styles.xml' in names else ''

    print(f'page_breaks={doc.count(PAGE_BREAK)}')

    # w:sectPr 必须是 w:body 的最后一个子元素，否则 Word 判定文档结构非法
    body_blocks = elements(doc, 'body')
    sect_last = False
    if body_blocks:
        body_inner = body_blocks[0][3]
        # 去掉尾部空白后，body 的最后一个元素是不是 sectPr
        tail = body_inner.rstrip()
        sect_last = tail.endswith('</w:sectPr>')
    print(f'sectpr_last={str(sect_last).lower()}')

    # TOC 域：必须四段齐全（begin → instrText → separate → 域结果 → end）。
    # 缺 separate 时 Word 把它当「未计算完的域」，界面上什么都看不到且不报错。
    instr = re.findall(r'<w:instrText[^>]*>(.*?)</w:instrText>', doc, re.S)
    print(f'toc_field={str(any("TOC" in t for t in instr)).lower()}')
    print(f'toc_separate={str(TOC_SEPARATE in doc).lower()}')

    footers = [n for n in names if re.match(r'word/footer\d+\.xml$', n)]
    page_field = any(b'PAGE' in z.read(n) for n in footers)
    print(f'footer_count={len(footers)}')
    print(f'footer_page_field={str(page_field).lower()}')
    # 页脚文本（评估名 + 生成时间）。单独给一行：它是「报告自己说明
    # 何时生成」的唯一落点，而页码域是另一个东西，两者都要在。
    footer_texts = [text_of(z.read(n).decode('utf-8')) for n in footers]
    print('footer_text=' + ' '.join(t.strip() for t in footer_texts if t.strip()))

    # 报告用到的全部样式。docgen 侧只定义到 Heading2（报告最深到二级标题），
    # 所以这里不检查 Heading3 —— 断言一个不存在的样式 ID 会永远为假，
    # 而「永远为假」的断言在第一次跑通之后就会被改成 == false 再也不会被看。
    styles_ok = all(f'w:styleId="{sid}"' in styles
                    for sid in ('SecRiskReportTitle', 'SecRiskReportSubtitle',
                                'SecRiskHeading1', 'SecRiskHeading2',
                                'SecRiskBodyText', 'SecRiskTableCaption',
                                'SecRiskTableHeaderCell', 'SecRiskTableCell',
                                'SecRiskTocTitle'))
    print(f'styles_registered={str(styles_ok).lower()}')

    # 分页符数量。报告结构固定（封面 1 + 目录 1 + 6 个「另起一页」的章节），
    # 数量变了说明渲染编排动了，应当让调用方看见。
    print(f'table_count={doc.count("<w:tbl>")}')
    print(f'has_gridspan={str("w:gridSpan" in doc).lower()}')
    print(f'has_tblheader={str("w:tblHeader" in doc).lower()}')


# ------------------------------------------------------------------ xlsx


def xlsx_sheets(path: str) -> None:
    z = open_zip(path)
    wb = z.read('xl/workbook.xml').decode('utf-8')
    for m in re.finditer(r'<sheet\b[^>]*>', wb):
        tag = m.group(0)
        name = re.search(r'name="([^"]*)"', tag)
        if name:
            print(name.group(1))


def resolve_sheet(z: zipfile.ZipFile, sheet: str):
    """工作表名 → (sheet XML 文本, 共享字符串表)。

    走 workbook.xml.rels 里的 r:id，不能靠「第 n 个 sheet 就是 sheetN.xml」
    这种顺序假设 —— 顺序假设在删过 sheet 的文件上会静默取错表。
    """
    wb = z.read('xl/workbook.xml').decode('utf-8')

    rid = None
    for m in re.finditer(r'<sheet\b[^>]*>', wb):
        tag = m.group(0)
        n = re.search(r'name="([^"]*)"', tag)
        i = re.search(r'r:id="([^"]*)"', tag)
        if n and n.group(1) == sheet and i:
            rid = i.group(1)
            break
    if rid is None:
        print(f'工作簿里没有名为「{sheet}」的表', file=sys.stderr)
        sys.exit(4)

    rels = z.read('xl/_rels/workbook.xml.rels').decode('utf-8')
    target = None
    for m in re.finditer(r'<Relationship\b[^>]*>', rels):
        tag = m.group(0)
        if re.search(r'Id="' + re.escape(rid) + '"', tag):
            t = re.search(r'Target="([^"]*)"', tag)
            if t:
                target = t.group(1).lstrip('/')
                if not target.startswith('xl/'):
                    target = 'xl/' + target
            break
    if target is None:
        print(f'找不到工作表部件：{sheet}', file=sys.stderr)
        sys.exit(4)

    shared = []
    if 'xl/sharedStrings.xml' in z.namelist():
        sst = z.read('xl/sharedStrings.xml').decode('utf-8')
        for _, _, _, si_inner in elements(sst, 'si'):
            shared.append(text_of(si_inner))

    return z.read(target).decode('utf-8'), shared


def cell_type(attrs: str) -> str:
    """OOXML 的单元格类型 → 人可读的名字。

    ▍为什么不能只看「有没有 t 属性」就断定它是文本

    OOXML 里数值单元格**根本不写 `t`**（数值是默认类型），excelize 写数值时
    显式把 `c.T` 置为空串，于是 `<c r="J3"><v>12</v></c>` 里没有 t 属性。
    反过来说「没有 t 就是数值」是对的，但「t 是空字符串」与「t 不存在」
    在字符串上看着一样，很容易被写成一个永远为假的断言（例如判
    `t == "n"`：OOXML 里压根没有 n 这个取值）。
    """
    m = re.search(r'\bt="([^"]*)"', attrs)
    if not m or m.group(1) == '':
        return 'number'
    return {'s': 'shared', 'inlineStr': 'inline', 'str': 'formula',
            'b': 'boolean', 'e': 'error', 'n': 'number'}.get(m.group(1), m.group(1))


def decode_cell(attrs: str, body: str, shared) -> str:
    kind = cell_type(attrs)
    vm = re.search(r'<v>(.*?)</v>', body, re.S)
    value = vm.group(1) if vm else ''
    if kind == 'shared':
        idx = int(value) if value.isdigit() else -1
        return shared[idx] if 0 <= idx < len(shared) else ''
    if kind == 'inline':
        return text_of(re.search(r'<is>(.*?)</is>', body, re.S).group(1)
                       if '<is>' in body else body)
    return value


def xlsx_tsv(path: str, sheet: str) -> None:
    z = open_zip(path)
    sheet_xml, shared = resolve_sheet(z, sheet)

    def col_index(ref: str) -> int:
        letters = re.match(r'([A-Z]+)', ref)
        n = 0
        for ch in (letters.group(1) if letters else 'A'):
            n = n * 26 + (ord(ch) - ord('A') + 1)
        return n - 1

    for _, _, _, row_inner in elements(sheet_xml, 'row'):
        cells = {}
        width = 0
        for m in re.finditer(r'<c\b([^>]*)>(.*?)</c>', row_inner, re.S):
            attrs, body = m.group(1), m.group(2)
            ref_m = re.search(r'r="([A-Z]+\d+)"', attrs)
            if not ref_m:
                continue
            idx = col_index(ref_m.group(1))
            cells[idx] = decode_cell(attrs, body, shared)
            width = max(width, idx + 1)
        if width == 0:
            continue
        print('\t'.join(cells.get(i, '') for i in range(width)))


def xlsx_cell(path: str, sheet: str, refs) -> None:
    """逐格输出 `引用<TAB>类型<TAB>值`。

    存在的理由是**类型**：`xlsx-tsv` 只给值，看不出「R 列是数值还是文本」。
    而把数字写成文本是 Excel 导出最容易犯、又最难在界面上看出来的错误 ——
    单元格右对齐与否只是显示习惯，业务方要的是能求和、能排序。
    """
    z = open_zip(path)
    sheet_xml, shared = resolve_sheet(z, sheet)

    found = {}
    for m in re.finditer(r'<c\b([^>]*)>(.*?)</c>', sheet_xml, re.S):
        attrs, body = m.group(1), m.group(2)
        ref_m = re.search(r'r="([A-Z]+\d+)"', attrs)
        if ref_m:
            found[ref_m.group(1)] = (cell_type(attrs), decode_cell(attrs, body, shared))

    for ref in refs:
        kind, value = found.get(ref, ('missing', ''))
        print(f'{ref}\t{kind}\t{value}')


# ------------------------------------------------------------------ 入口


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, path = sys.argv[1], sys.argv[2]

    if cmd == 'docx-text':
        docx_text(path)
    elif cmd == 'docx-tables':
        docx_tables(path)
    elif cmd == 'docx-structure':
        docx_structure(path)
    elif cmd == 'xlsx-sheets':
        xlsx_sheets(path)
    elif cmd == 'xlsx-tsv':
        if len(sys.argv) < 4:
            print('xlsx-tsv 需要工作表名', file=sys.stderr)
            return 2
        xlsx_tsv(path, sys.argv[3])
    elif cmd == 'xlsx-cell':
        if len(sys.argv) < 5:
            print('xlsx-cell 需要 工作表名 与至少一个单元格引用', file=sys.stderr)
            return 2
        xlsx_cell(path, sys.argv[3], sys.argv[4:])
    else:
        print(f'未知子命令：{cmd}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
