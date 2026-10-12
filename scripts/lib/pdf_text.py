#!/usr/bin/env python3
"""
从 PDF 里抽取文本，使用**纯标准库**（zlib + re）。

▍为什么需要它

P5 的验收标志第一句是「PDF 中文不乱码」。只断言「文件是 PDF、页数够」
证明不了这一条 —— 一个所有汉字都渲染成空心方框的 PDF，同样满足那两个
条件。要真正证明，必须把文字从 PDF 里读回来。

沙箱里 pdftotext / mutool / pypdf 一个都没有，所以这里自己实现。
PDF 文本抽取看着吓人，但 Chromium(Skia) 的输出结构很规整：

  · 无对象流（/ObjStm 为 0），所有对象都是明文 `N 0 obj ... endobj`
  · 每个字体都带 ToUnicode CMap
  · ⚠️ 每个文字 run 会建一个**独立的单字形子集字体**（F4、F5、F6 …），
     于是同一个汉字在不同位置可能属于不同字体、用不同的字节码表示。
     这决定了必须**按字体分别解码**，不能用一张全局映射表 ——
     全局表会让不同子集的相同字节码互相覆盖，结果是抽出一堆乱码。

▍实现

  1. 建对象表（N 0 obj → 内容）
  2. 从页面 /Resources /Font 取出「资源名 → 字体对象」映射
  3. 每个字体解析 /ToUnicode 流，得到「字节码 → Unicode」表
  4. 扫描内容流：`/Fx … Tf` 切换当前字体，`<hex> Tj` 按该字体的表解码

用法：
  python3 pdf_text.py <file.pdf>
"""

import re
import sys
import unicodedata
import zlib

# ----------------------------------------------------------------- 部首归一化

# ⚠️ Skia 的字形→Unicode 反查会把一部分汉字解析成**康熙部首 / CJK 部首**
# 码点，而不是汉字本身：
#
#     「文」(U+6587)  →  「⽂」(U+2F82)
#     「风」(U+98CE)  →  「⻛」(U+2EDB)
#     「页」(U+9875)  →  「⻚」(U+2EDA)
#     「一」(U+4E00)  →  「⼀」(U+2F00)
#
# 字形是对的、PDF 渲染出来也是对的（它是按字形 ID 画的），错的是**文本层**：
# 用户复制粘贴时会拿到部首而不是汉字。这是 Chromium 输出 PDF 的已知行为，
# 不是我们的渲染问题。
#
# 但它会让「抽出来的文本里找不找得到『风险评估』」这类断言失败，所以这里
# 做一次归一化。刻意**只替换部首区段**，不用全局 NFKC —— 全局 NFKC 还会把
# 全角括号、全角空格一并改写，那些字符在我们的断言里是有意义的。
# U+2E80–U+2EF3（CJK 部首补充）**没有** Unicode 兼容分解，NFKC 修不了，
# 只能手工补表。下表按 Unicode 字符名对应到简体本字。
#
# 为什么补到简体而不是繁体：本系统报告是简体，映射到「頁」的话下一步还得
# 做一次简繁转换，而标准库并不提供这个能力。表是场景特定的，如实说明。
#
# 带「⺌」这类只作偏旁的部首没有对应汉字，不在表内 —— 它们不会单独成字
# 出现在正文里。
_EXTRA_RADICALS = {
    "⺁": "厂", "⺄": "乙", "⺉": "刀", "⺊": "卜", "⺋": "卩",
    "⺌": "小", "⺍": "小", "⺎": "兀", "⺏": "尢", "⺐": "尣",
    "⺑": "尸", "⺒": "巳", "⺓": "幺", "⺔": "弋", "⺕": "彐",
    "⺖": "心", "⺗": "心", "⺘": "手", "⺙": "攴", "⺛": "无",
    "⺜": "日", "⺝": "月", "⺞": "歹", "⺟": "母", "⺠": "民",
    "⺡": "水", "⺢": "水", "⺣": "火", "⺤": "爪", "⺥": "爪",
    "⺦": "爿", "⺧": "牛", "⺨": "犬", "⺩": "玉", "⺪": "疋",
    "⺫": "目", "⺬": "示", "⺭": "示", "⺮": "竹", "⺯": "糸",
    "⺰": "糸", "⺱": "网", "⺲": "网", "⺳": "网", "⺴": "网",
    "⺵": "网", "⺶": "羊", "⺷": "羊", "⺸": "羊", "⺹": "老",
    "⺺": "聿", "⺻": "聿", "⺼": "月", "⺽": "臼", "⺾": "艹",
    "⺿": "艹", "⻀": "艹", "⻁": "虎", "⻂": "衣", "⻃": "西",
    "⻄": "西", "⻅": "见", "⻆": "角", "⻇": "角", "⻈": "讠",
    "⻉": "贝", "⻊": "足", "⻋": "车", "⻌": "辶", "⻍": "辶",
    "⻎": "辶", "⻏": "阝", "⻐": "钅", "⻑": "长", "⻒": "长",
    "⻓": "长", "⻔": "门", "⻕": "阝", "⻖": "阝", "⻗": "雨",
    "⻘": "青", "⻙": "韦", "⻚": "页", "⻛": "风", "⻜": "飞",
    "⻝": "食", "⻞": "食", "⻟": "食", "⻠": "食", "⻡": "首",
    "⻢": "马", "⻣": "骨", "⻤": "鬼", "⻥": "鱼", "⻦": "鸟",
    "⻧": "卤", "⻨": "麦", "⻩": "黄", "⻪": "黾", "⻫": "齐",
    "⻬": "齐", "⻭": "齿", "⻮": "齿", "⻯": "龙", "⻰": "龙",
    "⻱": "龟", "⻲": "龟", "⻳": "龟",
}


def _build_radical_map():
    mapping = dict(_EXTRA_RADICALS)
    # U+2F00–U+2FD5（康熙部首）有标准的兼容分解，交给 NFKC，
    # 不再手工维护 —— 手工表迟早会与 Unicode 数据漂移。
    for cp in range(0x2F00, 0x2FD6):
        ch = chr(cp)
        norm = unicodedata.normalize("NFKC", ch)
        if len(norm) == 1 and norm != ch and 0x4E00 <= ord(norm) <= 0x9FFF:
            mapping.setdefault(ch, norm)
    return mapping


RADICAL_MAP = _build_radical_map()
RADICAL_RE = (
    re.compile("[" + "".join(re.escape(c) for c in RADICAL_MAP) + "]")
    if RADICAL_MAP
    else None
)


def normalize_radicals(text):
    """把康熙部首/CJK 部首还原成对应汉字。"""
    if not RADICAL_RE:
        return text
    return RADICAL_RE.sub(lambda m: RADICAL_MAP.get(m.group(0), m.group(0)), text)


# ----------------------------------------------------------------- 基础解析

OBJ_RE = re.compile(rb"(\d+)\s+0\s+obj\b(.*?)\bendobj", re.S)
STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)


def inflate(raw):
    """解压，失败则原样返回（未压缩的流也是合法的）。"""
    try:
        return zlib.decompress(raw)
    except Exception:
        pass
    # 某些流带 zlib 头之外的填充，退一步用 decompressobj
    try:
        return zlib.decompressobj().decompress(raw)
    except Exception:
        return raw


def split_stream(body):
    """把对象体切成 (字典部分, 流数据)。没有流则返回 (body, None)。"""
    m = STREAM_RE.search(body)
    if not m:
        return body, None
    return body[: m.start()], inflate(m.group(1))


def build_objects(data):
    """建对象表。键是对象号，值是 (字典字节, 流字节 or None)。"""
    objs = {}
    for m in OBJ_RE.finditer(data):
        num = int(m.group(1))
        objs[num] = split_stream(m.group(2))
    return objs


def deref(objs, ref_text):
    """把 ref_text 里的 '12 0 R' 解析成对象号；失败返回 None。"""
    m = re.search(rb"(\d+)\s+0\s+R", ref_text)
    if not m:
        return None
    num = int(m.group(1))
    return objs.get(num)


# ----------------------------------------------------------------- CMap

def parse_cmap(stream_bytes):
    """
    解析 ToUnicode CMap，返回 (映射表, 码宽字节数)。

    映射表键是**整数**字节码，值是 Unicode 字符串（bfrange 可能映射到
    多字符，虽然极少见）。
    """
    table = {}
    if not stream_bytes:
        return table, None

    for blk in re.findall(rb"beginbfchar(.*?)endbfchar", stream_bytes, re.S):
        for src, dst in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", blk):
            table[int(src, 16)] = _utf16be(dst)

    for blk in re.findall(rb"beginbfrange(.*?)endbfrange", stream_bytes, re.S):
        # 形式一：<lo> <hi> <dstStart>
        for lo, hi, dst in re.findall(
            rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", blk
        ):
            lo_i, hi_i, d_i = int(lo, 16), int(hi, 16), int(dst, 16)
            base = _utf16be(dst)
            for k in range(lo_i, min(hi_i, lo_i + 65535) + 1):
                table[k] = chr(ord(base[0]) + (k - lo_i)) if base else ""
        # 形式二：<lo> <hi> [ <d1> <d2> ... ]
        for lo, hi, arr in re.findall(
            rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\[(.*?)\]", blk, re.S
        ):
            lo_i = int(lo, 16)
            for i, dst in enumerate(re.findall(rb"<([0-9A-Fa-f]+)>", arr)):
                table[lo_i + i] = _utf16be(dst)

    if not table:
        return table, None

    # 码宽：取所有源码里最短的十六进制串长度
    widths = []
    for blk in re.findall(rb"beginbfchar(.*?)endbfchar", stream_bytes, re.S):
        widths += [len(s) for s in re.findall(rb"<([0-9A-Fa-f]+)>\s*<", blk)]
    for blk in re.findall(rb"beginbfrange(.*?)endbfrange", stream_bytes, re.S):
        widths += [len(s) for s in re.findall(rb"<([0-9A-Fa-f]+)>\s*<", blk)]
    hexlen = min(widths) if widths else 4

    return table, max(1, (hexlen + 1) // 2)


def _utf16be(hexstr):
    """UTF-16BE 十六进制 → Python 字符串。"""
    try:
        raw = bytes.fromhex(hexstr.decode())
    except Exception:
        return ""
    try:
        return raw.decode("utf-16-be").replace("\ufeff", "")
    except Exception:
        return ""


# ------------------------------------------------------------ 字体与资源

FONT_DICT_RE = re.compile(rb"/Font\s*<<(.*?)>>", re.S)
FONT_ENTRY_RE = re.compile(rb"/([A-Za-z0-9_.+-]+)\s+(\d+)\s+0\s+R")
TO_UNICODE_RE = re.compile(rb"/ToUnicode\s+(\d+)\s+0\s+R")


def collect_fonts(objs):
    """
    返回 {资源名: (cmap 表, 码宽)}。

    资源名形如 b'F4'。同名资源在多页出现时后覆盖前，实践中同一份
    Skia 输出的字体资源是一致的。
    """
    fonts = {}
    for _, (dict_part, _stream) in objs.items():
        if b"/Type" not in dict_part or b"/Font" not in dict_part:
            # 页面对象里才有 /Font 资源字典；字体对象本身不含
            pass
        for fontdict in FONT_DICT_RE.findall(dict_part):
            for name, num in FONT_ENTRY_RE.findall(fontdict):
                font_obj = objs.get(int(num))
                if not font_obj:
                    continue
                fdict, _ = font_obj
                m = TO_UNICODE_RE.search(fdict)
                if not m:
                    continue
                cmap_obj = objs.get(int(m.group(1)))
                if not cmap_obj:
                    continue
                table, width = parse_cmap(cmap_obj[1])
                if table:
                    fonts[name.decode()] = (table, width or 2)
    return fonts


# ------------------------------------------------------------ 内容流解码

Tf_RE = re.compile(rb"/([A-Za-z0-9_.+-]+)\s+[\d.]+\s+Tf")
Tj_RE = re.compile(rb"<([0-9A-Fa-f]+)>\s*Tj")
TJ_ARRAY_RE = re.compile(rb"\[(.*?)\]\s*TJ", re.S)


def decode_content(content, fonts, fallback, fallback_width):
    """
    扫描内容流，逐段解码。

    ▍为什么必须逐 token 顺序扫描，而不是「把所有 <hex> 抓出来统一解」

    因为 Tf 决定用哪张表。同一份 PDF 里 F4 的字节码 0x6D 和 F5 的 0x6D
    是两个完全不同的字。先收集再统一解码，等于把字体信息丢掉，
    结果是随机乱码 —— 而且乱得"看起来像正常中文"，最难察觉。
    """
    out = []
    pos = 0
    current_font = None

    # 把所有「会影响解码的指令」按出现位置排序后线性推进
    events = []
    for m in Tf_RE.finditer(content):
        events.append((m.start(), "tf", m.group(1).decode()))
    for m in Tj_RE.finditer(content):
        events.append((m.start(), "tj", m.group(1).decode()))
    for m in TJ_ARRAY_RE.finditer(content):
        events.append((m.start(), "tjarr", m.group(1)))
    events.sort(key=lambda e: e[0])

    for _pos, kind, payload in events:
        if kind == "tf":
            current_font = payload
            continue

        table, width = fonts.get(current_font, (fallback, fallback_width))

        if kind == "tj":
            out.append(_decode_hex(payload, table, width))
        else:
            # TJ 数组：里面既有 <hex> 也有数字（字距调整），只要 hex
            for hexstr in re.findall(rb"<([0-9A-Fa-f]+)>", payload):
                out.append(_decode_hex(hexstr.decode(), table, width))

    return "".join(out)


def _decode_hex(hexstr, table, width):
    """把一段十六进制串按给定码宽解码成文本。"""
    if not hexstr:
        return ""
    # 十六进制串长度必须是偶数
    if len(hexstr) % 2:
        hexstr = hexstr[:-1]

    step = width * 2
    chars = []
    for i in range(0, len(hexstr) - step + 1, step):
        code = int(hexstr[i : i + step], 16)
        u = table.get(code)
        if u is None and width != 2:
            # 码宽猜错时退回两字节再试一次（不同子集可能不一致）
            u = table.get(int(hexstr[i : i + 4], 16)) if len(hexstr) - i >= 4 else None
        chars.append(u if u else "\ufffd")
    return "".join(chars)


# ----------------------------------------------------------------- 入口

def extract(path):
    data = open(path, "rb").read()
    objs = build_objects(data)
    fonts = collect_fonts(objs)

    # 兜底表：所有字体合并（仅在 Tf 未覆盖到某段时使用）
    fallback, fw = {}, 2
    for table, width in fonts.values():
        fallback.update(table)
        fw = min(fw, width)

    # 内容流：/Contents N 0 R
    chunks = []
    for _num, (dpart, _s) in objs.items():
        if b"/Contents" not in dpart:
            continue
        for m in re.finditer(rb"/Contents\s+(\d+)\s+0\s+R", dpart):
            ref = objs.get(int(m.group(1)))
            if ref and ref[1]:
                chunks.append(decode_content(ref[1], fonts, fallback, fw))
        # 也可能是数组形式 /Contents [1 0 R 2 0 R]
        arr = re.search(rb"/Contents\s*\[(.*?)\]", dpart, re.S)
        if arr:
            for m in re.finditer(rb"(\d+)\s+0\s+R", arr.group(1)):
                ref = objs.get(int(m.group(1)))
                if ref and ref[1]:
                    chunks.append(decode_content(ref[1], fonts, fallback, fw))

    return "".join(chunks), fonts


def main():
    if len(sys.argv) < 2:
        print("用法: pdf_text.py <file.pdf>", file=sys.stderr)
        return 2

    text, fonts = extract(sys.argv[1])
    text = normalize_radicals(text)

    sys.stdout.write(text)
    sys.stdout.write("\n")
    print(f"[pdf_text] 字体资源 {len(fonts)} 个，抽取 {len(text)} 字", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
