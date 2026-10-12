namespace SecRisk.DocGen.Models;

/// <summary>
/// docx 渲染请求。
///
/// 这是一个**契约**类型：字段变更即契约变更，必须同步更新
/// docs/09-docgen服务规范.md 与 Go 侧调用方。
/// </summary>
public sealed class DocxRenderRequest
{
    /// <summary>报告标题（文档首行，居中、黑体加粗）</summary>
    public string Title { get; set; } = "未命名报告";

    /// <summary>副标题，可选</summary>
    public string? Subtitle { get; set; }

    /// <summary>页脚文字，可选；页码会跟在它之后</summary>
    public string? FooterText { get; set; }

    /// <summary>
    /// 是否生成封面页。
    ///
    /// <para>
    /// true 时：标题与副标题独占第一页（居中偏上），其后插入分页符，
    /// 且**正文不再重复标题**——否则封面与正文各出现一次标题。
    /// </para>
    /// <para>
    /// 默认 false，老调用方行为不变（标题仍在正文首行）。
    /// </para>
    /// </summary>
    public bool CoverPage { get; set; }

    /// <summary>
    /// 是否生成目录页。
    ///
    /// <para>
    /// 生成的是一个 **TOC 域**（<c>TOC \o "1-2" \h \z \u</c>），
    /// 而不是预先算好的静态条目——页码只有 Word 自己知道。
    /// </para>
    /// <para>
    /// ⚠️ 域必须由 Word 更新后才有内容。为了让「不更新域」也不至于看到
    /// 一片空白，域结果里放了一句操作提示。这一点必须让调用方知道，
    /// 否则用户会以为目录渲染坏了。
    /// </para>
    /// <para>
    /// ⚠️ 该域按**大纲级别**（<c>w:outlineLvl</c>）收集段落，
    /// 因此标题样式必须声明 outlineLvl（见 <see cref="StyleFactory"/>），
    /// 否则更新域后目录仍然是空的，且不报任何错。
    /// </para>
    /// </summary>
    public bool TableOfContents { get; set; }

    /// <summary>章节列表</summary>
    public List<DocxSection> Sections { get; set; } = [];
}

/// <summary>文档章节</summary>
public sealed class DocxSection
{
    /// <summary>章节标题</summary>
    public string Heading { get; set; } = string.Empty;

    /// <summary>标题层级：1 = 一级标题，2 = 二级标题</summary>
    public int Level { get; set; } = 1;

    /// <summary>
    /// 本章节是否另起一页（在标题前插入分页符）。
    ///
    /// <para>
    /// 只在正文的一级章节上用（二级标题跟着父章节走）。报告里每个主要
    /// 章节独占一页，版面上比「章节标题挤在两页交界处」整齐得多。
    /// </para>
    /// <para>默认 false。</para>
    /// </summary>
    public bool PageBreakBefore { get; set; }

    /// <summary>正文段落，每项为一个自然段（自动首行缩进 2 字符）</summary>
    public List<string> Paragraphs { get; set; } = [];

    /// <summary>本章节内的表格，可选</summary>
    public DocxTable? Table { get; set; }
}

/// <summary>表格</summary>
public sealed class DocxTable
{
    /// <summary>表格题注，可选</summary>
    public string? Caption { get; set; }

    /// <summary>表头单元格文本</summary>
    public List<string> Headers { get; set; } = [];

    /// <summary>数据行</summary>
    public List<List<string>> Rows { get; set; } = [];

    /// <summary>表头是否跨页重复（长表格必开，否则翻页后无法对应列）</summary>
    public bool RepeatHeaderRow { get; set; } = true;

    /// <summary>横向合并单元格定义</summary>
    public List<DocxMerge> Merges { get; set; } = [];
}

/// <summary>
/// 横向合并单元格。
///
/// 语义：在第 <see cref="RowIndex"/> 行，把 <see cref="StartColumn"/> 到
/// <see cref="EndColumn"/>（含两端）的列合并为一个单元格，内容为 <see cref="Text"/>。
/// 列索引从 0 开始。
/// </summary>
public sealed class DocxMerge
{
    public int RowIndex { get; set; }

    public int StartColumn { get; set; }

    public int EndColumn { get; set; }

    public string Text { get; set; } = string.Empty;
}
