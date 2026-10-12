using DocumentFormat.OpenXml.Wordprocessing;

namespace SecRisk.DocGen.Rendering;

/// <summary>
/// 构建 docx 的样式表。
///
/// <para>
/// ⚠️ <b>铁律一</b>：所有自定义样式<strong>必须</strong>先注册进
/// <c>StyleDefinitionsPart</c> 再被引用。引用未注册的 StyleId 是典型的静默失败 ——
/// 编译通过、运行不报错、样式就是不生效，排查成本极高。
/// </para>
/// <para>
/// ⚠️ <b>铁律二</b>：中文字体必须写<strong>英文名</strong>（<c>SimSun</c> 而非「宋体」）。
/// 写中文名同样不报错，但中文样式不生效。且 <c>rFonts</c> 的
/// <c>Ascii</c> / <c>EastAsia</c> 要分别设置，否则中西文混排会出现字体跳变。
/// </para>
/// <para>
/// ⚠️ <b>铁律三</b>：字号单位是 <b>half-point</b>。16pt 必须写 <c>Val="32"</c>，
/// 写成 16 会让所有文字小一半。
/// </para>
/// <para>
/// ⚠️ <b>铁律四</b>：子元素顺序必须符合 OOXML schema（CT_Style 的顺序是
/// name → basedOn → qFormat → pPr → rPr）。顺序错误会导致 Word 提示
/// 「文件已损坏/内容有问题」而拒绝打开。
/// </para>
/// </summary>
public static class StyleFactory
{
    // ────────────────────────────────────────────────────────────────
    // 字体名（英文！）
    // ────────────────────────────────────────────────────────────────

    /// <summary>宋体。⚠️ 必须用英文名，写成「宋体」中文样式不生效。</summary>
    public const string FontSong = "SimSun";

    /// <summary>黑体</summary>
    public const string FontHei = "SimHei";

    /// <summary>微软雅黑</summary>
    public const string FontYaHei = "Microsoft YaHei";

    /// <summary>西文字体</summary>
    public const string FontLatin = "Times New Roman";

    // ────────────────────────────────────────────────────────────────
    // 样式 ID
    // ────────────────────────────────────────────────────────────────

    public const string Normal = "Normal";
    public const string ReportTitle = "SecRiskReportTitle";
    public const string ReportSubtitle = "SecRiskReportSubtitle";
    /// <summary>目录页标题（「目录」二字）。⚠️ 刻意**不带** outlineLvl，
    /// 否则它会把自己也列进目录里。</summary>
    public const string TocTitle = "SecRiskTocTitle";
    public const string Heading1 = "SecRiskHeading1";
    public const string Heading2 = "SecRiskHeading2";
    public const string BodyText = "SecRiskBodyText";
    public const string TableCaption = "SecRiskTableCaption";
    public const string TableHeaderCell = "SecRiskTableHeaderCell";
    public const string TableCell = "SecRiskTableCell";

    /// <summary>
    /// 把「磅值」换算成 OOXML 的 half-point 字符串。
    /// 保留小数是为了支持 10.5pt（五号字）这类中文常用字号。
    /// </summary>
    public static string HalfPoints(double points) =>
        ((int)Math.Round(points * 2, MidpointRounding.AwayFromZero)).ToString();

    /// <summary>创建完整样式表。</summary>
    public static Styles Create()
    {
        var styles = new Styles();

        // 顺序即 CT_Styles 的子元素顺序：docDefaults → 若干 style
        styles.AppendChild(BuildDocDefaults());
        styles.AppendChild(BuildNormal());

        styles.AppendChild(BuildParagraphStyle(
            ReportTitle, "报告标题", FontHei,
            sizePoints: 22, bold: true, justify: JustificationValues.Center,
            beforeTwips: 0, afterTwips: 360));

        styles.AppendChild(BuildParagraphStyle(
            ReportSubtitle, "报告副标题", FontYaHei,
            sizePoints: 14, bold: false, justify: JustificationValues.Center,
            beforeTwips: 0, afterTwips: 480));

        // 目录页标题。⚠️ 不设 outlineLvl —— TOC 域按大纲级别收集段落，
        // 若「目录」二字也有大纲级别，它会把自己列进目录，形成自引用。
        styles.AppendChild(BuildParagraphStyle(
            TocTitle, "目录标题", FontHei,
            sizePoints: 16, bold: true, justify: JustificationValues.Center,
            beforeTwips: 0, afterTwips: 240));

        // ⚠️ outlineLvl 是 TOC 域能收集到标题的**唯一**依据（TOC \o "1-2"）。
        //    缺了它，Word 更新域之后目录一片空白，且不报任何错 ——
        //    这是本文件里最容易漏、也最难排查的一处（见 docs/09 T15）。
        styles.AppendChild(BuildParagraphStyle(
            Heading1, "一级标题", FontHei,
            sizePoints: 16, bold: true, justify: JustificationValues.Left,
            beforeTwips: 360, afterTwips: 180, outlineLevel: 0));

        styles.AppendChild(BuildParagraphStyle(
            Heading2, "二级标题", FontHei,
            sizePoints: 14, bold: true, justify: JustificationValues.Left,
            beforeTwips: 240, afterTwips: 120, outlineLevel: 1));

        // 正文用两端对齐（w:jc=both），中文排版下比左对齐更整齐
        styles.AppendChild(BuildParagraphStyle(
            BodyText, "正文", FontSong,
            sizePoints: 12, bold: false, justify: JustificationValues.Both,
            beforeTwips: 0, afterTwips: 120));

        styles.AppendChild(BuildParagraphStyle(
            TableCaption, "表格题注", FontHei,
            sizePoints: 10.5, bold: false, justify: JustificationValues.Center,
            beforeTwips: 120, afterTwips: 60));

        styles.AppendChild(BuildParagraphStyle(
            TableHeaderCell, "表头单元格", FontHei,
            sizePoints: 10.5, bold: true, justify: JustificationValues.Center,
            beforeTwips: 40, afterTwips: 40));

        styles.AppendChild(BuildParagraphStyle(
            TableCell, "数据单元格", FontSong,
            sizePoints: 10.5, bold: false, justify: JustificationValues.Left,
            beforeTwips: 40, afterTwips: 40));

        return styles;
    }

    // ────────────────────────────────────────────────────────────────
    // 内部构建
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// 文档级默认格式。这里是「兜底」——样式表里没显式指定的部分由它决定。
    /// 中文文档必须在此把 EastAsia 字体设为宋体，否则 Word 会用默认的等线/Calibri 显示中文。
    /// </summary>
    private static DocDefaults BuildDocDefaults()
    {
        var docDefaults = new DocDefaults();

        // CT_DocDefaults 顺序：rPrDefault → pPrDefault
        docDefaults.AppendChild(new RunPropertiesDefault(
            new RunPropertiesBaseStyle(
                new RunFonts
                {
                    Ascii = FontLatin,
                    HighAnsi = FontLatin,
                    // ⚠️ EastAsia 必须单独设置，这是中文不生效最常见的漏配点
                    EastAsia = FontSong,
                    ComplexScript = FontLatin,
                },
                new FontSize { Val = HalfPoints(12) },
                new FontSizeComplexScript { Val = HalfPoints(12) }
            )
        ));

        docDefaults.AppendChild(new ParagraphPropertiesDefault(
            new ParagraphPropertiesBaseStyle(
                new SpacingBetweenLines
                {
                    After = "0",
                    // 行距 = 1.25 倍（240 = 单倍），中文长文档可读性更好
                    Line = "300",
                    LineRule = LineSpacingRuleValues.Auto,
                },
                new Justification { Val = JustificationValues.Both }
            )
        ));

        return docDefaults;
    }

    private static Style BuildNormal()
    {
        var runProps = new StyleRunProperties();
        runProps.AppendChild(new RunFonts
        {
            Ascii = FontLatin,
            HighAnsi = FontLatin,
            EastAsia = FontSong,
            ComplexScript = FontLatin,
        });
        runProps.AppendChild(new FontSize { Val = HalfPoints(12) });
        runProps.AppendChild(new FontSizeComplexScript { Val = HalfPoints(12) });

        return new Style(
            new StyleName { Val = "Normal" },
            new PrimaryStyle(),
            new StyleParagraphProperties(
                new SpacingBetweenLines { After = "0", Line = "300", LineRule = LineSpacingRuleValues.Auto }
            ),
            runProps
        )
        {
            Type = StyleValues.Paragraph,
            StyleId = Normal,
            Default = true,
        };
    }

    /// <summary>
    /// 构建一个段落样式。
    ///
    /// ⚠️ 子元素顺序严格遵循 CT_Style：
    ///    StyleName → BasedOn → PrimaryStyle(qFormat) → StyleParagraphProperties(pPr) → StyleRunProperties(rPr)
    /// 顺序错误 Word 会直接判定文件损坏。
    /// </summary>
    /// <param name="outlineLevel">
    /// 大纲级别（0 = 一级），null 表示不声明。
    ///
    /// <para>
    /// ⚠️ 它必须排在 <c>Justification</c> **之后**：CT_PPrBase 的顺序是
    /// … → spacing → ind → … → jc → … → outlineLvl → …，
    /// 顺序错了 Word 判定文件损坏。
    /// </para>
    /// </param>
    private static Style BuildParagraphStyle(
        string styleId,
        string displayName,
        string eastAsiaFont,
        double sizePoints,
        bool bold,
        JustificationValues justify,
        int beforeTwips,
        int afterTwips,
        int? outlineLevel = null)
    {
        // ── rPr：RunFonts → (Bold/BoldComplexScript) → FontSize → FontSizeComplexScript
        var runProps = new StyleRunProperties();
        runProps.AppendChild(new RunFonts
        {
            Ascii = FontLatin,
            HighAnsi = FontLatin,
            EastAsia = eastAsiaFont,
            ComplexScript = FontLatin,
        });
        if (bold)
        {
            // 中文字体加粗需要同时设置 bCs，否则复杂脚本区段不加粗
            runProps.AppendChild(new Bold());
            runProps.AppendChild(new BoldComplexScript());
        }
        runProps.AppendChild(new FontSize { Val = HalfPoints(sizePoints) });
        runProps.AppendChild(new FontSizeComplexScript { Val = HalfPoints(sizePoints) });

        // ── pPr
        var paragraphProps = new StyleParagraphProperties();
        paragraphProps.AppendChild(new SpacingBetweenLines
        {
            Before = beforeTwips.ToString(),
            After = afterTwips.ToString(),
            Line = "300",
            LineRule = LineSpacingRuleValues.Auto,
        });
        paragraphProps.AppendChild(new Justification { Val = justify });

        // ⚠️ outlineLvl 必须在 Justification 之后（CT_PPrBase 的顺序约束）。
        //    它同时服务于：① TOC 域按级别收集标题；② Word 的导航窗格。
        if (outlineLevel.HasValue)
        {
            paragraphProps.AppendChild(new OutlineLevel { Val = outlineLevel.Value });
        }

        return new Style(
            new StyleName { Val = displayName },
            new BasedOn { Val = Normal },
            // qFormat：让该样式出现在 Word 的样式库中
            new PrimaryStyle(),
            paragraphProps,
            runProps
        )
        {
            Type = StyleValues.Paragraph,
            StyleId = styleId,
        };
    }
}
