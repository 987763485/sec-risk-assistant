using System.Text;

using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Validation;
using DocumentFormat.OpenXml.Wordprocessing;

using SecRisk.DocGen.Models;

namespace SecRisk.DocGen.Rendering;

/// <summary>
/// 把结构化数据渲染为 docx。
///
/// <para>
/// 为什么用 OpenXML SDK 写代码，而不是「模板占位符替换」：
/// 有三类内容纯占位符替换做不到 ——
/// ① 行数不定的动态表格；② 带合并单元格的风险矩阵；③ 随评估范围变化的动态分节。
/// </para>
/// <para>
/// 单位备忘（写错不报错，但版式全乱）：
/// <list type="bullet">
///   <item>字号：half-point，16pt = 32</item>
///   <item>间距/缩进/页边距：twip，1 英寸 = 1440 twip，1 厘米 ≈ 567 twip</item>
///   <item>表格宽度百分比：1/50 %，100% = 5000</item>
///   <item>首行缩进：firstLineChars 单位为 1/100 字符，2 字符 = 200</item>
/// </list>
/// </para>
/// </summary>
public static class DocxRenderer
{
    // A4：210mm × 297mm
    private const int A4WidthTwips = 11906;
    private const int A4HeightTwips = 16838;

    // 页边距：上下 2.54cm、左右 3.17cm（接近 Word 中文默认版式）
    private const int MarginTopBottomTwips = 1440;
    private const int MarginLeftRightTwips = 1800;

    private const int ContentWidthTwips = A4WidthTwips - (MarginLeftRightTwips * 2);

    private const int HeaderDistanceTwips = 851;
    private const int FooterDistanceTwips = 992;

    /// <summary>渲染 docx，返回完整文件字节。</summary>
    /// <param name="request">契约化的渲染请求</param>
    /// <param name="logger">日志（可选）</param>
    public static byte[] Render(DocxRenderRequest request, ILogger? logger = null)
    {
        using var stream = new MemoryStream();

        using (var document = WordprocessingDocument.Create(stream, WordprocessingDocumentType.Document))
        {
            var mainPart = document.AddMainDocumentPart();
            mainPart.Document = new Document();
            var body = mainPart.Document.AppendChild(new Body());

            // ── ① 样式必须最先注册（否则后续引用的 StyleId 静默失效）
            var stylesPart = mainPart.AddNewPart<StyleDefinitionsPart>();
            stylesPart.Styles = StyleFactory.Create();
            stylesPart.Styles.Save();

            // ── ② 页脚（含页码域）
            var footerPart = mainPart.AddNewPart<FooterPart>();
            footerPart.Footer = BuildFooter(request);
            footerPart.Footer.Save();

            // ── ③ 正文
            //
            // 顺序即报告结构：封面 → 目录 → 各章节。
            // 封面与目录各自以分页符收尾，正文第一章节便自然另起一页。
            if (request.CoverPage)
            {
                AppendCoverPage(body, request);
                AppendPageBreak(body);
                // ⚠️ 封面已承载标题，这里**不再**调 AppendTitle，
                //    否则标题会在第 1 页与第 2 页各出现一次。
            }
            else
            {
                AppendTitle(body, request);
            }

            if (request.TableOfContents)
            {
                AppendTableOfContents(body);
                AppendPageBreak(body);
            }

            foreach (var section in request.Sections)
            {
                AppendSection(body, section);
            }

            // ── ④ 节属性必须是 body 的**最后一个**子元素，
            //       否则 Word 判定文档结构非法
            body.AppendChild(BuildSectionProperties(mainPart.GetIdOfPart(footerPart)));

            mainPart.Document.Save();
        }

        var bytes = stream.ToArray();

        // ── ⑤ 结构校验：把「Word 打开时才发现的文件损坏」提前到生成时暴露
        ValidateOrThrow(bytes, logger);

        return bytes;
    }

    // ────────────────────────────────────────────────────────────────
    // 正文装配
    // ────────────────────────────────────────────────────────────────

    private static void AppendTitle(Body body, DocxRenderRequest request)
    {
        body.AppendChild(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.ReportTitle }),
            new Run(PreserveText(request.Title))));

        if (!string.IsNullOrWhiteSpace(request.Subtitle))
        {
            body.AppendChild(new Paragraph(
                new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.ReportSubtitle }),
                new Run(PreserveText(request.Subtitle))));
        }
    }

    /// <summary>
    /// 封面页：标题与副标题位于页面上部约三分之一处。
    ///
    /// <para>
    /// 用空段落把内容往下压，而不是用段前间距（<c>w:spacing/@w:before</c>）：
    /// 段前间距在跨页时会被 Word 丢弃一部分，几行空段落则不会。
    /// 这也是 Word 里手工做封面最常见的做法。
    /// </para>
    /// </summary>
    private static void AppendCoverPage(Body body, DocxRenderRequest request)
    {
        const int leadingBlankLines = 6;
        for (var i = 0; i < leadingBlankLines; i++)
        {
            body.AppendChild(new Paragraph());
        }

        body.AppendChild(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.ReportTitle }),
            new Run(PreserveText(request.Title))));

        if (!string.IsNullOrWhiteSpace(request.Subtitle))
        {
            body.AppendChild(new Paragraph(
                new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.ReportSubtitle }),
                new Run(PreserveText(request.Subtitle))));
        }
    }

    /// <summary>
    /// 插入分页符。
    ///
    /// <para>
    /// 形式是「空段落里放一个 run，run 里是 <c>&lt;w:br w:type="page"/&gt;</c>」。
    /// 不用段落属性 <c>w:pageBreakBefore</c> 的原因：那是**给段落加属性**，
    /// 一旦段落内容为空（比如章节没有标题），Word 会把整个空段落丢掉，
    /// 分页随之消失——静默失效。显式的 br 元素不会。
    /// </para>
    /// </summary>
    private static void AppendPageBreak(Body body)
    {
        body.AppendChild(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.BodyText }),
            new Run(new Break { Type = BreakValues.Page })));
    }

    /// <summary>
    /// 目录页：一个 TOC 域。
    ///
    /// <para>
    /// 域的完整形态是四段：<c>begin</c> → <c>instrText</c> → <c>separate</c>
    /// → 域结果 → <c>end</c>。
    /// </para>
    /// <para>
    /// ⚠️ <c>separate</c> 与域结果不能省。只写 begin + instrText + end 时，
    /// Word 打开会把它当成一个**未计算完的域**，界面上什么都看不到，
    /// 且没有任何报错。
    /// </para>
    /// <para>
    /// 域结果是占位文本：真实目录（含页码）只有 Word 自己算得出来。
    /// 这里放一句操作提示，让「不知道要更新域」的人也有路可走。
    /// </para>
    /// <para>
    /// 域开关 <c>\o "1-2"</c> 收集 1–2 级大纲，<c>\h</c> 生成超链接，
    /// <c>\z</c> Web 视图下隐藏页码，<c>\u</c> 使用段落的大纲级别
    /// （而不是仅认内置 Heading 样式）—— 我们的标题是自定义样式，
    /// 缺了 <c>\u</c> 同样会收集不到。
    /// </para>
    /// </summary>
    private static void AppendTableOfContents(Body body)
    {
        // 目录页标题。用独立样式（无 outlineLvl），避免自引用。
        body.AppendChild(new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.TocTitle }),
            new Run(PreserveText("目录"))));

        var paragraph = new Paragraph(
            new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.BodyText }));

        paragraph.AppendChild(new Run(new FieldChar { FieldCharType = FieldCharValues.Begin }));
        paragraph.AppendChild(new Run(new FieldCode(" TOC \\o \"1-2\" \\h \\z \\u ")
        {
            // 域代码里的前后空格必须保留，否则 Word 解析域时可能出错
            Space = SpaceProcessingModeValues.Preserve,
        }));
        paragraph.AppendChild(new Run(new FieldChar { FieldCharType = FieldCharValues.Separate }));
        paragraph.AppendChild(new Run(PreserveText("（目录需在 Word 中更新：全选后按 F9）")));
        paragraph.AppendChild(new Run(new FieldChar { FieldCharType = FieldCharValues.End }));

        body.AppendChild(paragraph);
    }

    private static void AppendSection(Body body, DocxSection section)
    {
        // 另起一页：分页符段落放在标题**之前**，于是标题必然位于新页顶部。
        if (section.PageBreakBefore)
        {
            AppendPageBreak(body);
        }

        if (!string.IsNullOrWhiteSpace(section.Heading))
        {
            var styleId = section.Level >= 2 ? StyleFactory.Heading2 : StyleFactory.Heading1;
            body.AppendChild(new Paragraph(
                new ParagraphProperties(new ParagraphStyleId { Val = styleId }),
                new Run(PreserveText(section.Heading))));
        }

        foreach (var text in section.Paragraphs)
        {
            var paragraphProps = new ParagraphProperties();
            paragraphProps.AppendChild(new ParagraphStyleId { Val = StyleFactory.BodyText });
            // 中文正文首行缩进 2 字符（用 firstLineChars 而非 firstLine，
            // 这样字号变化时缩进会自动跟随，不会出现半个字宽度）
            paragraphProps.AppendChild(new Indentation { FirstLineChars = 200 });

            body.AppendChild(new Paragraph(paragraphProps, new Run(PreserveText(text))));
        }

        if (section.Table is { Headers.Count: > 0 } table)
        {
            if (!string.IsNullOrWhiteSpace(table.Caption))
            {
                body.AppendChild(new Paragraph(
                    new ParagraphProperties(new ParagraphStyleId { Val = StyleFactory.TableCaption }),
                    new Run(PreserveText(table.Caption))));
            }

            body.AppendChild(BuildTable(table));

            // 表格后补一个空段落：连续两个表格会被 Word 合并成一个，
            // 且表格紧贴下一个标题时版式很难看
            body.AppendChild(new Paragraph());
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 表格
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// 构建表格。
    ///
    /// ⚠️ 注意：表格边框必须用 <c>TableBorders</c>，
    /// 段落边框是 <c>ParagraphBorders</c> —— 两者是完全不同的类，
    /// 混用会「编译通过但毫无效果」。
    /// </summary>
    private static Table BuildTable(DocxTable spec)
    {
        var columnCount = spec.Headers.Count;
        var table = new Table();

        // ── 表格属性。CT_TblPr 顺序：tblW → jc → tblBorders → shd → tblLayout
        var tableProps = new TableProperties();
        tableProps.AppendChild(new TableWidth
        {
            // pct 单位是 1/50 %，5000 = 100%
            Width = "5000",
            Type = TableWidthUnitValues.Pct,
        });
        tableProps.AppendChild(new TableBorders(
            new TopBorder { Val = BorderValues.Single, Size = 4, Color = "8C8C8C" },
            new LeftBorder { Val = BorderValues.Single, Size = 4, Color = "8C8C8C" },
            new BottomBorder { Val = BorderValues.Single, Size = 4, Color = "8C8C8C" },
            new RightBorder { Val = BorderValues.Single, Size = 4, Color = "8C8C8C" },
            new InsideHorizontalBorder { Val = BorderValues.Single, Size = 4, Color = "8C8C8C" },
            new InsideVerticalBorder { Val = BorderValues.Single, Size = 4, Color = "8C8C8C" }));
        // 固定布局：列宽不会被长内容撑开，版式可预期
        tableProps.AppendChild(new TableLayout { Type = TableLayoutValues.Fixed });
        table.AppendChild(tableProps);

        // ── 列定义
        var grid = new TableGrid();
        var columnWidth = columnCount > 0 ? ContentWidthTwips / columnCount : ContentWidthTwips;
        for (var i = 0; i < columnCount; i++)
        {
            grid.AppendChild(new GridColumn { Width = columnWidth.ToString() });
        }
        table.AppendChild(grid);

        // ── 表头行
        table.AppendChild(BuildHeaderRow(spec.Headers, spec.RepeatHeaderRow));

        // ── 数据行
        for (var rowIndex = 0; rowIndex < spec.Rows.Count; rowIndex++)
        {
            table.AppendChild(BuildDataRow(spec, rowIndex, columnCount));
        }

        return table;
    }

    private static TableRow BuildHeaderRow(IReadOnlyList<string> headers, bool repeatOnEachPage)
    {
        // CT_TrPr 顺序：cantSplit → trHeight → tblHeader
        var rowProps = new TableRowProperties();
        rowProps.AppendChild(new CantSplit()); // 单行不跨页断开
        if (repeatOnEachPage)
        {
            rowProps.AppendChild(new TableHeader()); // ⚠️ w:tblHeader —— 跨页重复表头
        }

        var row = new TableRow(rowProps);
        foreach (var header in headers)
        {
            row.AppendChild(BuildCell(
                text: header,
                styleId: StyleFactory.TableHeaderCell,
                justify: JustificationValues.Center,
                gridSpan: 1,
                shadingFill: "F0F4FA"));
        }
        return row;
    }

    private static TableRow BuildDataRow(DocxTable spec, int rowIndex, int columnCount)
    {
        var rowProps = new TableRowProperties();
        rowProps.AppendChild(new CantSplit());
        var row = new TableRow(rowProps);

        var merges = spec.Merges
            .Where(m => m.RowIndex == rowIndex)
            .OrderBy(m => m.StartColumn)
            .ToList();

        var column = 0;
        while (column < columnCount)
        {
            var merge = merges.FirstOrDefault(m => m.StartColumn == column);
            if (merge is not null)
            {
                var span = Math.Max(1, merge.EndColumn - merge.StartColumn + 1);
                row.AppendChild(BuildCell(
                    text: merge.Text,
                    styleId: StyleFactory.TableHeaderCell,
                    justify: JustificationValues.Center,
                    gridSpan: span,
                    shadingFill: "FAFAFA"));
                column += span;
                continue;
            }

            var cells = spec.Rows[rowIndex];
            var value = column < cells.Count ? cells[column] : string.Empty;
            row.AppendChild(BuildCell(
                text: value,
                styleId: StyleFactory.TableCell,
                justify: JustificationValues.Left,
                gridSpan: 1,
                shadingFill: null));
            column += 1;
        }

        return row;
    }

    /// <summary>
    /// 构建单元格。
    ///
    /// ⚠️ CT_TcPr 子元素顺序：tcW → gridSpan → vMerge → tcBorders → shd → tcMar → vAlign
    /// 顺序错误会导致 Word 拒绝打开或合并单元格失效。
    /// </summary>
    private static TableCell BuildCell(
        string text,
        string styleId,
        JustificationValues justify,
        int gridSpan,
        string? shadingFill)
    {
        var cellProps = new TableCellProperties();
        cellProps.AppendChild(new TableCellWidth { Type = TableWidthUnitValues.Auto });

        if (gridSpan > 1)
        {
            // ⚠️ 横向合并靠的是「第一个单元格声明 gridSpan，后续被合并的单元格直接不生成」，
            //    而不是生成空单元格再标记合并
            cellProps.AppendChild(new GridSpan { Val = gridSpan });
        }

        if (!string.IsNullOrEmpty(shadingFill))
        {
            cellProps.AppendChild(new Shading
            {
                Val = ShadingPatternValues.Clear,
                Color = "auto",
                Fill = shadingFill,
            });
        }

        cellProps.AppendChild(new TableCellVerticalAlignment
        {
            Val = TableVerticalAlignmentValues.Center,
        });

        var paragraphProps = new ParagraphProperties();
        paragraphProps.AppendChild(new ParagraphStyleId { Val = styleId });
        paragraphProps.AppendChild(new Justification { Val = justify });

        return new TableCell(cellProps, new Paragraph(paragraphProps, new Run(PreserveText(text))));
    }

    // ────────────────────────────────────────────────────────────────
    // 页脚 / 节属性
    // ────────────────────────────────────────────────────────────────

    private static Footer BuildFooter(DocxRenderRequest request)
    {
        var paragraphProps = new ParagraphProperties();
        paragraphProps.AppendChild(new Justification { Val = JustificationValues.Center });
        paragraphProps.AppendChild(new SpacingBetweenLines { After = "0" });

        var paragraph = new Paragraph(paragraphProps);

        if (!string.IsNullOrWhiteSpace(request.FooterText))
        {
            paragraph.AppendChild(MakeSmallRun(request.FooterText + "　"));
        }

        // 页码域：PAGE / NUMPAGES 需要用「域的起始 → 域代码 → 域结束」三段构造，
        // 直接写文本不会自动更新
        AppendField(paragraph, "PAGE");
        paragraph.AppendChild(MakeSmallRun(" / "));
        AppendField(paragraph, "NUMPAGES");

        return new Footer(paragraph);
    }

    private static Run MakeSmallRun(string text)
    {
        var runProps = new RunProperties();
        runProps.AppendChild(new FontSize { Val = StyleFactory.HalfPoints(9) });
        return new Run(runProps, PreserveText(text));
    }

    private static void AppendField(Paragraph paragraph, string instruction)
    {
        paragraph.AppendChild(new Run(new FieldChar { FieldCharType = FieldCharValues.Begin }));
        paragraph.AppendChild(new Run(new FieldCode($" {instruction} ")
        {
            // 域代码里的前后空格必须保留，否则 Word 解析域时可能出错
            Space = SpaceProcessingModeValues.Preserve,
        }));
        paragraph.AppendChild(new Run(new FieldChar { FieldCharType = FieldCharValues.End }));
    }

    private static SectionProperties BuildSectionProperties(string footerPartId)
    {
        var sectionProps = new SectionProperties();

        // CT_SectPr 顺序：headerReference → footerReference → pgSz → pgMar → docGrid
        sectionProps.AppendChild(new FooterReference
        {
            Type = HeaderFooterValues.Default,
            Id = footerPartId,
        });

        sectionProps.AppendChild(new PageSize
        {
            Width = (UInt32Value)(uint)A4WidthTwips,
            Height = (UInt32Value)(uint)A4HeightTwips,
            Orient = PageOrientationValues.Portrait,
        });

        sectionProps.AppendChild(new PageMargin
        {
            Top = MarginTopBottomTwips,
            Bottom = MarginTopBottomTwips,
            Left = (UInt32Value)(uint)MarginLeftRightTwips,
            Right = (UInt32Value)(uint)MarginLeftRightTwips,
            Header = (UInt32Value)(uint)HeaderDistanceTwips,
            Footer = (UInt32Value)(uint)FooterDistanceTwips,
            Gutter = 0,
        });

        // 中文文档的行网格，让每行高度对齐中文字号，排版更整齐
        sectionProps.AppendChild(new DocGrid
        {
            Type = DocGridValues.Lines,
            LinePitch = 312,
        });

        return sectionProps;
    }

    // ────────────────────────────────────────────────────────────────
    // 文本与校验
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// ⚠️ 连续空格默认会被折叠。要保留首尾与连续空格，必须置
    /// <c>xml:space="preserve"</c>，否则「整改前　整改后」这类对齐文本会错位。
    /// </summary>
    private static Text PreserveText(string? value) =>
        new(value ?? string.Empty) { Space = SpaceProcessingModeValues.Preserve };

    /// <summary>
    /// 用 OpenXmlValidator 做结构校验。
    ///
    /// 价值：OOXML 的错误大多是**静默**的 —— 元素顺序错误、单位写错、
    /// 属性名拼错都不会抛异常，只表现为「样式不生效」或 Word 提示文件需修复。
    /// 把这些错误提前到生成时暴露，比等用户打开报告时才发现便宜得多。
    /// </summary>
    private static void ValidateOrThrow(byte[] docx, ILogger? logger)
    {
        var strict = string.Equals(
            Environment.GetEnvironmentVariable("DOCGEN_STRICT_VALIDATION"),
            "true",
            StringComparison.OrdinalIgnoreCase);

        using var stream = new MemoryStream(docx, writable: false);
        using var document = WordprocessingDocument.Open(stream, isEditable: false);

        var validator = new OpenXmlValidator(FileFormatVersions.Office2019);
        var errors = validator.Validate(document).Take(20).ToList();

        if (errors.Count == 0)
        {
            logger?.LogInformation("docx 结构校验通过");
            return;
        }

        // 用 StringBuilder 手工拼接，不用 string.Format —— 校验信息里含 XML 路径，
        // 其中的花括号会被当成格式占位符而抛出 FormatException
        var detail = new StringBuilder();
        detail.Append("docx 结构校验发现 ").Append(errors.Count).Append(" 处问题：");
        foreach (var error in errors)
        {
            detail.Append("\n  - [").Append(error.ErrorType).Append("] ")
                  .Append(error.Description);

            if (error.Node is not null)
            {
                detail.Append("（节点：").Append(error.Node.LocalName).Append('）');
            }
        }

        var message = detail.ToString();

        if (strict)
        {
            throw new InvalidOperationException(message);
        }

        logger?.LogWarning("{Detail}", message);
    }
}
