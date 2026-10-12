# 09 · docgen 服务规范

> 适用对象：`services/docgen/`（C# / .NET 10）以及它的调用方（Go 主服务）。
> 改动接口契约、样式表、OOXML 生成逻辑之前必须读完本文。

---

## 1. 定位与职责边界

docgen 是一个**只做一件事**的独立服务：

```
结构化 JSON  ──────────▶  docx 二进制流
```

### 允许 ✅

- 接收契约化 JSON
- 渲染 docx（标题、章节、段落、表格、合并单元格、页脚页码）
- 返回字节流
- 用 `OpenXmlValidator` 做结构自检

### 禁止 ❌

- **不连数据库** —— 一个数据访问能力都没有
- **不判权限** —— 调用方（Go 主服务）负责鉴权
- **不做风险计算** —— 风险值由 Go 侧算好后以纯文本传入
- **不执行任何用户提供的模板或表达式** —— 没有模板引擎，不存在注入面
- **不写文件系统** —— 完全无状态，产物只在内存

### 为什么坚持这条边界

只有无状态、无数据访问，这个服务才能：

1. 独立部署、独立重启、独立压测
2. 不成为「绕过权限的后门」—— 即使被攻陷也拿不到业务数据
3. 未来换语言重写时，代价只限于这一个进程

> 这条边界是本项目里最不该被妥协的一条。

---

## 2. 架构与调用链

```
┌──────────┐        ┌───────────────────┐        ┌──────────────────┐
│ 浏览器   │──REST─▶│ server (Go :8080) │──REST─▶│ docgen (C# :8090)│
└──────────┘        │  · 鉴权/会话      │        │  · 纯渲染        │
                    │  · 风险计算       │        │  · 无状态        │
                    │  · 数据持久化     │        └──────────────────┘
                    └─────────┬─────────┘                 ▲
                              │                           │
                              │                    secrisk-internal
                              │                    （internal: true）
                              ▼                   宿主机无端口映射
                       ┌──────────┐
                       │ MySQL    │
                       └──────────┘
```

**网络隔离**：docgen 只挂 `secrisk-internal` 网络，compose 中**刻意不声明
`ports`**，宿主机无法直接访问。在 netstat / lsof 上找不到 8090 是符合预期的。

**为什么不用 gRPC**：gRPC 需要额外的 proto 代码生成、多一套调试工具链，
而本服务的调用量极低（导出报告时一次请求）。REST + JSON 的调试成本几乎为零
（curl 就能测），契约用 OpenAPI 描述即可。这是刻意选择的简单方案。

---

## 3. 接口契约

### 3.1 端点

```
POST /api/v1/render/docx
```

| 项 | 值 |
|---|---|
| Content-Type | `application/json` |
| 请求体上限 | 16 MB（Kestrel `MaxRequestBodySize`） |
| 成功响应 | `200`，`Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| 成功响应头 | `Content-Disposition: attachment; filename="<清洗后的标题>.docx"` |
| 参数错误 | `400`，`{ "code": "INVALID_REQUEST", "message": "..." }` |
| 未授权 | `401`，`{ "code": "UNAUTHORIZED", "message": "..." }` |
| 渲染失败 | `500`，RFC 7807 Problem Details（**不含堆栈**，详情只进服务日志） |

### 3.2 请求头

| 请求头 | 必填 | 说明 |
|---|---|---|
| `X-Internal-Secret` | ✅ | 服务间共享密钥，见第 4 节 |
| `Content-Type` | ✅ | `application/json` |

### 3.3 请求体结构

字段名使用 **camelCase**（`Program.cs` 中配置了 `JsonNamingPolicy.CamelCase`
且 `PropertyNameCaseInsensitive = true`）。

```
DocxRenderRequest
├── title        string          报告标题（居中、黑体加粗、22pt）
├── subtitle     string?         副标题（可选，居中、微软雅黑、14pt）
├── footerText   string?         页脚文字（可选，页码会跟在它之后）
└── sections     DocxSection[]   章节列表

DocxSection
├── heading      string          章节标题
├── level        int             1 = 一级标题(16pt)，≥2 = 二级标题(14pt)
├── paragraphs   string[]        正文段落，每项一个自然段（自动首行缩进 2 字符）
└── table        DocxTable?      本章节内的表格（可选）

DocxTable
├── caption          string?         表格题注（可选）
├── headers          string[]        表头单元格文本；**列数由此决定**
├── rows             List<List<string>>  数据行
├── repeatHeaderRow  bool = true     表头是否跨页重复（长表格必开）
└── merges           DocxMerge[]     横向合并定义

DocxMerge
├── rowIndex      int      在第几行（0 起，不含表头行）
├── startColumn   int      起始列（0 起，含）
├── endColumn     int      结束列（0 起，含）
└── text          string   合并后单元格的内容
```

### 3.4 校验规则

- `title` 与 `sections` **不能同时为空** → 否则 `400 INVALID_REQUEST`
- `sections[].table` 仅当 `headers.Count > 0` 时才会渲染（空表头直接跳过整个表格）
- `rows[i]` 列数少于 `headers.Count` 时，缺的列补空字符串
- `DocxMerge` 的列区间会与普通单元格**争抢**：从 `startColumn` 开始，
  被合并覆盖的列直接不生成单元格（见第 5 节 T9）

### 3.5 完整示例

`services/docgen/samples/sample-request.json` 是一份刻意构造的样例，
覆盖了全部易错点：40 行跨页表格、3 列合并、全角空格、连续半角空格、中西文混排。

```bash
# 重新生成样例
python3 services/docgen/samples/generate_sample.py
```

---

## 4. 鉴权

`services/docgen/Security/InternalSecretMiddleware.cs`，**必须最先执行**
（在 `Program.cs` 中注册于任何业务端点之前）：

1. 从配置 `DOCGEN_INTERNAL_SECRET` 或同名环境变量读取预期密钥
2. **密钥缺失或长度 < 16 位 → 构造函数直接抛异常，拒绝启动**

   > 一个「忘记配密钥」的 docgen 服务，等于对内部网络完全敞开且毫无告警。
   > 宁可启动失败，也不能带着空密钥跑起来。

3. 逐请求校验 `X-Internal-Secret` 请求头
4. 比较使用 `CryptographicOperations.FixedTimeEquals` —— **恒定时间比较**，
   避免按字节短路比较带来的时序侧信道
5. `/health` 端点**绕过**密钥校验，否则容器 healthcheck 需要额外配密钥

> 网络隔离（`internal: true`）只挡住了外部流量，
> 挡不住同一网络内其他被攻陷的容器。共享密钥是第二道防线。

**部署要求**：生产环境的 `SR_INTERNAL_SHARED_SECRET` 必须是
`openssl rand -hex 32` 生成的值。Go 侧的 `SR_INTERNAL_SHARED_SECRET` 与
docgen 侧的 `DOCGEN_INTERNAL_SECRET` 必须配成**同一个值**
（compose 中两者都取自 `${SR_INTERNAL_SHARED_SECRET}`）。

---

## 5. OOXML 陷阱清单

> **这是本文档最有价值的部分。**
>
> OOXML 的错误绝大多数是**静默的** —— 编译通过、运行不报错，
> 只表现为「样式不生效」或「Word 提示文件需要修复」。
> 下面每一条都是实际踩过或明确验证过的，请勿凭直觉改写。

### T1 · 自定义样式必须先注册再引用

**现象**：`ParagraphStyleId { Val = "SecRiskHeading1" }` 引用了，
但 Word 里样式毫无变化，且没有任何报错。

**根因**：样式表 `StyleDefinitionsPart` 里没有这个 `StyleId` 的定义。
OOXML 不会因为引用不存在的样式而报错。

**正确做法**：在写入任何内容**之前**先挂样式表：

```csharp
var stylesPart = mainPart.AddNewPart<StyleDefinitionsPart>();
stylesPart.Styles = StyleFactory.Create();   // 里面 AppendChild 了全部样式
stylesPart.Styles.Save();                    // 顺序：先注册，后引用
```

**自动断言**：`verify-docgen.sh` 检查全部 `SecRisk*` StyleId 都出现在 `styles.xml` 里。

---

### T2 · 中文字体必须写英文名

**现象**：设置 `EastAsia = "宋体"`，中文仍显示为等线/Calibri。

**根因**：`w:rFonts` 的字体名走的是**字体族英文标识**，
写中文名不报错，但不生效。

**正确做法**：

```csharp
public const string FontSong = "SimSun";   // ✅
// public const string FontSong = "宋体";  // ❌ 不报错，但不生效
```

常用对照：`宋体` → `SimSun`，`黑体` → `SimHei`，`微软雅黑` → `Microsoft YaHei`。

**自动断言**：`w:eastAsia="SimSun"` 存在，且 `styles.xml` 中**不出现**任何中文字体名。

---

### T3 · `Ascii` / `EastAsia` / `HighAnsi` 必须分别设置

**现象**：中西文混排时字体跳变 —— 数字和字母一套字体，汉字另一套。

**根因**：OOXML 按字符范围分别取字体。只设 `Ascii` 时，
中文会回落到文档默认字体（通常是等线），与英文不一致。

**正确做法**：

```csharp
new RunFonts {
    Ascii         = "Times New Roman",
    HighAnsi      = "Times New Roman",
    EastAsia      = "SimSun",           // ⚠️ 中文不生效最常见的漏配点
    ComplexScript = "Times New Roman",
}
```

不要只在 `docDefaults` 里设 —— 自定义样式也要各自设一遍（样式会覆盖 docDefaults）。

---

### T4 · 字号单位是 half-point

**现象**：设置 `FontSize { Val = "16" }` 想让文字 16pt，结果字小了一半。

**根因**：`w:sz` 的单位是**半磅**。16pt 必须写 `32`。

**正确做法**：统一走换算函数，不要手写数字。

```csharp
public static string HalfPoints(double points) =>
    ((int)Math.Round(points * 2, MidpointRounding.AwayFromZero)).ToString();
```

保留小数是为了支持 10.5pt（五号字）这类中文常用字号。

**自动断言**：22pt 标题对应 `w:sz w:val="44"`。

---

### T5 · 子元素顺序必须符合 OOXML schema

**现象**：Word 打开时提示「文件已损坏 / 内容有问题」，拒绝打开；或样式整体失效。

**根因**：OOXML 是**有序**的 schema。用 `AppendChild` 时必须按 schema 定义的顺序。

**必须记住的顺序**：

| 容器 | 子元素顺序 |
|---|---|
| `CT_Style` | `name` → `basedOn` → `qFormat` → `pPr` → `rPr` |
| `CT_Styles` | `docDefaults` → 若干 `style` |
| `CT_DocDefaults` | `rPrDefault` → `pPrDefault` |
| `CT_TblPr` | `tblW` → `jc` → `tblBorders` → `shd` → `tblLayout` |
| `CT_TcPr` | `tcW` → `gridSpan` → `vMerge` → `tcBorders` → `shd` → `tcMar` → `vAlign` |
| `CT_TrPr` | `cantSplit` → `trHeight` → `tblHeader` |
| `CT_SectPr` | `headerReference` → `footerReference` → `pgSz` → `pgMar` → `docGrid` |
| `CT_PPr` 在正文中 | `pStyle` → … → `ind`（`ParagraphStyleId` 在 `Indentation` 之前） |

**自动断言**：`OpenXmlValidator` 在运行时校验（见第 7 节），
外加 `w:sectPr` 位置断言。

---

### T6 · `w:sectPr` 必须是 `w:body` 的**最后一个**子元素

**现象**：Word 拒绝打开，或页面尺寸/页边距设置全部无效。

**正确做法**：所有内容写完后再 append：

```csharp
foreach (var section in request.Sections) AppendSection(body, section);
body.AppendChild(BuildSectionProperties(footerId));   // ⚠️ 必须在最后
mainPart.Document.Save();
```

**自动断言**：解析 XML，确认 `body[-1].tag == 'w:sectPr'`。

---

### T7 · `w:ParagraphBorders` ≠ `w:TableBorders`

**现象**：想给表格加边框，写了 `ParagraphBorders`，编译通过但表格没有边框。

**根因**：这是两个**完全不同**的类，作用于完全不同的对象。
`ParagraphBorders` 给段落加框，`TableBorders` 给表格加框。

**正确做法**：

```csharp
tableProps.AppendChild(new TableBorders(
    new TopBorder { Val = BorderValues.Single, Size = 4, Color = "8C8C8C" },
    new LeftBorder { ... }, new BottomBorder { ... }, new RightBorder { ... },
    new InsideHorizontalBorder { ... }, new InsideVerticalBorder { ... }));
```

**自动断言**：`w:tblBorders` 存在于 `document.xml`。

---

### T8 · `xml:space="preserve"`，不是 `w:space`

**现象**：连续空格被折叠成一个，「整改前　　整改后」这类对齐文本错位；
全角空格丢失。

**根因**：保留空白的属性在 **`xml` 命名空间**下，不在 `w` 命名空间。
写成 `w:space` 不报错，但完全无效。

**正确做法**：

```csharp
private static Text PreserveText(string? value) =>
    new(value ?? string.Empty) { Space = SpaceProcessingModeValues.Preserve };
// 产出 xml:space="preserve"
```

**自动断言**：`xml:space="preserve"` 存在，且 `\u3000`（全角空格）未丢失。

---

### T9 · 横向合并用 `w:gridSpan`，且被合并的单元格**不生成**

**现象**：合并单元格后列数对不上，表格版式错乱。

**根因**：横向合并不是「生成 N 个单元格再标记合并」，而是
**只生成第一个单元格并声明它跨越 N 列，后续被覆盖的列直接不生成**。

**正确做法**（`BuildDataRow`）：以列游标推进，遇到合并定义就跳 `span` 列。

```csharp
var span = Math.Max(1, merge.EndColumn - merge.StartColumn + 1);
row.AppendChild(BuildCell(merge.Text, ..., gridSpan: span, ...));
column += span;                       // 跳过被合并的列
continue;
```

**自动断言**：`<w:gridSpan w:val="3" />` 存在。

---

### T10 · 中文首行缩进用 `firstLineChars`，不用 `firstLine`

**现象**：缩进在某个字号下是正好 2 字，换字号后变成 1.5 字或 2.5 字。

**根因**：`firstLine` 的单位是固定 twip，不随字号变化。
`firstLineChars` 的单位是 **1/100 字符**，会跟随字号自动换算。

**正确做法**：

```csharp
paragraphProps.AppendChild(new Indentation { FirstLineChars = 200 }); // 2 字符
```

**自动断言**：`w:firstLineChars="200"` 存在。

---

### T11 · 表头跨页重复：`w:tblHeader`

**现象**：40 行的长表格翻到第 2 页后看不到列名，读者无法对应哪列是什么。

**正确做法**：

```csharp
var rowProps = new TableRowProperties();
rowProps.AppendChild(new CantSplit());          // 单行不跨页断开
if (repeatOnEachPage) rowProps.AppendChild(new TableHeader());  // w:tblHeader
```

**自动断言**：`w:tblHeader` 与 `w:cantSplit` 均存在。

---

### T12 · 页脚页码必须用域代码三段构造

**现象**：页脚里直接写 "1 / 5"，页码不会随内容变化。

**根因**：页码是**域**（field），不是文本。需要「域起始 → 域代码 → 域结束」三段：

```csharp
paragraph.AppendChild(new Run(new FieldChar { FieldCharType = FieldCharValues.Begin }));
paragraph.AppendChild(new Run(new FieldCode(" PAGE ") {
    // ⚠️ 域代码里的前后空格必须保留，否则 Word 解析域时可能出错
    Space = SpaceProcessingModeValues.Preserve,
}));
paragraph.AppendChild(new Run(new FieldChar { FieldCharType = FieldCharValues.End }));
```

**自动断言**：`word/footer*.xml` 中存在 `PAGE`。

---

### T13 · 连续两个表格会被 Word 合并

**现象**：两个相邻表格变成一个表格。

**正确做法**：表格后补一个空段落：

```csharp
body.AppendChild(BuildTable(table));
body.AppendChild(new Paragraph());   // ⚠️ 必须有
```

同时这也避免了表格下边缘紧贴下一个标题的难看版式。

---

### T14 · 单位换算备忘

| 量 | 单位 | 换算 |
|---|---|---|
| 字号 | half-point | 1pt = 2 |
| 间距 / 缩进 / 页边距 | twip | 1 英寸 = 1440；1 厘米 ≈ 567 |
| 表格宽度百分比 | 1/50 % | 100% = 5000 |
| 首行缩进（`firstLineChars`） | 1/100 字符 | 2 字符 = 200 |
| 行距（`Line` + `Auto`） | 1/240 行 | 单倍 = 240；1.25 倍 = 300 |
| A4 纸张 | twip | 11906 × 16838 |

**这些写错都不报错，但版式全乱。**

---

### T15 · 分页符数量是结构契约，别用「≥ N」断言

**现象**：报告少了一整页，或者多出一整页空白，而 Word 打开完全正常、什么也不报。

**成因**：封面与目录之后各有一个分页符，之后每个一级章节还有一个
（**第一节不设** `pageBreakBefore` —— 目录之后本来就有分页符，再设会多出一整页空白）。
「总共有几个」是渲染编排决定的**结构契约**，不是随数据变化的量。

因此两处守门脚本都用**精确相等**断言分页符数量：

| 场景 | 期望值 | 构成 |
|---|---|---|
| docgen 样例（3 章） | 5 | 封面 1 + 目录 1 + 章节 3 |
| P5 报告（7 节） | 8 | 封面 1 + 目录 1 + 章节 6（第一节不设） |

写成 `≥ 3` 的话，「多出一个空白页」这类问题永远不会被抓住 —— 而它的成因常常是
某处重复设置了 `pageBreakBefore`，人眼在 Word 里逐页翻很难注意到。
数量变化说明编排动了，此时**应当让断言失败并人工确认**，而不是让它继续绿着。

**与之配套的两条**（同属 TOC 链路的静默失败）：

- 目录必须用**真正的 TOC 域**，四段齐全：`begin → instrText → separate → 域结果 → end`。
  缺 `separate` 时 Word 把域当成「未计算完」，界面上什么都看不到，**且不报错**。
- 标题样式必须声明 `w:outlineLvl` —— TOC 是按**大纲级别**收集段落的，不是按样式名。
  缺了它，用户更新域之后目录仍然是空的。
- 「目录」标题自身**不能**带大纲级别，否则它会把自己也列进目录，形成自引用。

---

## 6. 样式表约定

`Rendering/StyleFactory.cs` 中定义的 StyleId 一览（**改动即破坏契约**）：

| StyleId | 显示名 | 字体 | 字号 | 加粗 | 对齐 | 用途 |
|---|---|---|---|---|---|---|
| `Normal` | Normal | 宋体 | 12pt | — | 两端 | 默认样式（`Default = true`） |
| `SecRiskReportTitle` | 报告标题 | 黑体 | 22pt | ✅ | 居中 | 报告标题 |
| `SecRiskReportSubtitle` | 报告副标题 | 微软雅黑 | 14pt | — | 居中 | 副标题 |
| `SecRiskHeading1` | 一级标题 | 黑体 | 16pt | ✅ | 左 | `level = 1` |
| `SecRiskHeading2` | 二级标题 | 黑体 | 14pt | ✅ | 左 | `level ≥ 2` |
| `SecRiskTocTitle` | 目录标题 | 黑体 | 16pt | ✅ | 居中 | 「目录」二字。**不含 `outlineLvl`**（带了会自引用） |
| `SecRiskBodyText` | 正文 | 宋体 | 12pt | — | 两端 | 正文段落 |
| `SecRiskTableCaption` | 表格题注 | 黑体 | 10.5pt | — | 居中 | 表题 |
| `SecRiskTableHeaderCell` | 表头单元格 | 黑体 | 10.5pt | ✅ | 居中 | 表头、合并格 |
| `SecRiskTableCell` | 数据单元格 | 宋体 | 10.5pt | — | 左 | 数据行 |

**加粗必须同时设 `b` 和 `bCs`**（`Bold` + `BoldComplexScript`），
否则复杂脚本区段不加粗。

**正文用两端对齐**（`JustificationValues.Both`）—— 中文排版下比左对齐整齐。

`docDefaults` 是兜底：样式表里没显式指定的部分由它决定。
中文文档**必须**在 `docDefaults` 里把 `EastAsia` 设为宋体，
否则 Word 会用默认的等线/Calibri 显示中文。

---

## 7. 自检与验证

### 7.1 运行时：`OpenXmlValidator`

每次渲染后自动跑一遍（`DocxRenderer.ValidateOrThrow`）：

```csharp
var validator = new OpenXmlValidator(FileFormatVersions.Office2019);
var errors = validator.Validate(document).Take(20).ToList();
```

- 默认行为：发现问题写 `Warning` 日志，**仍然返回文件**
- 严格模式：环境变量 `DOCGEN_STRICT_VALIDATION=true` 时改为**抛异常**

> 为什么要跑这个：把「Word 打开时才发现的文件损坏」提前到生成时暴露。
>
> ⚠️ 拼装错误信息时用 `StringBuilder`，**不要用 `string.Format`** ——
> 校验信息里含 XML 路径，其中的花括号会被当成格式占位符而抛 `FormatException`。

### 7.2 守门验证：19 项 OOXML 断言

```bash
bash scripts/verify-docgen.sh
```

流程：起 docgen 容器 → 提交样例请求 → 取回 docx → **解包检查内部 XML**。

断言覆盖第 5 节的全部陷阱：

| # | 断言 | 对应陷阱 |
|---|---|---|
| 1 | 中文标题完整写入 `document.xml` | T2 / T3 |
| 2 | 全部自定义样式已注册到 `styles.xml` | T1 |
| 3 | `w:eastAsia="SimSun"` 存在，且无中文字体名泄漏 | T2 |
| 4 | 字号使用 half-point（22pt → 44） | T4 |
| 5 | `w:tblHeader` 跨页重复表头 | T11 |
| 6 | `w:cantSplit` 不跨页断开 | — |
| 7 | `w:gridSpan val="3"` 合并单元格 | T9 |
| 8 | `w:firstLineChars="200"` 首行缩进 | T10 |
| 9 | `xml:space="preserve"` + 全角空格未丢失 | T8 |
| 10 | `w:tblBorders` 表格边框 | T7 |
| 11 | 页脚包含 `PAGE` 域 | T12 |
| 12 | `w:sectPr` 是 `w:body` 最后一个子元素 | T6 |
| 13 | A4 页面（11906 × 16838 twip） | T14 |
| 14 | `[Content_Types].xml` 声明主文档部件 | — |
| 15 | 分页符存在（`w:br w:type="page"`） | T15 |
| 16 | 分页符数量**精确等于 5**（封面 1 + 目录 1 + 章节 3） | T15 |
| 17 | TOC 域四段完整（含 `w:fldCharType="separate"`） | T15 |
| 18 | 标题样式声明大纲级别（Heading1 → 0、Heading2 → 1） | T15 |
| 19 | 「目录」标题样式已注册且**不含**大纲级别（避免自引用） | T15 |

> #15–#19 是 P5 新增：封面/目录页与 TOC 链路引入的五条静默失败通道。
> 其中 #16 是**精确相等**断言 —— 理由见 T15，写成 `≥ N` 就抓不住「多出一页空白」。

产物落在 `.verify/report.docx`，脚本结束时提示**用 Word / WPS 打开做最终人工确认**。

> ⚠️ 计数口径：以脚本里 `check(` 的**调用点**为准（19 个）。
> 别去数「打印出来的行数」—— 未来若把断言放进循环，行数会与调用点数脱钩，
> 而这张表维护的是「我们承诺检查哪些事」，不是「运行时打印了几行」。

### 7.3 手工排查 docx 问题的最快手段

```bash
cp report.docx report.zip && unzip -o report.zip -d report_xml
# 重点看 word/document.xml 与 word/styles.xml
```

`.docx` 本质是 zip。上面 19 项断言做的就是这件事的自动化版本 ——
遇到断言失败时，直接去看对应的 XML 片段是最快的定位方式。

---

## 8. 本地调试

### 8.1 只跑 docgen（不依赖 Go 与 MySQL）

```bash
make infra        # 起 mysql / docgen / gotenberg
docker compose logs -f docgen
```

### 8.2 直接从宿主机打请求

docgen 不映射端口，需要**进入容器内部**请求：

```bash
docker compose exec -T docgen sh -c '
  curl -sS -o /tmp/out.docx -w "%{http_code}\n" \
    -H "X-Internal-Secret: '"$SR_INTERNAL_SHARED_SECRET"'" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    http://127.0.0.1:8090/api/v1/render/docx
' < services/docgen/samples/sample-request.json

docker compose cp docgen:/tmp/out.docx ./out.docx
```

### 8.3 健康检查

```bash
docker compose exec -T docgen curl -fsS http://127.0.0.1:8090/health
```

`/health` 返回服务名、版本、.NET 运行时版本、时间戳，且**不需要密钥**。

---

## 9. 构建与部署

`services/docgen/Dockerfile`：

- **多阶段构建**：`sdk:10.0` 编译（约 1 GB，不进最终镜像）→ `aspnet:10.0` 运行
- **先拷 `.csproj` 再 `restore`**，让 NuGet 层可被缓存
- 最终镜像**以非 root 用户 `$APP_UID` 运行**
- 内置 `curl` 仅用于容器 healthcheck（aspnet 镜像不含 curl/wget）
  → ⚠️ 这条 `apt-get install` **需要出网**，构建机需能访问 Debian 源

**为什么是 .NET 10**：.NET 8 的 LTS 支持在 2026 年 11 月到期，
.NET 9 是 STS（已停止支持），只有 .NET 10 是当前 LTS（支持至 2028）。

**工程约定**：

- `<TargetFramework>net10.0</TargetFramework>`
- `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` ——
  OpenXML 的错误大多是静默失败，先在这种低级问题上拦住
- `<InvariantGlobalization>false</InvariantGlobalization>` —— 中文日期/区域格式需要完整全球化

---

## 10. 契约变更流程

**`Models/RenderModels.cs` 里的类型是契约。字段增删改即契约变更。**

变更时必须同步以下位置，缺一不可：

| 同步对象 | 位置 |
|---|---|
| 本文档 | 第 3 节的字段表与示例 |
| 调用方 | `server/` 中构造渲染请求的代码 |
| 样例 | `services/docgen/samples/sample-request.json` |
| 守门验证 | `scripts/verify-docgen.sh` 中相关断言 |
| OpenAPI 描述 | 服务契约文件 |

**兼容性原则**：

- 新增字段必须**可选**（有默认值），老调用方不受影响
- 删除/重命名字段属于破坏性变更，需要双方同时发布
- 语义变更（如 `level` 从 1/2 改成 1/2/3）也要走上面的同步流程

---

## 附：文件索引

| 文件 | 作用 |
|---|---|
| `Program.cs` | 入口、JSON 配置、请求体上限、中间件与端点注册 |
| `Security/InternalSecretMiddleware.cs` | 共享密钥校验（恒定时间比较） |
| `Models/RenderModels.cs` | **契约类型** |
| `Rendering/StyleFactory.cs` | 样式表构建（字体/字号/half-point 换算/大纲级别） |
| `Rendering/DocxRenderer.cs` | 正文、表格、页脚、**封面与目录页**、节属性装配 + 校验 |
| `Endpoints/DocxEndpoints.cs` | HTTP 端点 + 文件名校验 + 异常处理 |
| `samples/generate_sample.py` | 生成覆盖全部易错点的样例请求 |
| `SecRisk.DocGen.csproj` | 目标框架与 OpenXML SDK 版本锁定 |
| `Dockerfile` | 多阶段构建，非 root 运行 |
| `scripts/verify-docgen.sh` | 19 项 OOXML 断言 |
