// Package spreadsheet 把 Excel / CSV 统一读成「带原始行号的二维字符串」，
// 并提供写出 xlsx 的能力。
//
// 独立成包的原因有两条：
//
//  1. **行号保真**是导入功能的硬需求。错误提示必须写「第 12 行 IP 地址格式
//     不正确」——用户打开 Excel 就能直接跳到第 12 行改。如果这里返回的是
//     「第 9 个数据行」，用户就得自己心算偏移量。所有格式转换都收在本包，
//     才不会出现「某一种格式忘了补偏移」。
//
//  2. 让 service 层完全不依赖 excelize。业务规则在纯 Go 测试里就能验证，
//     不必为了测一条「缺必填列」的规则去构造一个真实的 xlsx 字节流。
//
// ▍关于 CSV 的两个现实问题
//
// Excel 在简体中文 Windows 上「另存为 CSV」默认写的是 **GBK**，而且带 BOM
// 的 UTF-8 也常见。这两种文件按 UTF-8 硬读会得到乱码，且乱码后的列名
// 匹配不上，报出来的是「缺少必需列」——一个把用户引向错误方向的提示。
// 因此这里显式处理 BOM，并在字节流不是合法 UTF-8 时按 GBK 解码。
package spreadsheet

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/xuri/excelize/v2"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// 各种上限。
//
// 这些数字不是拍脑袋的：它们同时服务两个目的——挡住无意间的超大文件，
// 以及让「压缩炸弹」（一个几 KB 的 xlsx 解压出几个 GB 的 XML）在
// 解析阶段就失败，而不是把进程撑爆。
const (
	// MaxFileSize 上传文件体积上限（10 MB）。
	// 5000 行 × 14 列的 xlsx 通常在 300 KB 上下，10 MB 留了两个数量级余量。
	MaxFileSize = 10 << 20
	// MaxRows 数据行数上限。
	// 一次导入上万行已经不是「导入」而是「迁移」，那种场景应该走库对库同步。
	MaxRows = 5000
	// MaxColumns 列数上限。
	// 挡住「整行全选」后把 A..XFD 共 16384 列都带进来的文件。
	MaxColumns = 64
	// MaxCellRunes 单元格字符数上限。
	MaxCellRunes = 2000
	// UnzipSizeLimit 解压后总体积上限（128 MB）。
	UnzipSizeLimit int64 = 128 << 20
	// UnzipXMLSizeLimit 单个 XML 解压上限（32 MB）。
	UnzipXMLSizeLimit int64 = 32 << 20
)

// Format 表格格式。
type Format string

const (
	// FormatXLSX Office Open XML 工作簿
	FormatXLSX Format = "xlsx"
	// FormatCSV 逗号分隔文本
	FormatCSV Format = "csv"
)

// Row 一行数据。
//
// Number 是**源文件里的行号**（从 1 开始，含表头行），不是「第几个数据行」。
// 导入的错误提示直接用它，用户打开表格就能定位。
type Row struct {
	Number int
	Cells  []string
}

// Sheet 解析结果。
type Sheet struct {
	Format Format
	// Rows 全部非空行，行号保真。
	Rows []Row
	// skippedBlank 记录被跳过的空行数量，仅用于日志观察，
	// 不对外暴露——用户不关心文件里有多少空行。
	skippedBlank int
}

// ErrEmpty 文件里没有任何非空行。
var ErrEmpty = errors.New("spreadsheet: 文件里没有任何数据")

// ErrTooManyRows 数据行数超过上限。
var ErrTooManyRows = errors.New("spreadsheet: 数据行数超过上限")

// ErrTooLarge 文件体积超过上限。
//
// 必须是可识别的哨兵错误而不是普通错误：调用方要凭它把「文件太大」与
// 「文件不是表格」分开报警，而这两句话对用户意味着完全不同的动作
// （换个小文件 / 换个正确的文件）。若混在一起，一个 20 MB 的文件会得到
// 「请确认格式且未损坏」这种把人引向错误方向的提示。
var ErrTooLarge = errors.New("spreadsheet: 文件体积超过上限")

// DetectFormat 按**魔数**嗅探格式，而不是按扩展名。
//
// 只看扩展名会踩两类坑：用户把 xlsx 改名成 .csv（或反过来），
// 以及浏览器上报的 MIME 类型五花八门（xlsx 常被报成
// application/octet-stream）。xlsx 本质是 zip，因此头四个字节固定是
// PK\x03\x04，这个判据不会误判。
func DetectFormat(data []byte) Format {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 0x03, 0x04}) {
		return FormatXLSX
	}
	return FormatCSV
}

// Read 解析表格内容。
//
// 返回的行只包含至少有一个非空单元格的行；空行会被跳过但**不影响
// 其它行的 Number**，因为行号取自源文件本身而不是计数器。
func Read(data []byte, maxRows int) (*Sheet, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%w: 文件 %d 字节超过 %d 字节上限",
			ErrTooLarge, len(data), MaxFileSize)
	}
	if maxRows <= 0 {
		maxRows = MaxRows
	}

	switch DetectFormat(data) {
	case FormatXLSX:
		return readXLSX(data, maxRows)
	default:
		return readCSV(data, maxRows)
	}
}

// ------------------------------------------------------------------ xlsx

func readXLSX(data []byte, maxRows int) (*Sheet, error) {
	f, err := excelize.OpenReader(bytes.NewReader(data),
		excelize.Options{
			UnzipSizeLimit:    UnzipSizeLimit,
			UnzipXMLSizeLimit: UnzipXMLSizeLimit,
		})
	if err != nil {
		return nil, fmt.Errorf("spreadsheet: 无法解析 xlsx（文件可能已损坏或不是 Excel 文件）: %w", err)
	}
	defer func() { _ = f.Close() }()

	names := f.GetSheetList()
	if len(names) == 0 {
		return nil, ErrEmpty
	}
	// 只读第一张表：导入模板的第一张表就是数据表，第二张是填写说明。
	// 若改成「找名字最像数据表的那个」，用户改个表名就会导入失败。
	raw, err := f.GetRows(names[0])
	if err != nil {
		return nil, fmt.Errorf("spreadsheet: 读取工作表失败: %w", err)
	}

	sheet := &Sheet{Format: FormatXLSX}
	for i, cells := range raw {
		// excelize 的 GetRows 按行序返回（含中间的空行），因此下标 +1
		// 就是 Excel 里看到的行号。
		row, blank := normalizeRow(i+1, cells)
		if blank {
			sheet.skippedBlank++
			continue
		}
		// +1 是给「表头行」留的位置：上限约束的是数据行数，
		// 而这里还不知道哪一行是表头，因此用略宽松的界。
		if len(sheet.Rows) >= maxRows+1 {
			return nil, ErrTooManyRows
		}
		sheet.Rows = append(sheet.Rows, row)
	}
	if len(sheet.Rows) == 0 {
		return nil, ErrEmpty
	}
	return sheet, nil
}

// ------------------------------------------------------------------ csv

func readCSV(data []byte, maxRows int) (*Sheet, error) {
	text := decodeText(data)

	r := csv.NewReader(strings.NewReader(text))
	// 每行字段数可以不同：多出来的列由 normalizeRow 截断，少的补空。
	// 若保持默认的「字段数必须一致」，一个手改过的 CSV 会整份报错，
	// 而用户实际只想让系统告诉他第几行有问题。
	r.FieldsPerRecord = -1
	// 允许把裸引号当普通字符，而不是报「bare quote」——
	// 资产名里出现一个双引号不应该让整份文件无法导入。
	r.LazyQuotes = true

	sheet := &Sheet{Format: FormatCSV}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("spreadsheet: 解析 CSV 失败: %w", err)
		}

		// 行号取自 csv.Reader 自己记录的字段位置，而不是我们自己数的
		// 第几条记录。原因：csv.Reader **会跳过空行**，用记录序号
		// 当行号时，文件里每多一个空行，后面所有行的提示就整体偏移。
		line, _ := r.FieldPos(0)
		row, blank := normalizeRow(line, rec)
		if blank {
			sheet.skippedBlank++
			continue
		}
		if len(sheet.Rows) >= maxRows+1 {
			return nil, ErrTooManyRows
		}
		sheet.Rows = append(sheet.Rows, row)
	}

	if len(sheet.Rows) == 0 {
		return nil, ErrEmpty
	}
	return sheet, nil
}

// decodeText 把字节流解成 UTF-8 文本。
//
// 顺序：去 BOM → 合法 UTF-8 直接用 → 否则按 GBK 解。
//
// 「否则按 GBK 解」这个兜底有个需要说清楚的取舍：GBK 解码器对任意字节
// 序列都能返回结果（无效字节会被替换），因此它永远不会失败，也就没有
// 「两种编码都不像」这个分支。这在中文场景下是想要的——Excel 简体中文
// 版导出的 CSV 就是 GBK，而「UTF-8 校验失败」几乎必然意味着它是 GBK。
func decodeText(data []byte) string {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	if utf8.Valid(data) {
		return string(data)
	}
	decoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), data)
	if err != nil {
		// 理论上到不了这里（GBK 解码不报错），保留分支是为了万一
		// 将来换成会报错的解码器时行为仍然合理：降级成原始字节，
		// 让「乱码」而不是「整份文件失败」成为用户的观感。
		return string(data)
	}
	return string(decoded)
}

// ------------------------------------------------------------------ 通用

// normalizeRow 裁剪并规整一行，返回 (行, 是否为空行)。
func normalizeRow(number int, cells []string) (Row, bool) {
	// 去掉 Excel 那种「整行全选」留下的尾部空列，否则一行的长度可能是
	// 16384，而其中 16370 个是空串。
	end := len(cells)
	for end > 0 && strings.TrimSpace(cells[end-1]) == "" {
		end--
	}
	if end == 0 {
		return Row{}, true
	}
	if end > MaxColumns {
		end = MaxColumns
	}

	out := make([]string, end)
	for i := 0; i < end; i++ {
		out[i] = clampCell(cells[i])
	}
	return Row{Number: number, Cells: out}, false
}

// clampCell 裁掉首尾空白并限制长度。
//
// 只裁首尾不裁中间：单元格里的换行与多空格有时是用户刻意写的说明，
// 无声地压扁它们会让「备注」字段的内容与用户在 Excel 里看到的对不上。
func clampCell(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// 单元格里可能粘进不可见的制表符与不断行空格（从网页复制常见），
	// 它们会让「看起来一样」的两个值比较不相等。
	s = strings.ReplaceAll(s, "\u00a0", " ")
	if runes := []rune(s); len(runes) > MaxCellRunes {
		s = string(runes[:MaxCellRunes])
	}
	return s
}

// ------------------------------------------------------------------ 写出

// SheetSpec 一张待写出的工作表。
type SheetSpec struct {
	// Name 工作表名。Excel 限制 31 字符且不允许 : \ / ? * [ ]
	Name string
	// Header 表头。非空时会被加粗、着色并冻结首行。
	Header []string
	// Rows 数据行。
	Rows [][]string
	// TextColumns 需要强制为「文本」格式的列字母（如 "B"、"C"）。
	//
	// 不设的话，Excel 会把「00123」当成数字存，用户填的资产编号前导零
	// 会在他自己都没察觉的情况下丢掉；IP 地址也可能被自动转成日期。
	TextColumns []string
	// Widths 列宽（按列序对应），缺省用 18。
	Widths []float64
}

// WriteXLSX 生成 xlsx 字节流。
func WriteXLSX(sheets []SheetSpec) ([]byte, error) {
	if len(sheets) == 0 {
		return nil, errors.New("spreadsheet: 至少需要一张工作表")
	}

	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	// NewFile 自带一张 Sheet1，第一张目标表复用它改名，其余新建。
	// 这样做是为了避免产物里残留一张空的 Sheet1——下载下来打开发现
	// 有个莫名其妙的空表，是很典型的「看起来没做完」。
	defaultSheet := f.GetSheetName(0)

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Size: 11},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"409EFF"}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border: []excelize.Border{
			{Type: "left", Color: "DCDFE6", Style: 1},
			{Type: "top", Color: "DCDFE6", Style: 1},
			{Type: "bottom", Color: "DCDFE6", Style: 1},
			{Type: "right", Color: "DCDFE6", Style: 1},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("spreadsheet: 创建表头样式失败: %w", err)
	}

	// 内置数字格式 49 就是「文本」。
	textStyle, err := f.NewStyle(&excelize.Style{NumFmt: 49})
	if err != nil {
		return nil, fmt.Errorf("spreadsheet: 创建文本样式失败: %w", err)
	}

	for i, spec := range sheets {
		name := spec.Name
		if name == "" {
			name = fmt.Sprintf("Sheet%d", i+1)
		}

		if i == 0 {
			if err := f.SetSheetName(defaultSheet, name); err != nil {
				return nil, fmt.Errorf("spreadsheet: 重命名工作表失败: %w", err)
			}
		} else {
			if _, err := f.NewSheet(name); err != nil {
				return nil, fmt.Errorf("spreadsheet: 新建工作表失败: %w", err)
			}
		}

		if err := writeSheet(f, name, spec, headerStyle, textStyle); err != nil {
			return nil, err
		}
	}

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, fmt.Errorf("spreadsheet: 写出 xlsx 失败: %w", err)
	}
	return buf.Bytes(), nil
}

func writeSheet(f *excelize.File, name string, spec SheetSpec, headerStyle, textStyle int) error {
	row := 1

	if len(spec.Header) > 0 {
		// SetSheetRow 接受指向切片的指针，能一次写完一整行；
		// 逐格 SetCellValue 在 14 列 × N 行时会明显更慢，也更容易
		// 在坐标换算上写错。
		header := spec.Header
		if err := f.SetSheetRow(name, "A1", &header); err != nil {
			return fmt.Errorf("spreadsheet: 写入表头失败: %w", err)
		}
		lastCol, err := excelize.ColumnNumberToName(len(spec.Header))
		if err != nil {
			return fmt.Errorf("spreadsheet: 计算列字母失败: %w", err)
		}
		if err := f.SetCellStyle(name, "A1", lastCol+"1", headerStyle); err != nil {
			return fmt.Errorf("spreadsheet: 应用表头样式失败: %w", err)
		}
		// 冻结首行：5000 行的表往下滚时看不到列名，只能靠猜。
		if err := f.SetPanes(name, &excelize.Panes{
			Freeze: true, YSplit: 1, TopLeftCell: "A2",
			ActivePane: "bottomLeft",
			Selection: []excelize.Selection{
				{SQRef: "A2", ActiveCell: "A2", Pane: "bottomLeft"},
			},
		}); err != nil {
			return fmt.Errorf("spreadsheet: 冻结表头失败: %w", err)
		}
		row = 2
	}

	for i, data := range spec.Rows {
		cell, err := excelize.CoordinatesToCellName(1, row+i)
		if err != nil {
			return fmt.Errorf("spreadsheet: 计算单元格坐标失败: %w", err)
		}
		rowData := data
		if err := f.SetSheetRow(name, cell, &rowData); err != nil {
			return fmt.Errorf("spreadsheet: 写入数据行失败: %w", err)
		}
	}

	// 列宽
	widths := spec.Widths
	for i := 0; i < len(spec.Header); i++ {
		col, err := excelize.ColumnNumberToName(i + 1)
		if err != nil {
			return fmt.Errorf("spreadsheet: 计算列字母失败: %w", err)
		}
		width := 18.0
		if i < len(widths) && widths[i] > 0 {
			width = widths[i]
		}
		if err := f.SetColWidth(name, col, col, width); err != nil {
			return fmt.Errorf("spreadsheet: 设置列宽失败: %w", err)
		}
	}

	// 文本列：把整列（含表头之下的所有行）设成文本格式。
	// 从第 2 行开始，表头保持自己的样式。
	if len(spec.TextColumns) > 0 {
		endRow := row + len(spec.Rows) + 64 // 多留 64 行，用户往下补行时格式仍然生效
		for _, col := range spec.TextColumns {
			if err := f.SetCellStyle(name, col+"2", fmt.Sprintf("%s%d", col, endRow), textStyle); err != nil {
				return fmt.Errorf("spreadsheet: 应用文本格式失败: %w", err)
			}
		}
	}

	return nil
}

// IsZip 判断字节流是否是 zip（即 xlsx）。供外部在给出「不是 Excel 文件」
// 这类提示前做一个廉价判断，避免为一个明显不合法的输入去启动解析器。
func IsZip(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if !bytes.Equal(data[:4], []byte{'P', 'K', 0x03, 0x04}) {
		return false
	}
	// 真正校验一次 zip 目录，避免「前四字节对了但内容不是 zip」的伪造文件
	_, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	return err == nil
}
