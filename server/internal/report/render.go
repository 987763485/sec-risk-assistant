package report

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Render 把 ReportData 渲染成指定格式的字节流。
//
// 这是本包唯一的对外入口。三种格式走三条完全不同的技术路线：
//
//	word  → docgen（C#/OpenXML）
//	excel → excelize（纯 Go，进程内）
//	pdf   → html/template → Gotenberg（Chromium）
//
// 但对调用方来说是同一个签名——service 层不需要知道「Excel 不用起容器」
// 这种实现细节，也就不需要为它写一条特殊分支。
func Render(ctx context.Context, client *Client, format Format, data ReportData) ([]byte, error) {
	switch format {
	case FormatWord:
		return client.RenderDocx(ctx, buildWordRequest(data))

	case FormatExcel:
		// 纯进程内，不依赖任何上游服务——因此 Excel 导出在上游挂掉时
		// 依然可用。这不是刻意设计出来的特性，但它确实是对的：
		// 一个不需要外部依赖的功能不应该被外部依赖拖垮。
		return buildExcel(data)

	case FormatPDF:
		htmlBytes, err := buildHTML(data)
		if err != nil {
			return nil, err
		}
		return client.RenderPDF(ctx, string(htmlBytes), pdfFooterHTML(data))

	default:
		return nil, fmt.Errorf("不支持的导出格式 %q", format)
	}
}

// 文件名长度上限（不含扩展名）。
//
// 与 docgen 侧 SanitizeFileName 的 80 保持一致：两边都用「字符数」而不是
// 字节数，中文名才不会被拦腰截断。超长文件名在部分客户端会被整体丢弃，
// 用户拿到一个叫 "download" 的文件。
const fileNameMaxRunes = 80

// FileName 生成下载文件名：`{评估名}_{格式}_{时间}.{ext}`。
//
// 时间戳精确到分钟：连续导出同一份报告时不会互相覆盖，同时又不会长到
// 影响阅读。秒级精度带来的额外区分度，收益低于名字变长的代价。
func FileName(data ReportData, format Format, at time.Time) string {
	base := SanitizeFileName(data.Assessment.Name)
	return fmt.Sprintf("%s_%s_%s.%s",
		base, format.Label(), at.Format("20060102-1504"), format.Ext())
}

// SanitizeFileName 清洗文件名。
//
// ▍为什么必须清洗
//
// 名字来自用户录入的评估名称，而它要进 Content-Disposition 响应头。
// 不清洗的话：
//   - 一个含 `"` 或换行的名字可以**注入响应头**（CRLF injection）；
//   - 一个含 `/` 或 `\` 的名字会让部分客户端把它当路径；
//   - 控制字符会让某些浏览器直接拒绝保存。
//
// 保留中日韩汉字与常规可打印字符，其余一律换成下划线 —— 与 docgen 侧的
// 规则一致（那一侧也要生成文件名，两处规则不同会出现"下载的 docx 与
// 我们声称的文件名不一样"）。
func SanitizeFileName(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "评估报告"
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		// unicode.IsLetter 已覆盖中日韩汉字（它们的 Unicode 类别就是 Lo）
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}

	out := strings.Trim(strings.TrimSpace(b.String()), ".")
	if out == "" {
		return "评估报告"
	}
	if runes := []rune(out); len(runes) > fileNameMaxRunes {
		out = string(runes[:fileNameMaxRunes])
	}
	return out
}
