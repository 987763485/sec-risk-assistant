package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/report"
	"secrisk/server/internal/repository"
)

// ReportResult 一次导出产出的文件。
type ReportResult struct {
	// Content 文件字节。
	//
	// 一次性读进内存而不是流式下发：这份数据本来就已经在内存里
	// （ReportData 的 5000 条明细），三种格式的产物都在个位数 MB。
	// 流式下发换不来什么，却会让「渲染成功但写到一半连接断了」变成一个
	// 用户拿到半个文件、服务端以为成功的状态——半个 xlsx 打不开，
	// 而用户会以为是文件本身坏了。
	Content []byte
	// FileName 下载文件名（已清洗，UTF-8，含扩展名）。
	FileName string
	// ContentType 响应的 MIME 类型。
	ContentType string
	// Format 导出格式（word / excel / pdf），供审计与日志使用。
	Format report.Format
}

// ReportService 报告导出服务。
//
// ▍为什么它不是 AssessmentService 的一组方法
//
// 报告导出的失败模式与评估业务完全不同：这条路径上有两个**外部进程**
// （docgen 的 .NET 与 Gotenberg 的 Chromium），会连接被拒、会超时、
// 会返回 5xx、需要重试与降级。把这些混进 AssessmentService，会让那个类
// 同时承担「业务规则」与「外部依赖编排」两件事——而后者是可以整体替换的
// （换渲染引擎不该动评估逻辑）。
//
// 但**取数**必须复用：走的是 AssessmentService.buildExportData，
// 与 /api/assessments/{id}/export-data 同一份实现。这一点是硬要求，
// 两条取数路径一旦分叉，「界面值 = 落库值 = 报告值」的第三个等号就断了。
type ReportService struct {
	assess *AssessmentService
	client *report.Client
	audit  *auditor
	logger *slog.Logger
}

// NewReportService 构建报告服务。
//
// client 允许为 nil：那表示部署里没有配任何渲染上游。此时 Excel 仍然可用
// （excelize 是纯 Go、进程内），Word 与 PDF 会返回 503。
// 这个选择不是刻意设计的特性，但它确实是对的——一个不需要外部依赖的功能，
// 不该被外部依赖拖垮，尤其是「上游没起来」这种部署期问题发生时，
// 用户至少还能拿到 Excel 去干活，而不是被一个空白页面挡住。
func NewReportService(
	repo *repository.Repository, assess *AssessmentService, client *report.Client, logger *slog.Logger,
) *ReportService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ReportService{
		assess: assess,
		client: client,
		audit:  newAuditor(repo, logger),
		logger: logger,
	}
}

// Export 渲染并返回报告文件。
//
// 成功返回时审计已经落库（审计失败只记日志、不影响本次导出，
// 理由见 auditor）。
func (s *ReportService) Export(
	ctx context.Context, p *auth.Principal, meta RequestMeta,
	assessmentID uint64, rawFormat string,
) (*ReportResult, error) {
	format, err := report.ParseFormat(rawFormat)
	if err != nil {
		// ParseFormat 的文案里已经列了可选值，直接透出即可——
		// 这里再包装一层只会把「可选：word / excel / pdf」这句话丢掉。
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, err.Error())
	}

	a, err := s.assess.findAssessment(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	// ▍未计算不可导出
	//
	// 草稿任务没有结果行，硬渲染会得到一份「0 条风险项」的报告。
	// 那份报告**看起来完全正常**：有封面、有目录、有矩阵（全 0）、
	// 有说明。收到它的人不会想到「这份评估其实还没跑」——他只会得出
	// 「这个系统的资产全都没风险」这个结论。这种错误比报错危险得多，
	// 因此必须在渲染之前拦住。
	if a.Status != model.AssessmentCalculated {
		return nil, newError(http.StatusConflict, errcode.CodeReportNotCalculated,
			"该评估任务尚未计算，没有可导出的结论。请先在评估执行页完成计算")
	}

	exportData, err := s.assess.buildExportData(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	// 矩阵单独取一次而不是从 export-data 里推：矩阵的格子由 riskengine
	// 按快照阈值定级，自己再按 R 推一遍就成了第二条判定路径。
	matrix, err := s.assess.Matrix(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	// 一次导出只用**一个** now：报告里的生成时间、页脚日期与文件名里的
	// 时间戳必须一致。跨零点导出时调用两次 time.Now() 会出现
	// 「页脚写着 23:59、文件名是次日」这种没法解释的差异。
	now := time.Now()
	data := toReportData(exportData, matrix, principalName(p), now)

	content, err := report.Render(ctx, s.client, format, data)
	if err != nil {
		return nil, s.renderError(ctx, a, format, err)
	}

	fileName := report.FileName(data, format, now)

	s.audit.record(ctx, auditEntryFor(p, meta, model.ActionReportExport, "assessment",
		fmt.Sprint(assessmentID), map[string]any{
			"name":             a.Name,
			"format":           string(format),
			"file_name":        fileName,
			"size_bytes":       len(content),
			"assets_count":     len(exportData.Assets),
			"risk_items_count": len(exportData.Items),
			"max_risk":         exportData.MaxRisk,
		}))

	return &ReportResult{
		Content:     content,
		FileName:    fileName,
		ContentType: format.ContentType(),
		Format:      format,
	}, nil
}

// renderError 把渲染失败翻译成业务错误。
//
// 三种情况分开，因为它们对用户意味着完全不同的下一步：
//
//	上游不可用（503）—— 稍后重试大概率就好了
//	调用方取消     —— 用户已经关掉页面，谁都不需要看到这句话
//	其余（500）    —— 系统自己有毛病（模板坏了、数据形态超出预期）
func (s *ReportService) renderError(
	ctx context.Context, a *model.Assessment, format report.Format, err error,
) error {
	// 先判取消：调用方取消时 err 里也含「网络层错误」的形态，
	// 若先撞上 ErrUpstream 分支，日志里会记一条「上游不可用」的假警报。
	if ctxErr := ctx.Err(); ctxErr != nil {
		s.logger.Info("报告导出被调用方中止",
			"assessment_id", a.ID, "format", string(format), "reason", ctxErr)
		return wrapError(http.StatusServiceUnavailable, errcode.CodeReportRenderFailed,
			"报告导出已中止", err)
	}

	if errors.Is(err, report.ErrUpstream) {
		s.logger.Error("报告渲染上游不可用",
			"assessment_id", a.ID, "format", string(format), "err", err)
		return wrapError(http.StatusServiceUnavailable, errcode.CodeReportRenderFailed,
			"报告渲染服务暂时不可用，请稍后重试", err)
	}

	s.logger.Error("报告渲染失败",
		"assessment_id", a.ID, "format", string(format), "err", err)
	return wrapError(http.StatusInternalServerError, errcode.CodeInternal,
		"生成报告失败，请联系管理员", err)
}

// ------------------------------------------------------------------ 视图映射

// toReportData 把接口视图映射成渲染器的输入。
//
// ▍这是一次「搬运」，不是一次「加工」
//
// A / T / V / R、条数、档位一律原样搬，一处都不重算。报告值 = 落库值
// 这条等式靠的就是这里不做任何算术——只要这里对某个数动了一次手
// （哪怕是「保留两位小数」这种看起来无害的格式化），等式就断了，
// 而且断在渲染器之外，守门脚本逐条比对数字时才会发现。
// 唯一被改写的是两个时间字段的**展示格式**，那是排版，不是数值。
//
// 序号（Seq）是个例外，它确实是「生成」的：用 1..N 的展示序号而不是
// 风险项的数据库主键。报告读者拿主键去系统里查不到东西——风险项没有
// 单独的详情页，主键对外没有意义，只会让人以为漏了页。
func toReportData(d *ExportDataView, m *MatrixView, generatedBy string, now time.Time) report.ReportData {
	a := d.Assessment

	assets := make([]report.AssetRow, 0, len(d.Assets))
	for _, v := range d.Assets {
		assets = append(assets, report.AssetRow{
			Name:       v.AssetName,
			IP:         v.AssetIP,
			Importance: v.Importance,
			ValueA:     v.AssetValueA,
			RiskValue:  v.RiskValue,
			RiskLevel:  v.RiskLevel,
			ItemsCount: v.RiskItemsCount,
		})
	}

	items := make([]report.ItemRow, 0, len(d.Items))
	for i := range d.Items {
		it := &d.Items[i]
		items = append(items, report.ItemRow{
			Seq:        i + 1,
			AssetName:  it.AssetName,
			AssetIP:    it.AssetIP,
			VulnTitle:  it.VulnTitle,
			ThreatName: it.ThreatName,
			Importance: it.Importance,
			Severity:   it.Severity,
			A:          it.AssetValueA,
			T:          it.ThreatWeight,
			V:          it.VulnWeight,
			R:          it.RiskValue,
			RiskLevel:  it.RiskLevel,
		})
	}

	cells := make([]report.MatrixCell, 0, len(m.Cells))
	for _, c := range m.Cells {
		cells = append(cells, report.MatrixCell{
			Importance: c.Importance,
			Severity:   c.Severity,
			Count:      c.Count,
			MaxRisk:    c.MaxRisk,
			Level:      c.Level,
		})
	}

	cfg := d.Config
	return report.ReportData{
		Title:       a.Name + " 网络安全风险评估报告",
		Subtitle:    "评估依据：GB/T 20984 相乘法",
		GeneratedAt: now,
		GeneratedBy: generatedBy,
		Assessment: report.AssessmentInfo{
			ID:                a.ID,
			Name:              a.Name,
			Description:       a.Description,
			ScopeType:         a.ScopeType,
			ScopeRef:          a.ScopeRef,
			DefaultThreatName: a.DefaultThreatName,
			AssetsCount:       a.AssetsCount,
			RiskItemsCount:    a.RiskItemsCount,
			CalculatedAt:      displayTime(a.CalculatedAt),
		},
		Config: report.ConfigInfo{
			Model:       cfg.Model,
			AssetWeight: cfg.AssetWeight,
			Thresholds: report.Thresholds{
				VeryHigh: cfg.Thresholds.VeryHigh,
				High:     cfg.Thresholds.High,
				Medium:   cfg.Thresholds.Medium,
				Low:      cfg.Thresholds.Low,
			},
			// 快照时间来自落库的 config_snapshot.captured_at（计算时刻），
			// **不是** now。报告里写的是「配置在计算时刻即被快照冻结」，
			// 填导出时刻会让这句话在事实上说谎。见 configForAssessment。
			CapturedAt: cfg.CapturedAt,
		},
		LevelCounts: d.LevelCounts,
		MaxRisk:     d.MaxRisk,
		Assets:      assets,
		Items:       items,
		Matrix: report.MatrixData{
			GridSize: m.GridSize,
			Total:    m.Total,
			Cells:    cells,
		},
	}
}

// displayTime 把 RFC3339 时间串转成报告里的展示格式。
//
// 接口下发 RFC3339（机器可读、带时区偏移），报告里要的是
// 「2026-10-11 13:00:00」。只在报告这一侧转换，接口契约不动——
// 让接口为了排版去改格式，是拿机器的可解析性换人的顺眼。
//
// 解析失败时原样返回：宁可报告里出现一串不好看的时间，
// 也不要把「时间丢了」伪装成「这里没有时间」。
func displayTime(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.Format("2006-01-02 15:04:05")
	}
	return raw
}
