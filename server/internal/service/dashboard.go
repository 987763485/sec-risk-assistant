package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/repository"
)

const (
	// dashboardTopAssets 仪表盘「最危险的资产」展示条数。
	dashboardTopAssets = 5
	// dashboardDueSoonDays 与 remediationDueSoonDays 保持一致：
	// 仪表盘上「即将到期」的那个数字和列表页 `?due_within=7` 筛出来的条数
	// 必须是同一个数，否则用户会开始怀疑两个页面的数据。
	dashboardDueSoonDays = remediationDueSoonDays
)

// DashboardSummary 首页统计。
//
// ▍口径问题是仪表盘的头号陷阱（见 docs/13 D6）
//
// 同一个「很高风险有多少条」，在四种口径下能给出四个不同的数字：
// 全部评估累加、每次评估取平均、最近一次评估、某个指定评估。
// 累加会把「上周算过、这周又算过」的同一条风险计两次；
// 而界面上只写「很高 37 条」时，没有任何人能从数字本身看出用的是哪种口径。
//
// 因此这里采取两条硬约束：
//
//  1. **风险相关的数字全部绑定一个具体的评估**，并把那个评估的
//     ID / 名称 / 计算时间一并回传（`assessments.latest`），
//     界面上必须把它显示出来；
//  2. 资产、漏洞、整改单是**全局当前态**，与评估无关，不受口径影响。
type DashboardSummary struct {
	GeneratedAt        string                   `json:"generated_at"`
	Assets             DashboardAssets          `json:"assets"`
	Vulnerabilities    DashboardVulnerabilities `json:"vulnerabilities"`
	Assessments        DashboardAssessments     `json:"assessments"`
	Remediations       DashboardRemediations    `json:"remediations"`
	RecentRemediations []RemediationView        `json:"recent_remediations"`
}

// DashboardAssets 资产概览。
type DashboardAssets struct {
	Total int64 `json:"total"`
	// ByType 按资产类型分布，**含已报废资产**（与 total 同一口径），
	// 名称取自字典；字典里查不到的码（历史数据、已删字典项）name 留空，
	// 前端显示原始码——这类条目恰恰最该被看见。
	ByType []DashboardNamedCount `json:"by_type"`
	// Scrapped 已报废数量。单独给出来，是为了让 total 与资产列表页
	// 对得上时用户不会困惑「怎么有这么多资产」。
	Scrapped int64 `json:"scrapped"`
}

// DashboardNamedCount 带展示名的计数（仪表盘通用）。
type DashboardNamedCount struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// DashboardVulnerabilities 漏洞概览。
type DashboardVulnerabilities struct {
	Total int64 `json:"total"`
	// BySeverity 按 1–5 档位分布，**五个档位一定都在**（没有的填 0），
	// 与 level_counts / by_status 同一约定：固定形状才能固定渲染。
	BySeverity []DashboardSeverityCount `json:"by_severity"`
}

// DashboardSeverityCount 按严重程度档位的计数。
type DashboardSeverityCount struct {
	Severity uint8 `json:"severity"`
	Count    int64 `json:"count"`
}

// DashboardAssessments 评估任务概览。
type DashboardAssessments struct {
	Total      int64 `json:"total"`
	Calculated int64 `json:"calculated"`
	Draft      int64 `json:"draft"`
	// Latest 风险数字的口径来源。
	//
	// 三种可能：调用方显式传了 assessment_id → 就是它；
	// 没传 → 最近一次**已计算**的评估；库里一次都没算过 → nil。
	// nil 是合法状态（刚初始化的系统），前端显示空态而不是报错。
	Latest *DashboardLatestAssessment `json:"latest"`
}

// DashboardLatestAssessment 风险数字所依附的那一次评估。
type DashboardLatestAssessment struct {
	ID     uint64 `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// CalculatedAt 已计算时有值；显式查询了一个草稿评估时为空。
	CalculatedAt   *string             `json:"calculated_at"`
	AssetsCount    int                 `json:"assets_count"`
	RiskItemsCount int                 `json:"risk_items_count"`
	MaxRisk        *float64            `json:"max_risk"`
	LevelCounts    map[string]int      `json:"level_counts"`
	TopAssets      []DashboardTopAsset `json:"top_assets"`
}

// DashboardTopAsset 风险值最高的资产。
type DashboardTopAsset struct {
	AssetID        uint64  `json:"asset_id"`
	AssetName      string  `json:"asset_name"`
	AssetIP        string  `json:"asset_ip"`
	RiskValue      float64 `json:"risk_value"`
	RiskLevel      string  `json:"risk_level"`
	RiskItemsCount uint32  `json:"risk_items_count"`
}

// DashboardRemediations 整改单概览。
type DashboardRemediations struct {
	Total  int64 `json:"total"`
	Active int64 `json:"active"`
	// ByStatus 五个状态**一定都在**（没有的填 0）。
	ByStatus map[string]int64 `json:"by_status"`
	// Overdue 逾期未闭环条数（due_date < 今天 且 未闭环）。
	Overdue int64 `json:"overdue"`
	// DueSoon 未来 DueWithinDays 天内到期（含今天）且未闭环的条数。
	//
	// 与 Overdue 的区间**不重叠**：今天到期的算 DueSoon 不算 Overdue。
	// 重叠的话同一个单子会在两个数字里各出现一次，用户会以为有两张单子。
	DueSoon       int64 `json:"due_soon"`
	DueWithinDays int   `json:"due_within_days"`
}

// DashboardService 首页统计服务。
//
// 它是**只读的聚合服务**：不写库、不留审计（读操作本就不留），
// 也不做任何风险计算——所有风险数字直接取 P4 已落库的结果
// （见 docs/13 §4.3：P6 不引入新的计算）。
type DashboardService struct {
	repo   *repository.Repository
	logger *slog.Logger
	// now 与 RemediationService 同一个注入点。两个服务必须用**同一个**
	// 「今天」——仪表盘上的「逾期 N 条」与整改列表页 `?overdue=true`
	// 筛出来的条数是同一个数，若各自取时刻，跨零点时会对不上。
	now func() time.Time
}

// NewDashboardService 构建仪表盘服务。
func NewDashboardService(repo *repository.Repository, logger *slog.Logger) *DashboardService {
	if logger == nil {
		logger = slog.Default()
	}
	return &DashboardService{repo: repo, logger: logger, now: time.Now}
}

// Summary 汇总首页统计。
//
// assessmentID 为 0 时取最近一次已计算评估；显式给出时必须存在（否则 404），
// 但**允许是一个草稿** —— 此时风险区块按「尚未计算」返回全零并带上
// status=draft，让前端能解释清楚为什么是空的，而不是 500 或一句 409。
func (s *DashboardService) Summary(
	ctx context.Context, assessmentID uint64,
) (*DashboardSummary, error) {
	assets, err := s.assets(ctx)
	if err != nil {
		return nil, err
	}
	vulns, err := s.vulnerabilities(ctx)
	if err != nil {
		return nil, err
	}
	assessments, err := s.assessments(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	remediations, err := s.remediations(ctx)
	if err != nil {
		return nil, err
	}
	recent, err := s.recentRemediations(ctx)
	if err != nil {
		return nil, err
	}

	return &DashboardSummary{
		GeneratedAt:        s.now().Format(time.RFC3339),
		Assets:             *assets,
		Vulnerabilities:    *vulns,
		Assessments:        *assessments,
		Remediations:       *remediations,
		RecentRemediations: recent,
	}, nil
}

// ------------------------------------------------------------------ 各区块

func (s *DashboardService) assets(ctx context.Context) (*DashboardAssets, error) {
	total, err := s.repo.Asset.CountAll(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "统计资产失败", err)
	}
	byType, err := s.repo.Asset.TypeCounts(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "统计资产类型分布失败", err)
	}
	byStatus, err := s.repo.Asset.StatusCounts(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "统计资产状态分布失败", err)
	}

	// 名称取自字典（含停用项：停用类型的资产仍然存在于台账里，
	// 显示成空白会让人以为数据坏了）。查不到的码 name 留空。
	names, err := s.dictionaryNames(ctx, model.CategoryAssetType)
	if err != nil {
		return nil, err
	}

	out := &DashboardAssets{
		Total:    total,
		Scrapped: byStatus[string(model.AssetStatusScrapped)],
		ByType:   make([]DashboardNamedCount, 0, len(byType)),
	}
	codes := make([]string, 0, len(byType))
	for code := range byType {
		codes = append(codes, code)
	}
	// 按数量倒序、同数量按码排序：仪表盘的图例顺序必须在两次刷新之间稳定，
	// 否则同一份数据每次打开都是另一种排列。
	sort.Slice(codes, func(i, j int) bool {
		if byType[codes[i]] != byType[codes[j]] {
			return byType[codes[i]] > byType[codes[j]]
		}
		return codes[i] < codes[j]
	})
	for _, code := range codes {
		out.ByType = append(out.ByType, DashboardNamedCount{
			Code:  code,
			Name:  names[code],
			Count: byType[code],
		})
	}
	return out, nil
}

func (s *DashboardService) vulnerabilities(ctx context.Context) (*DashboardVulnerabilities, error) {
	total, err := s.repo.Vuln.CountAll(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "统计漏洞失败", err)
	}
	bySeverity, err := s.repo.Vuln.SeverityCounts(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"统计漏洞严重程度分布失败", err)
	}

	out := &DashboardVulnerabilities{
		Total:      total,
		BySeverity: make([]DashboardSeverityCount, 0, model.SeverityMax),
	}
	for v := model.SeverityMin; v <= model.SeverityMax; v++ {
		out.BySeverity = append(out.BySeverity, DashboardSeverityCount{
			Severity: v,
			Count:    bySeverity[v],
		})
	}
	return out, nil
}

func (s *DashboardService) assessments(
	ctx context.Context, assessmentID uint64,
) (*DashboardAssessments, error) {
	total, err := s.repo.Assessment.CountAll(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "统计评估失败", err)
	}
	byStatus, err := s.repo.Assessment.StatusCounts(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"统计评估状态分布失败", err)
	}

	out := &DashboardAssessments{
		Total:      total,
		Calculated: byStatus[string(model.AssessmentCalculated)],
		Draft:      byStatus[string(model.AssessmentDraft)],
	}

	var target *model.Assessment
	if assessmentID > 0 {
		a, err := s.repo.Assessment.FindByID(ctx, assessmentID)
		if err != nil {
			if errors.Is(err, repository.ErrAssessmentNotFound) {
				return nil, newError(http.StatusNotFound, errcode.CodeAssessmentNotFound, "评估任务不存在")
			}
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
				"查询评估任务失败", err)
		}
		target = a
	} else {
		a, err := s.repo.Assessment.FindLatestCalculated(ctx)
		if err != nil {
			if errors.Is(err, repository.ErrAssessmentNotFound) {
				// 一次都没算过：合法的空场景，不是错误。
				return out, nil
			}
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
				"查询最近一次评估失败", err)
		}
		target = a
	}

	latest := &DashboardLatestAssessment{
		ID:             target.ID,
		Name:           target.Name,
		Status:         string(target.Status),
		AssetsCount:    int(target.AssetsCount),
		RiskItemsCount: int(target.RiskItemsCount),
		MaxRisk:        target.MaxRisk,
		LevelCounts:    levelCountsOf(target),
		TopAssets:      []DashboardTopAsset{},
	}
	if target.CalculatedAt != nil {
		v := target.CalculatedAt.Format(time.RFC3339)
		latest.CalculatedAt = &v
	}
	if target.Status == model.AssessmentCalculated {
		rows, err := s.repo.Assessment.TopRiskAssets(ctx, target.ID, dashboardTopAssets)
		if err != nil {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
				"查询高风险资产失败", err)
		}
		for _, row := range rows {
			latest.TopAssets = append(latest.TopAssets, DashboardTopAsset{
				AssetID:        row.AssetID,
				AssetName:      row.AssetName,
				AssetIP:        row.AssetIP,
				RiskValue:      row.RiskValue,
				RiskLevel:      string(row.RiskLevel),
				RiskItemsCount: row.RiskItemsCount,
			})
		}
	}
	out.Latest = latest
	return out, nil
}

func (s *DashboardService) remediations(ctx context.Context) (*DashboardRemediations, error) {
	rows, err := s.repo.Remediation.StatusCounts(ctx)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"统计整改单分布失败", err)
	}
	counts := make(map[model.RemediationStatus]int64, len(rows))
	for _, row := range rows {
		counts[model.RemediationStatus(row.Status)] = row.Count
	}

	// 由状态集合**派生** total / active，而不是另查两次 COUNT(*)：
	// 「五状态之和」与「total」若分别查，两次查询之间的新单会让它们对不上，
	// 界面上表现为「加起来比总数少一张」，而这是最难解释的一类不一致。
	byStatus := make(map[string]int64, len(model.RemediationStatuses))
	var total, active int64
	for _, st := range model.RemediationStatuses {
		n := counts[st]
		byStatus[string(st)] = n
		total += n
		if st.IsActive() {
			active += n
		}
	}

	today := s.now()
	overdue, err := s.repo.Remediation.CountOverdue(ctx, today)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"统计逾期整改单失败", err)
	}
	dueSoon, err := s.repo.Remediation.CountDueWithin(ctx, today, dashboardDueSoonDays)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"统计即将到期整改单失败", err)
	}

	return &DashboardRemediations{
		Total:         total,
		Active:        active,
		ByStatus:      byStatus,
		Overdue:       overdue,
		DueSoon:       dueSoon,
		DueWithinDays: dashboardDueSoonDays,
	}, nil
}

func (s *DashboardService) recentRemediations(ctx context.Context) ([]RemediationView, error) {
	rows, err := s.repo.Remediation.ListRecent(ctx, remediationRecentLimit)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询最近整改动态失败", err)
	}

	seen := map[uint64]struct{}{}
	ids := make([]uint64, 0, len(rows)*2)
	add := func(p *uint64) {
		if p == nil {
			return
		}
		if _, ok := seen[*p]; ok {
			return
		}
		seen[*p] = struct{}{}
		ids = append(ids, *p)
	}
	for i := range rows {
		add(rows[i].AssigneeID)
		add(rows[i].CreatedBy)
	}
	names, err := s.repo.User.NamesByIDs(ctx, ids)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询用户显示名失败", err)
	}

	today := s.now()
	out := make([]RemediationView, 0, len(rows))
	for i := range rows {
		out = append(out, toRemediationView(&rows[i], today, names))
	}
	return out, nil
}

// ------------------------------------------------------------------ 辅助

// dictionaryNames 取某类目下的 码 → 名称。
//
// enabledOnly=false：停用项也要能解析出来。资产台账里可能留着一条
// 「类型已停用」的资产，把它显示成空白的类型名只会让人以为数据坏了。
// 字典类目本身查不到任何项时返回空 map（不报错）——那是合法状态。
func (s *DashboardService) dictionaryNames(
	ctx context.Context, category model.DictionaryCategory,
) (map[string]string, error) {
	items, err := s.repo.Dictionary.List(ctx, []model.DictionaryCategory{category}, false)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询字典失败", err)
	}
	out := make(map[string]string, len(items))
	for _, it := range items {
		out[it.Code] = it.Name
	}
	return out, nil
}

// levelCountsOf 解析评估行里的 level_counts，并补齐五个等级。
//
// JSON 解析失败时**不报错**，而是返回全零：这个字段是展示用的汇总，
// 让它把整个仪表盘打成 500 是不划算的；而全零至少是「看得出不对」的。
// 同时补零由 fillLevelCounts 完成，与 P4 视图走同一条路径
// —— 两处各写一份补零逻辑，迟早会有一处忘了改。
func levelCountsOf(a *model.Assessment) map[string]int {
	counts := map[string]int{}
	if a.LevelCounts != nil && strings.TrimSpace(*a.LevelCounts) != "" {
		_ = json.Unmarshal([]byte(*a.LevelCounts), &counts)
	}
	fillLevelCounts(counts)
	return counts
}
