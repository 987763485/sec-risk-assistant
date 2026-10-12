package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/riskengine"
	"secrisk/server/internal/repository"
)

// 评估相关的长度与数量上限。
const (
	assessNameMaxRunes = 128
	assessDescMaxRunes = 512
	// assessMaxScopeIDs 手工圈定范围时允许的最大条目数。
	// 圈 500 个以上的资产不叫「手工指定」，那叫「按条件筛选」——
	// 而这个模型里没有条件筛选，与其让它悄悄退化成全表，不如直接拒绝。
	assessMaxScopeIDs = 500
	// assessExportMaxItems 一次导出的风险项上限。见 errcode 里
	// ASSESSMENT_EXPORT_TOO_LARGE 的说明：截断的报告比报错的危险。
	assessExportMaxItems = 5000
	// previewTopItems 试算结果里返回的风险项条数（按 R 从高到低）。
	// 试算是给人看着调的，前 20 条足够判断阈值是否合理。
	previewTopItems = 20
	// previewMaxAssets 试算结果里返回的资产级汇总条数上限。
	previewMaxAssets = 200
	// riskItemMaxPageSize 风险项下钻单页上限。
	riskItemMaxPageSize = 200
)

// AssessmentView 评估任务对外视图。
type AssessmentView struct {
	ID                uint64               `json:"id"`
	Name              string               `json:"name"`
	Description       string               `json:"description"`
	Status            string               `json:"status"`
	ScopeType         string               `json:"scope_type"`
	ScopeRef          []uint64             `json:"scope_ref"`
	ModelKey          string               `json:"model_key"`
	DefaultThreatCode string               `json:"default_threat_code"`
	DefaultThreatName string               `json:"default_threat_name"`
	AssetsCount       uint32               `json:"assets_count"`
	RiskItemsCount    uint32               `json:"risk_items_count"`
	MaxRisk           *float64             `json:"max_risk"`
	LevelCounts       map[string]int       `json:"level_counts"`
	CalculatedAt      *string              `json:"calculated_at"`
	ConfigSnapshot    *riskengine.Snapshot `json:"config_snapshot"`
	CreatedAt         string               `json:"created_at"`
	UpdatedAt         string               `json:"updated_at"`
}

// RiskItemView 风险项对外视图。
//
// A / T / V / R 四个量一并下发：前端要能把「20 分」当场拆成 4 × 5 × 1，
// 这是「可解释」在接口层的具体形态。
type RiskItemView struct {
	ID              uint64  `json:"id"`
	AssessmentID    uint64  `json:"assessment_id"`
	AssetID         uint64  `json:"asset_id"`
	VulnID          uint64  `json:"vuln_id"`
	AssetName       string  `json:"asset_name"`
	AssetIP         string  `json:"asset_ip"`
	VulnTitle       string  `json:"vuln_title"`
	VulnCVEIDs      string  `json:"vuln_cve_ids"`
	VulnSeverityRaw string  `json:"vuln_severity_raw"`
	ThreatCode      string  `json:"threat_code"`
	ThreatName      string  `json:"threat_name"`
	ThreatSource    string  `json:"threat_source"`
	Importance      uint8   `json:"importance"`
	Severity        uint8   `json:"severity"`
	AssetValueA     float64 `json:"asset_value_a"`
	ThreatWeight    float64 `json:"threat_weight_t"`
	VulnWeight      float64 `json:"vuln_weight_v"`
	RiskValue       float64 `json:"risk_value_r"`
	RiskLevel       string  `json:"risk_level"`
}

// AssessmentAssetView 资产级汇总视图。
type AssessmentAssetView struct {
	AssetID        uint64  `json:"asset_id"`
	AssetName      string  `json:"asset_name"`
	AssetIP        string  `json:"asset_ip"`
	Importance     uint8   `json:"importance"`
	AssetValueA    float64 `json:"asset_value_a"`
	RiskValue      float64 `json:"risk_value"`
	RiskLevel      string  `json:"risk_level"`
	RiskItemsCount uint32  `json:"risk_items_count"`
	TopItemID      *uint64 `json:"top_item_id"`
}

// AssessmentListQuery 评估列表查询入参。
type AssessmentListQuery struct {
	Keyword  string
	Status   *string
	Page     int
	PageSize int
}

// CreateAssessmentInput 新建评估入参。
type CreateAssessmentInput struct {
	Name              string
	Description       string
	ScopeType         string
	ScopeRef          []uint64
	DefaultThreatCode string
}

// UpdateAssessmentInput 编辑评估入参（nil 表示不改）。
type UpdateAssessmentInput struct {
	Name              *string
	Description       *string
	ScopeType         *string
	ScopeRef          *[]uint64
	DefaultThreatCode *string
}

// PreviewInput 试算入参。
type PreviewInput struct {
	// AssessmentID 非空时按该任务的范围与默认威胁试算（评估执行页）；
	// 为空时用下面的临时参数试算（新建页还没有任务行可以指）。
	AssessmentID      *uint64
	ScopeType         string
	ScopeRef          []uint64
	DefaultThreatCode string
	// 可选的配置覆盖：让「阈值预览」能在保存前试。
	// 不传则用当前系统配置。
	AssetWeight *float64
	Thresholds  *riskengine.Thresholds
}

// PreviewResult 试算结果。
type PreviewResult struct {
	Config          riskengine.Snapshot   `json:"config"`
	ScopeType       string                `json:"scope_type"`
	ScopeRef        []uint64              `json:"scope_ref"`
	AssetsCount     int                   `json:"assets_count"`
	RiskItemsCount  int                   `json:"risk_items_count"`
	UnmatchedAssets int                   `json:"unmatched_assets"`
	MaxRisk         float64               `json:"max_risk"`
	LevelCounts     map[string]int        `json:"level_counts"`
	Assets          []AssessmentAssetView `json:"assets"`
	TopItems        []RiskItemView        `json:"top_items"`
}

// MatrixCellView 矩阵中的一个格子。
type MatrixCellView struct {
	Importance uint8   `json:"importance"`
	Severity   uint8   `json:"severity"`
	Count      int64   `json:"count"`
	MaxRisk    float64 `json:"max_risk"`
	Level      string  `json:"level"`
}

// MatrixView 风险矩阵。
type MatrixView struct {
	AssessmentID uint64           `json:"assessment_id"`
	GridSize     int              `json:"grid_size"`
	MaxGrade     int              `json:"max_grade"`
	Total        int64            `json:"total"`
	Cells        []MatrixCellView `json:"cells"`
}

// ExportDataView 报告数据的结构化形态。
//
// ▍这个接口为什么在 P4 就存在
//
// docs/01 给 P4 的验收标志是「界面值 = 落库值 = 报告值」三者一致。
// 报告要到 P5 的 docgen 才渲染，但「报告里的数字从哪来」必须现在就定死——
// 否则一致性要拖到 P5 才能验，P4 这句验收就没有着落。
// 于是这里提前落一个 export-data：它返回 P5 渲染器将要消费的那一份数据，
// 三方等式因此在本阶段就能逐条比对（见 scripts/verify-assess.sh）。
type ExportDataView struct {
	Assessment  ExportAssessmentView `json:"assessment"`
	Config      riskengine.Snapshot  `json:"config"`
	LevelCounts map[string]int       `json:"level_counts"`
	MaxRisk     float64              `json:"max_risk"`
	Assets      []ExportAssetView    `json:"assets"`
	Items       []RiskItemView       `json:"items"`
	GeneratedAt string               `json:"generated_at"`
}

// ExportAssessmentView 报告头部的评估信息。
type ExportAssessmentView struct {
	ID                uint64   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	ScopeType         string   `json:"scope_type"`
	ScopeRef          []uint64 `json:"scope_ref"`
	DefaultThreatCode string   `json:"default_threat_code"`
	DefaultThreatName string   `json:"default_threat_name"`
	AssetsCount       int      `json:"assets_count"`
	RiskItemsCount    int      `json:"risk_items_count"`
	CalculatedAt      string   `json:"calculated_at"`
}

// ExportAssetView 报告里的资产条目。
type ExportAssetView struct {
	AssetID        uint64  `json:"asset_id"`
	AssetName      string  `json:"asset_name"`
	AssetIP        string  `json:"asset_ip"`
	Importance     uint8   `json:"importance"`
	AssetValueA    float64 `json:"asset_value_a"`
	RiskValue      float64 `json:"risk_value"`
	RiskLevel      string  `json:"risk_level"`
	RiskItemsCount uint32  `json:"risk_items_count"`
}

// AssessmentService 风险评估服务。
type AssessmentService struct {
	repo   *repository.Repository
	cfgSvc *RiskConfigService
	audit  *auditor
	logger *slog.Logger
}

// NewAssessmentService 构建评估服务。
//
// 依赖 RiskConfigService 而不是直接读配置表：读取配置只有一条路径，
// 「哪里是权威」不留第二种可能。
func NewAssessmentService(
	repo *repository.Repository, cfgSvc *RiskConfigService, logger *slog.Logger,
) *AssessmentService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AssessmentService{
		repo:   repo,
		cfgSvc: cfgSvc,
		audit:  newAuditor(repo, logger),
		logger: logger,
	}
}

// ------------------------------------------------------------------ 查询

// List 分页查询评估任务。
func (s *AssessmentService) List(ctx context.Context, q AssessmentListQuery) ([]AssessmentView, int64, error) {
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.PageSize <= 0 || q.PageSize > 200 {
		q.PageSize = 20
	}

	rows, total, err := s.repo.Assessment.List(ctx, repository.AssessmentListQuery{
		Keyword: q.Keyword, Status: q.Status, Page: q.Page, PageSize: q.PageSize,
	})
	if err != nil {
		return nil, 0, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询评估任务失败", err)
	}

	names, err := s.threatNameMap(ctx)
	if err != nil {
		return nil, 0, err
	}

	views := make([]AssessmentView, 0, len(rows))
	for i := range rows {
		views = append(views, toAssessmentView(&rows[i], names))
	}
	return views, total, nil
}

// Get 查询单个评估任务。
func (s *AssessmentService) Get(ctx context.Context, id uint64) (*AssessmentView, error) {
	a, err := s.findAssessment(ctx, id)
	if err != nil {
		return nil, err
	}
	names, err := s.threatNameMap(ctx)
	if err != nil {
		return nil, err
	}
	view := toAssessmentView(a, names)
	return &view, nil
}

// ------------------------------------------------------------------ 增删改

// Create 新建评估任务。
func (s *AssessmentService) Create(
	ctx context.Context, p *auth.Principal, meta RequestMeta, in CreateAssessmentInput,
) (*AssessmentView, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "评估任务名称不能为空")
	}
	if len([]rune(name)) > assessNameMaxRunes {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("评估任务名称不得超过 %d 个字符", assessNameMaxRunes))
	}
	if len([]rune(in.Description)) > assessDescMaxRunes {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("说明不得超过 %d 个字符", assessDescMaxRunes))
	}

	scopeType, err := parseScopeType(in.ScopeType)
	if err != nil {
		return nil, err
	}
	scopeRef, err := s.validateScope(ctx, scopeType, in.ScopeRef)
	if err != nil {
		return nil, err
	}
	threatCode, err := s.validateThreat(ctx, in.DefaultThreatCode)
	if err != nil {
		return nil, err
	}

	scopeJSON, err := encodeScope(scopeRef)
	if err != nil {
		return nil, err
	}

	a := &model.Assessment{
		Name:              name,
		Description:       strings.TrimSpace(in.Description),
		Status:            model.AssessmentDraft,
		ScopeType:         scopeType,
		ScopeRef:          scopeJSON,
		ModelKey:          riskengine.Name,
		DefaultThreatCode: threatCode,
	}
	if p != nil {
		uid := p.UserID
		a.CreatedBy = &uid
	}

	if err := s.repo.Assessment.Create(ctx, a); err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "创建评估任务失败", err)
	}

	s.audit.record(ctx, auditEntryFor(p, meta, model.ActionAssessCreate, "assessment",
		fmt.Sprint(a.ID), map[string]any{
			"name":                a.Name,
			"scope_type":          string(a.ScopeType),
			"scope_count":         len(scopeRef),
			"default_threat_code": a.DefaultThreatCode,
		}))

	view, err := s.Get(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	return view, nil
}

// Update 编辑评估任务。
//
// 允许改范围与默认威胁，但**不自动重算**：改完任务仍停在原状态，
// 由用户显式点「重新计算」。理由与配置快照同源——「改了参数」与
// 「按新参数算出结果」是两件事，自动重算会让「我明明只改了个名字，
// 结果怎么全变了」变成一次找不到原因的投诉。
func (s *AssessmentService) Update(
	ctx context.Context, p *auth.Principal, meta RequestMeta, id uint64, in UpdateAssessmentInput,
) (*AssessmentView, error) {
	a, err := s.findAssessment(ctx, id)
	if err != nil {
		return nil, err
	}

	fields := map[string]any{}
	detail := map[string]any{}

	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "评估任务名称不能为空")
		}
		if len([]rune(name)) > assessNameMaxRunes {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
				fmt.Sprintf("评估任务名称不得超过 %d 个字符", assessNameMaxRunes))
		}
		fields["name"] = name
		detail["name"] = name
	}
	if in.Description != nil {
		if len([]rune(*in.Description)) > assessDescMaxRunes {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
				fmt.Sprintf("说明不得超过 %d 个字符", assessDescMaxRunes))
		}
		fields["description"] = strings.TrimSpace(*in.Description)
		detail["description"] = fields["description"]
	}
	if in.ScopeType != nil || in.ScopeRef != nil {
		rawType := string(a.ScopeType)
		if in.ScopeType != nil {
			rawType = *in.ScopeType
		}
		scopeType, err := parseScopeType(rawType)
		if err != nil {
			return nil, err
		}
		rawRef := []uint64(nil)
		if in.ScopeRef != nil {
			rawRef = *in.ScopeRef
		} else {
			existing, err := decodeScope(a)
			if err != nil {
				return nil, err
			}
			rawRef = existing
		}
		scopeRef, err := s.validateScope(ctx, scopeType, rawRef)
		if err != nil {
			return nil, err
		}
		scopeJSON, err := encodeScope(scopeRef)
		if err != nil {
			return nil, err
		}
		fields["scope_type"] = string(scopeType)
		fields["scope_ref"] = scopeJSON
		detail["scope_type"] = string(scopeType)
		detail["scope_count"] = len(scopeRef)
	}
	if in.DefaultThreatCode != nil {
		code, err := s.validateThreat(ctx, *in.DefaultThreatCode)
		if err != nil {
			return nil, err
		}
		fields["default_threat_code"] = code
		detail["default_threat_code"] = code
	}

	if len(fields) == 0 {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "没有需要更新的字段")
	}

	if err := s.repo.Assessment.Update(ctx, id, fields); err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "更新评估任务失败", err)
	}

	s.audit.record(ctx, auditEntryFor(p, meta, model.ActionAssessUpdate, "assessment",
		fmt.Sprint(id), detail))

	view, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return view, nil
}

// Delete 删除评估任务。结果行由外键 CASCADE 清理。
func (s *AssessmentService) Delete(ctx context.Context, p *auth.Principal, meta RequestMeta, id uint64) error {
	a, err := s.findAssessment(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.Assessment.Delete(ctx, id); err != nil {
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal, "删除评估任务失败", err)
	}
	s.audit.record(ctx, auditEntryFor(p, meta, model.ActionAssessDelete, "assessment",
		fmt.Sprint(id), map[string]any{"name": a.Name, "status": string(a.Status)}))
	return nil
}

// ------------------------------------------------------------------ 试算

// Preview 试算：**只读**，不写任何结果行。
//
// 与 Calculate 共用同一个 build（即同一份 riskengine 调用），
// 这是「界面值 = 落库值」在实现层面的保证：两条路径不存在第二套算法。
func (s *AssessmentService) Preview(ctx context.Context, in PreviewInput) (*PreviewResult, error) {
	cfg, err := s.cfgSvc.currentConfig(ctx)
	if err != nil {
		return nil, err
	}
	// 允许请求覆盖配置（阈值预览用），但仍要过一遍同样的自洽校验。
	if in.AssetWeight != nil || in.Thresholds != nil {
		weight := cfg.AssetWeightValue()
		th := cfg.Thresholds()
		if in.AssetWeight != nil {
			weight = *in.AssetWeight
		}
		if in.Thresholds != nil {
			th = *in.Thresholds
		}
		cfg, err = riskengine.ParseConfig(weight, th.VeryHigh, th.High, th.Medium, th.Low)
		if err != nil {
			return nil, newError(http.StatusBadRequest, errcode.CodeRiskConfigInvalid, err.Error())
		}
	}

	// 组装「临时评估」：任务试算复用它的范围与默认威胁，
	// 新建页试算用请求里带的参数。
	probe := &model.Assessment{
		ScopeType:         model.ScopeAll,
		ModelKey:          riskengine.Name,
		DefaultThreatCode: strings.TrimSpace(in.DefaultThreatCode),
	}
	var overrides map[repository.ItemKey]string

	if in.AssessmentID != nil {
		a, err := s.findAssessment(ctx, *in.AssessmentID)
		if err != nil {
			return nil, err
		}
		probe = a
		overrides, err = s.repo.Assessment.ManualThreatOverrides(ctx, a.ID)
		if err != nil {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
				"读取威胁覆盖失败", err)
		}
	} else {
		scopeType, err := parseScopeType(in.ScopeType)
		if err != nil {
			return nil, err
		}
		scopeRef, err := s.validateScope(ctx, scopeType, in.ScopeRef)
		if err != nil {
			return nil, err
		}
		if _, err := s.validateThreat(ctx, in.DefaultThreatCode); err != nil {
			return nil, err
		}
		scopeJSON, err := encodeScope(scopeRef)
		if err != nil {
			return nil, err
		}
		probe.ScopeType = scopeType
		probe.ScopeRef = scopeJSON
	}

	built, err := s.build(ctx, probe, cfg, overrides)
	if err != nil {
		return nil, err
	}

	// 资产汇总按 R 从高到低截断：试算页面右侧展示的是「最该先看的那几台」。
	// 排序在 build 里已经做过，这里只负责截断。
	assets := make([]AssessmentAssetView, 0, len(built.Summaries))
	for i := range built.Summaries {
		if len(assets) >= previewMaxAssets {
			break
		}
		assets = append(assets, toAssessmentAssetView(&built.Summaries[i]))
	}

	// RiskItemView 是值类型切片，逐个取地址会触发拷贝告警（gosec G601），
	// 因此用下标取址。
	top := make([]RiskItemView, 0, previewTopItems)
	for i := range built.Items {
		if len(top) >= previewTopItems {
			break
		}
		top = append(top, toRiskItemView(&built.Items[i]))
	}

	scopeType := probe.ScopeType
	scopeRef, err := decodeScope(probe)
	if err != nil {
		return nil, err
	}
	// 必须显式非 nil 化：`all` 范围下 decodeScope 返回 nil，而 nil 切片
	// 在 JSON 里是 `null` 不是 `[]`，前端 `scope_ref.length` 会当场炸。
	// 契约写的是「all 时为空数组」，实现就得是空数组。
	if scopeRef == nil {
		scopeRef = []uint64{}
	}

	return &PreviewResult{
		Config:          riskengine.SnapshotOf(cfg, time.Now()),
		ScopeType:       string(scopeType),
		ScopeRef:        scopeRef,
		AssetsCount:     len(built.Assets),
		RiskItemsCount:  len(built.Items),
		UnmatchedAssets: built.UnmatchedAssets,
		MaxRisk:         built.MaxRisk,
		LevelCounts:     built.LevelCounts,
		Assets:          assets,
		TopItems:        top,
	}, nil
}

// ------------------------------------------------------------------ 计算

// Calculate 计算并落库（幂等：重复执行是覆盖而不是追加）。
func (s *AssessmentService) Calculate(
	ctx context.Context, p *auth.Principal, meta RequestMeta, id uint64,
) (*AssessmentView, error) {
	a, err := s.findAssessment(ctx, id)
	if err != nil {
		return nil, err
	}

	cfg, err := s.cfgSvc.currentConfig(ctx)
	if err != nil {
		return nil, err
	}

	// 1) 取逐项覆盖。重算只刷新「算出来的部分」，用户逐条调整过的威胁
	//    选择必须保留——否则一次「重新计算」就悄悄回退了他半小时的调整。
	overrides, err := s.repo.Assessment.ManualThreatOverrides(ctx, id)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取威胁覆盖失败", err)
	}

	built, err := s.build(ctx, a, cfg, overrides)
	if err != nil {
		return nil, err
	}

	snapshot := riskengine.SnapshotOf(cfg, time.Now())
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "序列化配置快照失败", err)
	}
	snapStr := string(snapshotJSON)

	// 2) 事务内「先清后写」。清空放在事务里而不是事务外，是为了让
	//    「旧的删掉了、新的没写进去」这种状态不可能被其它请求看见。
	err = s.repo.Transaction(ctx, func(tx *repository.Repository) error {
		if err := tx.Assessment.DeleteResults(ctx, id); err != nil {
			return err
		}
		// GORM 会把自增主键回填进 built.Items，供下面取 top_item_id。
		if err := tx.Assessment.CreateRiskItems(ctx, built.Items); err != nil {
			return err
		}
		for i := range built.Summaries {
			idx, ok := built.TopItemIndex[built.Summaries[i].AssetID]
			if !ok || idx < 0 || idx >= len(built.Items) {
				continue
			}
			itemID := built.Items[idx].ID
			built.Summaries[i].TopItemID = &itemID
		}
		if err := tx.Assessment.CreateAssessmentAssets(ctx, built.Summaries); err != nil {
			return err
		}
		return tx.Assessment.Update(ctx, id, summaryFields(built, snapStr, time.Now()))
	})
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "计算评估结果失败", err)
	}

	s.audit.record(ctx, auditEntryFor(p, meta, model.ActionAssessCalculate, "assessment",
		fmt.Sprint(id), map[string]any{
			"name":             a.Name,
			"assets_count":     len(built.Assets),
			"risk_items_count": len(built.Items),
			"max_risk":         built.MaxRisk,
			"level_counts":     built.LevelCounts,
			"config_snapshot":  snapshot,
		}))

	view, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return view, nil
}

// ------------------------------------------------------------------ 结果

// RiskItemListQuery 风险项列表查询入参。
//
// 定义在 service 而不是直接复用 repository 的查询结构：handler 应当只认识
// service 的类型，否则「handler 只碰 service」这条分层纪律会在参数类型上
// 先破一个口子，而这个口子迟早会变成 handler 直接调仓储。
type RiskItemListQuery struct {
	Importance *uint8
	Severity   *uint8
	Level      *string
	Keyword    string
	Page       int
	PageSize   int
}

// ListRiskItems 分页查询风险项（含矩阵下钻过滤）。
func (s *AssessmentService) ListRiskItems(
	ctx context.Context, assessmentID uint64, q RiskItemListQuery,
) ([]RiskItemView, int64, error) {
	if _, err := s.findAssessment(ctx, assessmentID); err != nil {
		return nil, 0, err
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.PageSize <= 0 || q.PageSize > riskItemMaxPageSize {
		q.PageSize = 20
	}

	rows, total, err := s.repo.Assessment.ListRiskItems(ctx, repository.RiskItemQuery{
		AssessmentID: assessmentID,
		Importance:   q.Importance,
		Severity:     q.Severity,
		Level:        q.Level,
		Keyword:      q.Keyword,
		Page:         q.Page,
		PageSize:     q.PageSize,
	})
	if err != nil {
		return nil, 0, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询风险项失败", err)
	}
	views := make([]RiskItemView, 0, len(rows))
	for i := range rows {
		views = append(views, toRiskItemView(&rows[i]))
	}
	return views, total, nil
}

// Matrix 返回 5×5 风险矩阵（资产重要性 × 漏洞严重程度）。
//
// 返回**全部 25 个格子**（空格 count=0）而不是稀疏的命中格子：
// 热力图的形状必须固定，否则同一个评估在两次加载之间格子位置会变，
// 而「昨天这块是红的」这种判断依赖于位置稳定。
func (s *AssessmentService) Matrix(ctx context.Context, assessmentID uint64) (*MatrixView, error) {
	a, err := s.findAssessment(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	cfg, _, err := s.configForAssessment(ctx, a)
	if err != nil {
		return nil, err
	}

	cells, err := s.repo.Assessment.Matrix(ctx, assessmentID)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "聚合风险矩阵失败", err)
	}

	byKey := make(map[[2]uint8]repository.MatrixCell, len(cells))
	var total int64
	for _, c := range cells {
		byKey[[2]uint8{c.Importance, c.Severity}] = c
		total += c.Count
	}

	out := make([]MatrixCellView, 0, riskengine.GridSize*riskengine.GridSize)
	for i := riskengine.MinGrade; i <= riskengine.MaxGrade; i++ {
		for j := riskengine.MinGrade; j <= riskengine.MaxGrade; j++ {
			cell := MatrixCellView{Importance: uint8(i), Severity: uint8(j)}
			if hit, ok := byKey[[2]uint8{uint8(i), uint8(j)}]; ok {
				cell.Count = hit.Count
				cell.MaxRisk = hit.MaxRisk
			}
			cell.Level = riskengine.LevelOfValue(cfg, cell.MaxRisk)
			out = append(out, cell)
		}
	}

	return &MatrixView{
		AssessmentID: assessmentID,
		GridSize:     riskengine.GridSize,
		MaxGrade:     riskengine.MaxGrade,
		Total:        total,
		Cells:        out,
	}, nil
}

// ExportData 导出报告数据（带审计）。
//
// 见 ExportDataView 的注释：这个接口是「报告值」这一路在 P4 就位的关键，
// 它让三方等式（界面 / 落库 / 报告）在本阶段就能逐条比对。
func (s *AssessmentService) ExportData(
	ctx context.Context, p *auth.Principal, meta RequestMeta, assessmentID uint64,
) (*ExportDataView, error) {
	view, err := s.buildExportData(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	s.audit.record(ctx, auditEntryFor(p, meta, model.ActionAssessExport, "assessment",
		fmt.Sprint(assessmentID), map[string]any{
			"name":             view.Assessment.Name,
			"assets_count":     len(view.Assets),
			"risk_items_count": len(view.Items),
		}))

	return view, nil
}

// buildExportData 组装报告数据，**不写审计**。
//
// ▍为什么与 ExportData 拆开
//
// P5 增加了第二个消费方：ReportService 渲染 Word / Excel / PDF 时也要这份
// 数据。若它直接调 ExportData，一次「导出报告」会在审计里同时留下
// assessment.export 与 report.export 两条——而前者在那条链路上根本没有
// 发生过（没有任何请求打到 /export-data）。审计里出现没发生过的动作，
// 比漏记一条更糟：它会让人怀疑整套审计的可信度。
//
// 于是切成「取数只有一条路径，审计由各自入口负责」。取数路径唯一这一点
// 是硬要求——两条取数逻辑一旦分叉，「界面值 = 落库值 = 报告值」里的
// 第三个等号就断了，而且不报错。
func (s *AssessmentService) buildExportData(
	ctx context.Context, assessmentID uint64,
) (*ExportDataView, error) {
	a, err := s.findAssessment(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	items, err := s.repo.Assessment.ListAllRiskItems(ctx, assessmentID, assessExportMaxItems+1)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询风险项失败", err)
	}
	if len(items) > assessExportMaxItems {
		return nil, newError(http.StatusBadRequest, errcode.CodeAssessmentExportTooLarge,
			fmt.Sprintf("该评估的风险项超过 %d 条，无法一次性导出报告，请先缩小评估范围",
				assessExportMaxItems))
	}

	summaries, err := s.repo.Assessment.ListAssessmentAssets(ctx, assessmentID)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询资产汇总失败", err)
	}

	cfg, capturedAt, err := s.configForAssessment(ctx, a)
	if err != nil {
		return nil, err
	}
	// 草稿（没有快照）时 capturedAt 是零值，回落成「现在」：
	// 报告里那格不能是 0001-01-01。已算过的评估一定带快照，走不到这里。
	if capturedAt.IsZero() {
		capturedAt = time.Now()
	}

	names, err := s.threatNameMap(ctx)
	if err != nil {
		return nil, err
	}

	itemViews := make([]RiskItemView, 0, len(items))
	for i := range items {
		itemViews = append(itemViews, toRiskItemView(&items[i]))
	}
	assetViews := make([]ExportAssetView, 0, len(summaries))
	for _, sm := range summaries {
		assetViews = append(assetViews, ExportAssetView{
			AssetID:        sm.AssetID,
			AssetName:      sm.AssetName,
			AssetIP:        sm.AssetIP,
			Importance:     sm.Importance,
			AssetValueA:    sm.AssetValueA,
			RiskValue:      sm.RiskValue,
			RiskLevel:      string(sm.RiskLevel),
			RiskItemsCount: sm.RiskItemsCount,
		})
	}

	levelCounts := map[string]int{}
	var maxRisk float64
	for _, it := range items {
		levelCounts[string(it.RiskLevel)]++
		if it.RiskValue > maxRisk {
			maxRisk = it.RiskValue
		}
	}
	fillLevelCounts(levelCounts)

	calculatedAt := ""
	if a.CalculatedAt != nil {
		calculatedAt = a.CalculatedAt.Format(time.RFC3339)
	}

	return &ExportDataView{
		Assessment: ExportAssessmentView{
			ID:                a.ID,
			Name:              a.Name,
			Description:       a.Description,
			ScopeType:         string(a.ScopeType),
			ScopeRef:          scopeRefOrEmpty(a),
			DefaultThreatCode: a.DefaultThreatCode,
			DefaultThreatName: names[a.DefaultThreatCode],
			AssetsCount:       len(summaries),
			RiskItemsCount:    len(items),
			CalculatedAt:      calculatedAt,
		},
		Config:      riskengine.SnapshotOf(cfg, capturedAt),
		LevelCounts: levelCounts,
		MaxRisk:     maxRisk,
		Assets:      assetViews,
		Items:       itemViews,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}, nil
}

// SetRiskItemThreat 逐项覆盖某风险项的威胁，并立即重算该条与所在评估的汇总。
func (s *AssessmentService) SetRiskItemThreat(
	ctx context.Context, p *auth.Principal, meta RequestMeta,
	assessmentID, itemID uint64, threatCode string,
) (*RiskItemView, error) {
	if _, err := s.findAssessment(ctx, assessmentID); err != nil {
		return nil, err
	}

	item, err := s.repo.Assessment.FindRiskItemByID(ctx, itemID)
	if err != nil {
		if errors.Is(err, repository.ErrRiskItemNotFound) {
			return nil, errRiskItemNotFound()
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询风险项失败", err)
	}
	if item.AssessmentID != assessmentID {
		// 用 404 而不是 403：路径里的评估 ID 与风险项不匹配时，
		// 对外应当与「这个风险项不存在」完全一样，不让调用方据此探测
		// 别的评估里有哪些风险项。
		return nil, errRiskItemNotFound()
	}

	a, err := s.findAssessment(ctx, item.AssessmentID)
	if err != nil {
		return nil, err
	}

	code, err := s.validateThreat(ctx, threatCode)
	if err != nil {
		return nil, err
	}

	// 用**该评估的快照配置**重算，不是当前配置：这条风险项属于那次评估。
	cfg, _, err := s.configForAssessment(ctx, a)
	if err != nil {
		return nil, err
	}

	// 威胁权重与名称一次取全，避免先按名称映射查一次、再按权重查一次
	// 同一个字典——两次查询之间字典被改动的话，落库的 name 与 weight
	// 就会来自两个不同的版本。
	weight := riskengine.DefaultThreatWeight
	name := ""
	if code != "" {
		dict, err := s.repo.Dictionary.Resolve(ctx, model.CategoryThreat)
		if err != nil {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取威胁字典失败", err)
		}
		if d, ok := dict[code]; ok {
			weight = d.Weight
			name = d.Name
		} else {
			name = code
		}
	}

	result := riskengine.Compute(cfg, riskengine.Input{
		Importance:   item.Importance,
		ThreatWeight: weight,
		Severity:     item.Severity,
	})

	err = s.repo.Transaction(ctx, func(tx *repository.Repository) error {
		if err := tx.Assessment.UpdateRiskItem(ctx, itemID, map[string]any{
			"threat_code":     code,
			"threat_name":     name,
			"threat_source":   model.ThreatSourceManual,
			"asset_value_a":   result.A,
			"threat_weight_t": result.T,
			"vuln_weight_v":   result.V,
			"risk_value_r":    result.R,
			"risk_level":      result.Level,
		}); err != nil {
			return err
		}
		// 一条风险项的 R 变了，它的资产级汇总与整个评估的汇总都要跟着动，
		// 否则「界面值 = 落库值」从这一刻起就不成立了。
		if err := tx.Assessment.RebuildAssetSummaries(ctx, item.AssessmentID, assessExportMaxItems); err != nil {
			return err
		}
		agg, err := tx.Assessment.LevelAggregate(ctx, item.AssessmentID)
		if err != nil {
			return err
		}
		assetsCount, err := tx.Assessment.CountAssetSummary(ctx, item.AssessmentID)
		if err != nil {
			return err
		}
		return tx.Assessment.Update(ctx, item.AssessmentID, summaryFieldsFromAgg(agg, int(assetsCount)))
	})
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "更新风险项失败", err)
	}

	s.audit.record(ctx, auditEntryFor(p, meta, model.ActionAssessItemUpdate, "risk_item",
		fmt.Sprint(itemID), map[string]any{
			"assessment_id": item.AssessmentID,
			"asset_name":    item.AssetName,
			"vuln_title":    item.VulnTitle,
			"threat_code":   code,
			"risk_value_r":  result.R,
			"risk_level":    result.Level,
		}))

	updated, err := s.repo.Assessment.FindRiskItemByID(ctx, itemID)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询风险项失败", err)
	}
	view := toRiskItemView(updated)
	return &view, nil
}

// ------------------------------------------------------------------ 内部

// buildOutcome build 的产出。
type buildOutcome struct {
	Assets          []model.Asset
	Items           []model.RiskItem
	Summaries       []model.AssessmentAsset
	TopItemIndex    map[uint64]int
	LevelCounts     map[string]int
	MaxRisk         float64
	UnmatchedAssets int
}

// build 按评估范围组装全部风险项（**不落库**）。
//
// Preview 与 Calculate 都走这一个函数，两者的差别只在「算完之后写不写库」。
// 这是「不允许存在第二条计算路径」的落点——只要有两份组装逻辑，
// 界面值与落库值迟早会在某个边界条件下分叉，而分叉不报错。
func (s *AssessmentService) build(
	ctx context.Context, a *model.Assessment, cfg riskengine.Config,
	overrides map[repository.ItemKey]string,
) (*buildOutcome, error) {
	groupIDs, assetIDs, err := decodeScopeSplit(a)
	if err != nil {
		return nil, err
	}

	assets, err := s.repo.Assessment.AssetsByScope(ctx, string(a.ScopeType), groupIDs, assetIDs)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "按范围查询资产失败", err)
	}

	out := &buildOutcome{
		Assets:       assets,
		Summaries:    make([]model.AssessmentAsset, 0, len(assets)),
		TopItemIndex: map[uint64]int{},
		LevelCounts:  map[string]int{},
	}
	if len(assets) == 0 {
		fillLevelCounts(out.LevelCounts)
		return out, nil
	}

	assetByID := make(map[uint64]*model.Asset, len(assets))
	ids := make([]uint64, len(assets))
	for i := range assets {
		assetByID[assets[i].ID] = &assets[i]
		ids[i] = assets[i].ID
	}

	pairs, err := s.repo.Assessment.VulnPairsByAssets(ctx, ids)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询漏洞关联失败", err)
	}

	vulnIDSet := make(map[uint64]struct{}, len(pairs))
	for _, p := range pairs {
		vulnIDSet[p.VulnID] = struct{}{}
	}
	vulnIDs := make([]uint64, 0, len(vulnIDSet))
	for id := range vulnIDSet {
		vulnIDs = append(vulnIDs, id)
	}
	vulns, err := s.repo.Assessment.VulnsByIDs(ctx, vulnIDs)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "批量查询漏洞失败", err)
	}

	threats, err := s.repo.Dictionary.Resolve(ctx, model.CategoryThreat)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取威胁字典失败", err)
	}

	perAsset := make(map[uint64]int, len(assets)) // assetID → Summaries 下标
	touched := make(map[uint64]struct{}, len(assets))

	for _, pair := range pairs {
		asset := assetByID[pair.AssetID]
		vuln, ok := vulns[pair.VulnID]
		if asset == nil || !ok {
			// 理论上不可达：pairs 来自 vuln_asset_links（vuln_id 有外键），
			// assets 来自同一批 id。真出现了也只是这一对被跳过，
			// 不让它把整次计算带崩。
			continue
		}

		code := strings.TrimSpace(a.DefaultThreatCode)
		source := model.ThreatSourceDefault
		if override, has := overrides[repository.ItemKey{AssetID: pair.AssetID, VulnID: pair.VulnID}]; has && strings.TrimSpace(override) != "" {
			code = strings.TrimSpace(override)
			source = model.ThreatSourceManual
		}

		weight := riskengine.DefaultThreatWeight
		name := ""
		if code != "" {
			if d, has := threats[code]; has {
				weight = d.Weight
				name = d.Name
			} else {
				// 威胁码在字典里查不到（被删了，或被停用后清理过）。
				// 不报错、不静默改成默认值：把原码显示出来，
				// 用户一眼就能看出「这条的威胁配置失效了」。
				name = code
			}
		}

		res := riskengine.Compute(cfg, riskengine.Input{
			Importance:   asset.Importance,
			ThreatWeight: weight,
			Severity:     vuln.Severity,
		})

		out.Items = append(out.Items, model.RiskItem{
			AssessmentID:    a.ID,
			AssetID:         asset.ID,
			VulnID:          vuln.ID,
			AssetName:       asset.Name,
			AssetIP:         asset.IPAddress,
			VulnTitle:       vuln.Title,
			VulnCVEIDs:      vuln.CVEIDs,
			VulnSeverityRaw: vuln.SeverityRaw,
			ThreatCode:      code,
			ThreatName:      name,
			ThreatSource:    source,
			Importance:      asset.Importance,
			Severity:        vuln.Severity,
			AssetValueA:     res.A,
			ThreatWeight:    res.T,
			VulnWeight:      res.V,
			RiskValue:       res.R,
			RiskLevel:       model.RiskLevel(res.Level),
		})

		touched[asset.ID] = struct{}{}
		idx, ok := perAsset[asset.ID]
		if !ok {
			idx = len(out.Summaries)
			perAsset[asset.ID] = idx
			out.Summaries = append(out.Summaries, model.AssessmentAsset{
				AssessmentID: a.ID,
				AssetID:      asset.ID,
				AssetName:    asset.Name,
				AssetIP:      asset.IPAddress,
				Importance:   asset.Importance,
				AssetValueA:  res.A,
			})
		}
		sm := &out.Summaries[idx]
		sm.RiskItemsCount++
		// 资产级风险由最严重的一条决定（不是平均）：一台机器能被打穿到
		// 什么程度，取决于它最弱的那一环。
		if res.R > sm.RiskValue {
			sm.RiskValue = res.R
			sm.RiskLevel = model.RiskLevel(res.Level)
			out.TopItemIndex[asset.ID] = len(out.Items) - 1
		}
	}

	// 资产汇总按 R 从高到低：报告与试算页面展示的都是「最该先看的那几台」，
	// 顺序在源头定死，省得每个消费端各排一次（也就各排得不一样一次）。
	sort.SliceStable(out.Summaries, func(i, j int) bool {
		if out.Summaries[i].RiskValue != out.Summaries[j].RiskValue {
			return out.Summaries[i].RiskValue > out.Summaries[j].RiskValue
		}
		return out.Summaries[i].AssetID < out.Summaries[j].AssetID
	})

	for _, it := range out.Items {
		out.LevelCounts[string(it.RiskLevel)]++
		if it.RiskValue > out.MaxRisk {
			out.MaxRisk = it.RiskValue
		}
	}
	fillLevelCounts(out.LevelCounts)
	out.UnmatchedAssets = len(assets) - len(touched)

	// 风险项按 R 从高到低重排。契约里 `top_items` 写的是「风险值最高的
	// 风险项」，报告也要「最严重的排前面」——顺序在源头定死，省得每个
	// 消费端各排一次（也就各排得不一样一次）。
	//
	// ⚠️ 重排必须与 TopItemIndex 的**重建**配套。TopItemIndex 存的是切片
	//    下标，而 Calculate 要用它去取 CreateRiskItems 回填的自增 ID；
	//    重排后旧下标全部失效，若不重建，TopItemID 会指到别的资产的行上去
	//    （而且不会报错，只是下钻跳错页面）。因为已按 R 降序，
	//    每个资产首次出现的位置就是它最大 R 的那一条。
	sort.SliceStable(out.Items, func(i, j int) bool {
		if out.Items[i].RiskValue != out.Items[j].RiskValue {
			return out.Items[i].RiskValue > out.Items[j].RiskValue
		}
		if out.Items[i].AssetID != out.Items[j].AssetID {
			return out.Items[i].AssetID < out.Items[j].AssetID
		}
		return out.Items[i].VulnID < out.Items[j].VulnID
	})
	out.TopItemIndex = make(map[uint64]int, len(out.Summaries))
	for i := range out.Items {
		if _, ok := out.TopItemIndex[out.Items[i].AssetID]; !ok {
			out.TopItemIndex[out.Items[i].AssetID] = i
		}
	}

	return out, nil
}

// summaryFields 组装 assessments 行的汇总列（calculate 路径）。
//
// 直接用内存里刚算好的值，不去数据库再聚合一遍：那批数据就是本次计算的
// 结果，再查一次不但多一轮 IO，还会因为两次聚合的时点不同而引入
// 「刚写的行被别的请求改了」这种理论上的不一致。
func summaryFields(out *buildOutcome, snapshotJSON string, at time.Time) map[string]any {
	levelJSON, _ := json.Marshal(out.LevelCounts)
	return map[string]any{
		"assets_count":     len(out.Summaries),
		"risk_items_count": len(out.Items),
		"max_risk":         out.MaxRisk,
		"level_counts":     string(levelJSON),
		"config_snapshot":  snapshotJSON,
		"status":           string(model.AssessmentCalculated),
		"calculated_at":    at,
	}
}

// summaryFieldsFromAgg 由等级聚合结果组装汇总列（逐项覆盖后的重算路径）。
func summaryFieldsFromAgg(agg []repository.LevelAgg, assetsCount int) map[string]any {
	counts := map[string]int{}
	var total int64
	var maxRisk float64
	for _, a := range agg {
		counts[a.Level] = int(a.Count)
		total += a.Count
		if a.MaxRisk > maxRisk {
			maxRisk = a.MaxRisk
		}
	}
	fillLevelCounts(counts)
	levelJSON, _ := json.Marshal(counts)
	return map[string]any{
		"assets_count":     assetsCount,
		"risk_items_count": total,
		"max_risk":         maxRisk,
		"level_counts":     string(levelJSON),
		"calculated_at":    time.Now(),
	}
}

// configForAssessment 取该评估应当使用的配置，以及这份配置的**快照时间**。
//
// 已算过的评估一律用**快照**：历史评估必须可复现，改一次阈值不能把
// 三个月前的报告结论一起改掉（迁移 000006 约束 1）。
// 没算过的（草稿）没有快照，只能用当前配置——反正草稿还没有结果可言。
//
// ▍第二个返回值为什么必须存在
//
// 调用方**不能**用 `riskengine.SnapshotOf(cfg, time.Now())` 自己补快照时间。
// 报告里写的是「配置在计算时刻即被快照冻结，快照时间：X」——那句话的主语
// 是**计算时刻**。用 time.Now() 会把导出那一刻的墙上时间填进去，
// 于是报告在事实上说谎：它声称的那份阈值，其实不是那个时间点冻结的。
// 这个错误不会让任何断言变红，只会让半年后拿着报告复盘的人对不上账。
//
// 返回零值 time.Time 表示「用的不是快照，是当前配置」，调用方自行决定
// 展示成什么（Export 会回落成生成时刻）。
func (s *AssessmentService) configForAssessment(
	ctx context.Context, a *model.Assessment,
) (riskengine.Config, time.Time, error) {
	if a.ConfigSnapshot != nil && strings.TrimSpace(*a.ConfigSnapshot) != "" {
		var snap riskengine.Snapshot
		if err := json.Unmarshal([]byte(*a.ConfigSnapshot), &snap); err == nil {
			cfg, err := riskengine.ParseConfig(
				snap.AssetWeight, snap.Thresholds.VeryHigh, snap.Thresholds.High,
				snap.Thresholds.Medium, snap.Thresholds.Low)
			if err == nil {
				return cfg, snap.CapturedAt, nil
			}
			s.logger.Warn("评估任务的配置快照不合法，回退到当前配置",
				"assessment_id", a.ID, "err", err)
		} else {
			s.logger.Warn("评估任务的配置快照无法解析，回退到当前配置",
				"assessment_id", a.ID, "err", err)
		}
	}
	cfg, err := s.cfgSvc.currentConfig(ctx)
	if err != nil {
		return riskengine.Config{}, time.Time{}, err
	}
	return cfg, time.Time{}, nil
}

// findAssessment 查询评估任务，归一化「不存在」的错误。
func (s *AssessmentService) findAssessment(ctx context.Context, id uint64) (*model.Assessment, error) {
	a, err := s.repo.Assessment.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrAssessmentNotFound) {
			return nil, newError(http.StatusNotFound, errcode.CodeAssessmentNotFound, "评估任务不存在")
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询评估任务失败", err)
	}
	return a, nil
}

// threatNameMap 返回威胁码 → 名称映射。
func (s *AssessmentService) threatNameMap(ctx context.Context) (map[string]string, error) {
	items, err := s.repo.Dictionary.Resolve(ctx, model.CategoryThreat)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取威胁字典失败", err)
	}
	out := make(map[string]string, len(items))
	for code, d := range items {
		out[code] = d.Name
	}
	return out, nil
}

// validateThreat 校验威胁码。空串合法（表示未指定）。
func (s *AssessmentService) validateThreat(ctx context.Context, raw string) (string, error) {
	code := strings.TrimSpace(raw)
	if code == "" {
		return "", nil
	}
	items, err := s.repo.Dictionary.Resolve(ctx, model.CategoryThreat)
	if err != nil {
		return "", wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取威胁字典失败", err)
	}
	d, ok := items[code]
	if !ok {
		return "", newError(http.StatusBadRequest, errcode.CodeThreatNotFound,
			"威胁「"+code+"」不存在")
	}
	if !d.Enabled {
		return "", newError(http.StatusBadRequest, errcode.CodeThreatNotFound,
			"威胁「"+d.Name+"」已停用，请先在字典中启用它")
	}
	return code, nil
}

// parseScopeType 解析并校验范围类型。
func parseScopeType(raw string) (model.AssessmentScopeType, error) {
	t := model.AssessmentScopeType(strings.TrimSpace(raw))
	if !t.Valid() {
		return "", newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			"评估范围只能是 all / group / custom")
	}
	return t, nil
}

// validateScope 校验范围明细并归一化。
//
// 三条规则：
//   - all    范围明细必须为空（有值说明前端传错了，静默忽略会让用户
//     以为自己圈定的范围生效了）；
//   - group  / custom 明细不能为空，且每个 ID 必须真实存在；
//   - 明细条数上限 500。
func (s *AssessmentService) validateScope(
	ctx context.Context, scopeType model.AssessmentScopeType, ref []uint64,
) ([]uint64, error) {
	cleaned := dedupUint64(ref)

	if scopeType == model.ScopeAll {
		if len(cleaned) > 0 {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
				"范围类型为「全部资产」时不应指定具体资产或资产组")
		}
		return nil, nil
	}

	if len(cleaned) == 0 {
		return nil, newError(http.StatusBadRequest, errcode.CodeAssessmentScopeEmpty,
			"请至少选择一个资产组或一个资产")
	}
	if len(cleaned) > assessMaxScopeIDs {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("手工指定的范围最多 %d 项", assessMaxScopeIDs))
	}

	switch scopeType {
	case model.ScopeGroup:
		groups, err := s.repo.AssetGroup.ListAll(ctx)
		if err != nil {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询资产组失败", err)
		}
		known := make(map[uint64]struct{}, len(groups))
		for _, g := range groups {
			known[g.ID] = struct{}{}
		}
		for _, id := range cleaned {
			if _, ok := known[id]; !ok {
				return nil, newError(http.StatusBadRequest, errcode.CodeAssetGroupNotFound,
					fmt.Sprintf("资产组 %d 不存在", id))
			}
		}
	case model.ScopeCustom:
		assets, err := s.repo.Asset.ListByIDs(ctx, cleaned)
		if err != nil {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询资产失败", err)
		}
		if len(assets) != len(cleaned) {
			return nil, newError(http.StatusBadRequest, errcode.CodeAssetNotFound,
				"部分资产不存在或已被删除")
		}
	}
	return cleaned, nil
}

// -------------------------------------------------------------- 编解码

// encodeScope 把范围明细编码成 JSON 字符串；空明细返回 nil（SQL NULL）。
func encodeScope(ids []uint64) (*string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "序列化评估范围失败", err)
	}
	s := string(raw)
	return &s, nil
}

// decodeScope 解出范围明细（按范围类型返回对应的一组 ID）。
func decodeScope(a *model.Assessment) ([]uint64, error) {
	groupIDs, assetIDs, err := decodeScopeSplit(a)
	if err != nil {
		return nil, err
	}
	if a.ScopeType == model.ScopeGroup {
		return groupIDs, nil
	}
	return assetIDs, nil
}

// decodeScopeSplit 按范围类型把明细拆成「组 ID」与「资产 ID」两组。
func decodeScopeSplit(a *model.Assessment) (groupIDs, assetIDs []uint64, err error) {
	if a.ScopeRef == nil || strings.TrimSpace(*a.ScopeRef) == "" {
		return nil, nil, nil
	}
	var ids []uint64
	if err := json.Unmarshal([]byte(*a.ScopeRef), &ids); err != nil {
		return nil, nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"评估范围数据损坏", err)
	}
	switch a.ScopeType {
	case model.ScopeGroup:
		return ids, nil, nil
	case model.ScopeCustom:
		return nil, ids, nil
	default:
		// all 却带着明细：数据层不该出现，但真出现了也不让它改变语义，
		// 仍然按「全部资产」处理（AssetsByScope 只看 scopeType）。
		return nil, nil, nil
	}
}

// scopeRefOrEmpty 返回范围明细，出错时返回空切片（用于展示，不是关键路径）。
func scopeRefOrEmpty(a *model.Assessment) []uint64 {
	ids, err := decodeScope(a)
	if err != nil {
		return []uint64{}
	}
	if ids == nil {
		return []uint64{}
	}
	return ids
}

// -------------------------------------------------------------- 视图转换

// fillLevelCounts 把缺失的等级补成 0。
//
// 前端要按固定顺序渲染五个等级，map 里少一个键就得在模板里写一堆 `|| 0`。
func fillLevelCounts(counts map[string]int) {
	for _, l := range riskengine.Levels {
		if _, ok := counts[l]; !ok {
			counts[l] = 0
		}
	}
}

// toAssessmentView 转评估视图。
func toAssessmentView(a *model.Assessment, threatNames map[string]string) AssessmentView {
	counts := map[string]int{}
	if a.LevelCounts != nil && strings.TrimSpace(*a.LevelCounts) != "" {
		_ = json.Unmarshal([]byte(*a.LevelCounts), &counts)
	}
	fillLevelCounts(counts)

	var snapshot *riskengine.Snapshot
	if a.ConfigSnapshot != nil && strings.TrimSpace(*a.ConfigSnapshot) != "" {
		var snap riskengine.Snapshot
		if err := json.Unmarshal([]byte(*a.ConfigSnapshot), &snap); err == nil {
			snapshot = &snap
		}
	}

	var calculatedAt *string
	if a.CalculatedAt != nil {
		v := a.CalculatedAt.Format(time.RFC3339)
		calculatedAt = &v
	}

	return AssessmentView{
		ID:                a.ID,
		Name:              a.Name,
		Description:       a.Description,
		Status:            string(a.Status),
		ScopeType:         string(a.ScopeType),
		ScopeRef:          scopeRefOrEmpty(a),
		ModelKey:          a.ModelKey,
		DefaultThreatCode: a.DefaultThreatCode,
		DefaultThreatName: threatNames[a.DefaultThreatCode],
		AssetsCount:       a.AssetsCount,
		RiskItemsCount:    a.RiskItemsCount,
		MaxRisk:           a.MaxRisk,
		LevelCounts:       counts,
		CalculatedAt:      calculatedAt,
		ConfigSnapshot:    snapshot,
		CreatedAt:         a.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         a.UpdatedAt.Format(time.RFC3339),
	}
}

// toRiskItemView 转风险项视图。
func toRiskItemView(item *model.RiskItem) RiskItemView {
	return RiskItemView{
		ID:              item.ID,
		AssessmentID:    item.AssessmentID,
		AssetID:         item.AssetID,
		VulnID:          item.VulnID,
		AssetName:       item.AssetName,
		AssetIP:         item.AssetIP,
		VulnTitle:       item.VulnTitle,
		VulnCVEIDs:      item.VulnCVEIDs,
		VulnSeverityRaw: item.VulnSeverityRaw,
		ThreatCode:      item.ThreatCode,
		ThreatName:      item.ThreatName,
		ThreatSource:    item.ThreatSource,
		Importance:      item.Importance,
		Severity:        item.Severity,
		AssetValueA:     item.AssetValueA,
		ThreatWeight:    item.ThreatWeight,
		VulnWeight:      item.VulnWeight,
		RiskValue:       item.RiskValue,
		RiskLevel:       string(item.RiskLevel),
	}
}

// toAssessmentAssetView 转资产级汇总视图。
func toAssessmentAssetView(sm *model.AssessmentAsset) AssessmentAssetView {
	return AssessmentAssetView{
		AssetID:        sm.AssetID,
		AssetName:      sm.AssetName,
		AssetIP:        sm.AssetIP,
		Importance:     sm.Importance,
		AssetValueA:    sm.AssetValueA,
		RiskValue:      sm.RiskValue,
		RiskLevel:      string(sm.RiskLevel),
		RiskItemsCount: sm.RiskItemsCount,
		TopItemID:      sm.TopItemID,
	}
}

// dedupUint64 去重并保持顺序稳定。
func dedupUint64(in []uint64) []uint64 {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[uint64]struct{}, len(in))
	out := make([]uint64, 0, len(in))
	for _, v := range in {
		if v == 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// errRiskItemNotFound 风险项不存在。
func errRiskItemNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeRiskItemNotFound, "风险项不存在")
}
