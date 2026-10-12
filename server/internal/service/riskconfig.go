package service

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/riskengine"
	"secrisk/server/internal/repository"
)

// riskConfigPrefix 风险模型配置的键前缀。
const riskConfigPrefix = "risk."

// RiskConfigItemView 单项配置的展示形态。
//
// 顺带把 value_type / description / editable 一起给前端：配置页要渲染一个
// 「字段 + 说明 + 能不能改」，把这些写死在前端意味着新增一个配置项要改两处。
type RiskConfigItemView struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	ValueType   string `json:"value_type"`
	Description string `json:"description"`
	Editable    bool   `json:"editable"`
}

// RiskConfigView 风险模型配置。
//
// 结构化的三个字段（model / asset_weight / thresholds）是**给程序用的**，
// 前端直接用它们渲染表单与调试信息；Items 是**给人看的**原始行，
// 用来显示每一项的说明与可编辑性。两者并存不冗余：前者是语义，后者是出处。
type RiskConfigView struct {
	Model       string                `json:"model"`
	AssetWeight float64               `json:"asset_weight"`
	Thresholds  riskengine.Thresholds `json:"thresholds"`
	UpdatedAt   string                `json:"updated_at"`
	Items       []RiskConfigItemView  `json:"items"`
}

// UpdateRiskConfigInput 配置更新入参。
//
// 每个字段都是指针：只有传了才改。用零值表示「没传」会让
// 「把权重改成 0」与「不改权重」变成同一件事。
type UpdateRiskConfigInput struct {
	AssetWeight *float64
	VeryHigh    *int
	High        *int
	Medium      *int
	Low         *int
}

// RiskConfigService 风险模型配置服务。
type RiskConfigService struct {
	repo   *repository.Repository
	audit  *auditor
	logger *slog.Logger
}

// NewRiskConfigService 构建配置服务。
func NewRiskConfigService(repo *repository.Repository, logger *slog.Logger) *RiskConfigService {
	if logger == nil {
		logger = slog.Default()
	}
	return &RiskConfigService{repo: repo, audit: newAuditor(repo, logger), logger: logger}
}

// Get 读取当前风险模型配置。
func (s *RiskConfigService) Get(ctx context.Context) (*RiskConfigView, error) {
	rows, err := s.repo.SystemCfg.ListByPrefix(ctx, riskConfigPrefix)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取系统配置失败", err)
	}
	cfg, err := parseRiskConfigRows(rows)
	if err != nil {
		return nil, err
	}
	return toRiskConfigView(cfg, rows), nil
}

// Update 更新风险模型配置。
//
// 顺序很重要：**先合并出完整配置并校验，再写库**。反过来的话，一次
// 「只改资产权重」的请求会把四个阈值原样写回去（值没变，看着无害），
// 但如果这次请求同时把阈值改成了倒序，库就已经脏了——校验必须在写之前。
func (s *RiskConfigService) Update(
	ctx context.Context, p *auth.Principal, meta RequestMeta, in UpdateRiskConfigInput,
) (*RiskConfigView, error) {
	rows, err := s.repo.SystemCfg.ListByPrefix(ctx, riskConfigPrefix)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取系统配置失败", err)
	}

	known := make(map[string]model.SystemConfig, len(rows))
	for _, row := range rows {
		known[row.ConfigKey] = row
	}

	current, err := parseRiskConfigRows(rows)
	if err != nil {
		return nil, err
	}

	weight := current.AssetWeightValue()
	th := current.Thresholds()
	changes := map[string]any{}
	updates := map[string]string{}

	if in.AssetWeight != nil {
		weight = *in.AssetWeight
		updates[model.ConfigRiskAssetWeight] = strconv.FormatFloat(weight, 'f', -1, 64)
		changes["asset_weight"] = weight
	}
	if in.VeryHigh != nil {
		th.VeryHigh = *in.VeryHigh
		updates[model.ConfigRiskThresholdVeryHigh] = strconv.Itoa(th.VeryHigh)
		changes["threshold_very_high"] = th.VeryHigh
	}
	if in.High != nil {
		th.High = *in.High
		updates[model.ConfigRiskThresholdHigh] = strconv.Itoa(th.High)
		changes["threshold_high"] = th.High
	}
	if in.Medium != nil {
		th.Medium = *in.Medium
		updates[model.ConfigRiskThresholdMedium] = strconv.Itoa(th.Medium)
		changes["threshold_medium"] = th.Medium
	}
	if in.Low != nil {
		th.Low = *in.Low
		updates[model.ConfigRiskThresholdLow] = strconv.Itoa(th.Low)
		changes["threshold_low"] = th.Low
	}

	if len(updates) == 0 {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "没有需要更新的配置项")
	}

	// 校验：权重与阈值的组合必须自洽（严格递减、下界不小于 1）。
	if _, err := riskengine.ParseConfig(weight, th.VeryHigh, th.High, th.Medium, th.Low); err != nil {
		return nil, newError(http.StatusBadRequest, errcode.CodeRiskConfigInvalid, err.Error())
	}

	// 只允许改「已存在且可编辑」的键。
	for key := range updates {
		row, ok := known[key]
		if !ok {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
				"系统配置缺失，请联系管理员", nil)
		}
		if !row.Editable {
			return nil, newError(http.StatusForbidden, errcode.CodeRiskConfigReadonly,
				"配置项 "+key+" 不允许修改")
		}
	}

	if err := s.repo.SystemCfg.UpdateValues(ctx, updates); err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "更新系统配置失败", err)
	}

	s.audit.record(ctx, auditEntryFor(p, meta,
		model.ActionSystemConfigUpdate, "system_config", "risk", changes))

	return s.Get(ctx)
}

// currentConfig 读取并解析当前生效的风险配置。
//
// 供评估引擎在「试算」与「计算」时取用。配置缺失或非法都返回 500：
// 这不是用户的输入错误，而是部署状态坏了——配置表被删了行或被手工改成了
// 倒序阈值，唯一正确的处置是让运维看见并修好它，而不是悄悄用默认值算完。
func (s *RiskConfigService) currentConfig(ctx context.Context) (riskengine.Config, error) {
	rows, err := s.repo.SystemCfg.ListByPrefix(ctx, riskConfigPrefix)
	if err != nil {
		return riskengine.Config{}, wrapError(http.StatusInternalServerError,
			errcode.CodeInternal, "读取系统配置失败", err)
	}
	return parseRiskConfigRows(rows)
}

// parseRiskConfigRows 把配置行解析成引擎配置。
func parseRiskConfigRows(rows []model.SystemConfig) (riskengine.Config, error) {
	values := make(map[string]string, len(rows))
	for _, row := range rows {
		values[row.ConfigKey] = strings.TrimSpace(row.ConfigValue)
	}

	requiredInt := func(key string) (int, error) {
		raw, ok := values[key]
		if !ok {
			return 0, errRiskConfigBroken("缺少配置项 " + key)
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, errRiskConfigBroken("配置项 " + key + " 的值「" + raw + "」不是整数")
		}
		return n, nil
	}

	weightRaw, ok := values[model.ConfigRiskAssetWeight]
	if !ok {
		return riskengine.Config{}, errRiskConfigBroken("缺少配置项 " + model.ConfigRiskAssetWeight)
	}
	weight, err := strconv.ParseFloat(weightRaw, 64)
	if err != nil {
		return riskengine.Config{}, errRiskConfigBroken(
			"配置项 " + model.ConfigRiskAssetWeight + " 的值「" + weightRaw + "」不是数字")
	}

	veryHigh, err := requiredInt(model.ConfigRiskThresholdVeryHigh)
	if err != nil {
		return riskengine.Config{}, err
	}
	high, err := requiredInt(model.ConfigRiskThresholdHigh)
	if err != nil {
		return riskengine.Config{}, err
	}
	medium, err := requiredInt(model.ConfigRiskThresholdMedium)
	if err != nil {
		return riskengine.Config{}, err
	}
	low, err := requiredInt(model.ConfigRiskThresholdLow)
	if err != nil {
		return riskengine.Config{}, err
	}

	cfg, parseErr := riskengine.ParseConfig(weight, veryHigh, high, medium, low)
	if parseErr != nil {
		return riskengine.Config{}, errRiskConfigBroken(parseErr.Error())
	}
	return cfg, nil
}

// toRiskConfigView 组装对外视图。
func toRiskConfigView(cfg riskengine.Config, rows []model.SystemConfig) *RiskConfigView {
	items := make([]RiskConfigItemView, 0, len(rows))
	updated := time.Time{}
	for _, row := range rows {
		items = append(items, RiskConfigItemView{
			Key:         row.ConfigKey,
			Value:       row.ConfigValue,
			ValueType:   row.ValueType,
			Description: row.Description,
			Editable:    row.Editable,
		})
		if row.UpdatedAt.After(updated) {
			updated = row.UpdatedAt
		}
	}
	updatedStr := ""
	if !updated.IsZero() {
		updatedStr = updated.Format(time.RFC3339)
	}

	modelKey := ""
	for _, row := range rows {
		if row.ConfigKey == model.ConfigRiskModel {
			modelKey = strings.TrimSpace(row.ConfigValue)
			break
		}
	}

	return &RiskConfigView{
		Model:       modelKey,
		AssetWeight: cfg.AssetWeightValue(),
		Thresholds:  cfg.Thresholds(),
		UpdatedAt:   updatedStr,
		Items:       items,
	}
}

// errRiskConfigBroken 配置表本身有问题（缺行 / 值非法 / 阈值倒序）。
//
// 报 500 而不是 400：走到这里说明请求没有任何问题，是服务端的部署状态
// 坏了。把它伪装成「参数错误」会让用户反复检查自己的输入。
func errRiskConfigBroken(reason string) *Error {
	return newError(http.StatusInternalServerError, errcode.CodeRiskConfigInvalid,
		"系统风险配置不合法（"+reason+"），请联系管理员检查系统设置")
}
