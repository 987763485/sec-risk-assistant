package service

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/repository"
)

// 字典项的字段约束。
const (
	dictionaryNameMaxRunes        = 64
	dictionaryDescriptionMaxRunes = 255
	// 风险模型里的资产价值 A / 发生可能性 T / 严重程度 V 都是 1–5 级，
	// 权重因此也约束在这个区间。放开的话会出现「权重 99」这种算式上跑得通、
	// 但结论无法解释的数据（风险值会超出 1–125 的既定区间）。
	dictionaryWeightMin = 1.0
	dictionaryWeightMax = 5.0
)

// dictionaryCodePattern 字典码的格式。
//
// 只允许小写字母、数字与下划线，且必须以字母开头。收紧字符集有两个
// 实际收益：码会出现在 URL 查询参数与 Excel 单元格里，限定为 ASCII
// 小写可以避开「大小写不一致导致匹配不上」这类幽灵问题；同时它与
// 权限码 `<资源>:<动作>` 的风格一致，读代码时不必切换心智。
var dictionaryCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// DictionaryView 字典项的对外视图。
//
// 与 model.Dictionary 分开定义：模型字段不带 json tag，直接序列化会输出
// PascalCase；而且对外形状应当由接口层决定，模型调整不该自动改掉 API。
type DictionaryView struct {
	ID          uint64    `json:"id"`
	Category    string    `json:"category"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Weight      float64   `json:"weight"`
	Description string    `json:"description"`
	IsBuiltin   bool      `json:"is_builtin"`
	Enabled     bool      `json:"enabled"`
	SortOrder   int       `json:"sort_order"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateDictionaryInput 新建字典项入参。
type CreateDictionaryInput struct {
	Category string
	Code     string
	Name     string
	// Weight 为 nil 时按类别取默认值：参与风险计算的类别用中性值 3，
	// asset_type 固定 1。给「没填权重」一个中性默认，比默认为 1
	// 更不容易让资产被系统性低估。
	Weight      *float64
	Description string
	SortOrder   *int
}

// UpdateDictionaryInput 编辑字典项入参。
//
// Code 也在其中，但它**只能等于原值**——带 Code 字段的目的是能把
// 「用户试图改码」识别出来并给出明确提示，而不是静默忽略。
// 静默忽略会让用户以为改成功了，然后在资产列表里看到一个空白的类型名。
type UpdateDictionaryInput struct {
	Code        *string
	Name        *string
	Weight      *float64
	Description *string
	Enabled     *bool
	SortOrder   *int
}

// DictionaryService 业务字典服务。
type DictionaryService struct {
	cfg    *config.Config
	repo   *repository.Repository
	audit  *auditor
	logger *slog.Logger
}

// NewDictionaryService 构建字典服务。
func NewDictionaryService(
	cfg *config.Config, repo *repository.Repository, logger *slog.Logger,
) *DictionaryService {
	if logger == nil {
		logger = slog.Default()
	}
	return &DictionaryService{
		cfg: cfg, repo: repo, audit: newAuditor(repo, logger), logger: logger,
	}
}

// List 查询字典项。
//
// category 为空表示不限类目；enabledOnly 为 false 时连停用项一并返回
// （字典维护页需要看到停用项，否则一个被停用的类型在界面里会凭空消失，
// 用户既看不到它也无法重新启用）。
func (s *DictionaryService) List(
	ctx context.Context, category string, enabledOnly bool,
) ([]DictionaryView, error) {
	var categories []model.DictionaryCategory
	if category != "" {
		c := model.DictionaryCategory(category)
		if !c.Valid() {
			return nil, errDictionaryCategoryInvalid()
		}
		categories = []model.DictionaryCategory{c}
	}

	items, err := s.repo.Dictionary.List(ctx, categories, enabledOnly)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询字典失败", err)
	}
	return toDictionaryViews(items), nil
}

// Create 新建字典项。
func (s *DictionaryService) Create(
	ctx context.Context, in CreateDictionaryInput,
	operator *auth.Principal, meta RequestMeta,
) (*DictionaryView, error) {
	category := model.DictionaryCategory(strings.TrimSpace(in.Category))
	if !category.Valid() {
		return nil, errDictionaryCategoryInvalid()
	}

	code := strings.TrimSpace(in.Code)
	if !dictionaryCodePattern.MatchString(code) {
		return nil, newError(400, errcode.CodeInvalidParam,
			"字典码需为 1–64 位小写字母、数字或下划线，且以字母开头")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, newError(400, errcode.CodeInvalidParam, "名称不能为空")
	}
	if len([]rune(name)) > dictionaryNameMaxRunes {
		return nil, newError(400, errcode.CodeInvalidParam,
			"名称不得超过 "+strconv.Itoa(dictionaryNameMaxRunes)+" 个字符")
	}
	description := strings.TrimSpace(in.Description)
	if len([]rune(description)) > dictionaryDescriptionMaxRunes {
		return nil, newError(400, errcode.CodeInvalidParam, "说明不得超过 255 个字符")
	}

	weight, err := resolveDictionaryWeight(category, in.Weight)
	if err != nil {
		return nil, err
	}

	// 先查一次给友好提示，唯一索引在并发下兜底
	exists, err := s.repo.Dictionary.ExistsCode(ctx, category, code, 0)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "创建字典项失败", err)
	}
	if exists {
		return nil, errDictionaryCodeTaken()
	}

	d := &model.Dictionary{
		Category:    category,
		Code:        code,
		Name:        name,
		Weight:      weight,
		Description: description,
		// 用户新建的项永远是「非内置」：内置标记决定的是「能不能删」，
		// 而由界面创建的东西本来就是可以删掉的。
		IsBuiltin: false,
		Enabled:   true,
	}
	if in.SortOrder != nil {
		d.SortOrder = *in.SortOrder
	}

	if err := s.repo.Dictionary.Create(ctx, d); err != nil {
		if isDuplicateKey(err) {
			return nil, errDictionaryCodeTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "创建字典项失败", err)
	}

	view := toDictionaryView(d)
	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionDictionaryCreate,
		"dictionary", strconv.FormatUint(d.ID, 10), map[string]any{
			"category": string(category),
			"code":     code,
			"name":     name,
			"weight":   weight,
		}))

	return &view, nil
}

// Update 编辑字典项。
func (s *DictionaryService) Update(
	ctx context.Context, id uint64, in UpdateDictionaryInput,
	operator *auth.Principal, meta RequestMeta,
) (*DictionaryView, error) {
	current, err := s.repo.Dictionary.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrDictionaryNotFound) {
			return nil, errDictionaryNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "更新字典项失败", err)
	}

	fields := make(map[string]any, 5)

	if in.Code != nil {
		next := strings.TrimSpace(*in.Code)
		// 允许「原样回传」：前端编辑表单会把 code 一起提交回来，
		// 因此只有真的改了才报错。对一个不可变字段来说，
		// 「传了相同的值」与「没传」在语义上是一回事。
		if next != current.Code {
			return nil, errDictionaryCodeImmutable()
		}
	}

	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, newError(400, errcode.CodeInvalidParam, "名称不能为空")
		}
		if len([]rune(name)) > dictionaryNameMaxRunes {
			return nil, newError(400, errcode.CodeInvalidParam, "名称不得超过 64 个字符")
		}
		fields["name"] = name
	}

	if in.Weight != nil {
		weight, err := resolveDictionaryWeight(current.Category, in.Weight)
		if err != nil {
			return nil, err
		}
		fields["weight"] = weight
	}

	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		if len([]rune(description)) > dictionaryDescriptionMaxRunes {
			return nil, newError(400, errcode.CodeInvalidParam, "说明不得超过 255 个字符")
		}
		fields["description"] = description
	}

	if in.Enabled != nil {
		// 内置项允许停用：停用不破坏任何引用（历史资产仍能翻译出名称），
		// 而它恰恰是「这个内置类型我们不用」的正确表达方式。
		fields["enabled"] = *in.Enabled
	}

	if in.SortOrder != nil {
		fields["sort_order"] = *in.SortOrder
	}

	if len(fields) == 0 {
		view := toDictionaryView(current)
		return &view, nil
	}
	fields["updated_at"] = time.Now()

	if err := s.repo.Dictionary.Update(ctx, id, fields); err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "更新字典项失败", err)
	}

	updated, err := s.repo.Dictionary.FindByID(ctx, id)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "更新字典项失败", err)
	}
	view := toDictionaryView(updated)

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionDictionaryUpdate,
		"dictionary", strconv.FormatUint(id, 10), map[string]any{
			"code":    current.Code,
			"fields":  sortedKeys(fields, "updated_at"),
			"name":    updated.Name,
			"weight":  updated.Weight,
			"enabled": updated.Enabled,
		}))

	return &view, nil
}

// Delete 删除字典项。
//
// 两道保护，都指向同一件事：**删除会让历史数据失去解释**。
//
//   - 内置项不允许删。它们是模板与流程的一部分（资产类型直接决定
//     资产台账怎么分类），删掉会留下一批「类型名为空」的资产。
//   - 仍被资产引用的资产类型不允许删。资产按 code 引用字典，
//     删掉之后 assets.asset_type 就指向一个不存在的码，列表里
//     那一列会直接变成空白，而且没有任何报错。
//
// 这两种情况下正确的动作都是「停用」，因此错误提示里都写明了这一点。
func (s *DictionaryService) Delete(
	ctx context.Context, id uint64, operator *auth.Principal, meta RequestMeta,
) error {
	current, err := s.repo.Dictionary.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrDictionaryNotFound) {
			return errDictionaryNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "删除字典项失败", err)
	}
	if current.IsBuiltin {
		return errDictionaryBuiltinReadonly()
	}

	if current.Category == model.CategoryAssetType {
		counts, err := s.repo.Asset.CountByTypes(ctx, []string{current.Code})
		if err != nil {
			return wrapError(500, errcode.CodeInternal, "删除字典项失败", err)
		}
		if n := counts[current.Code]; n > 0 {
			return errDictionaryInUse(n)
		}
	}

	if err := s.repo.Dictionary.Delete(ctx, id); err != nil {
		if errors.Is(err, repository.ErrDictionaryNotFound) {
			return errDictionaryNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "删除字典项失败", err)
	}

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionDictionaryDelete,
		"dictionary", strconv.FormatUint(id, 10), map[string]any{
			"category": string(current.Category),
			"code":     current.Code,
			"name":     current.Name,
		}))

	return nil
}

// ------------------------------------------------------------------ 内部

// resolveDictionaryWeight 归一化权重取值。
//
// asset_type 的权重不参与风险计算，因此不接受调用方传值——统一写 1。
// 与其让用户填一个「写了也没用」的数字再在文档里解释，不如直接钉死。
func resolveDictionaryWeight(
	category model.DictionaryCategory, raw *float64,
) (float64, error) {
	if !category.ParticipatesInRiskCalculation() {
		return 1, nil
	}
	if raw == nil {
		return 3, nil
	}
	w := *raw
	if w < dictionaryWeightMin || w > dictionaryWeightMax {
		return 0, newError(400, errcode.CodeInvalidParam,
			"权重需在 "+strconv.FormatFloat(dictionaryWeightMin, 'f', -1, 64)+
				"–"+strconv.FormatFloat(dictionaryWeightMax, 'f', -1, 64)+" 之间")
	}
	return w, nil
}

// loadDictionaryMap 读取某个类目的 码 → 字典项 映射。
//
// 供资产服务在批量校验时复用：5000 行的导入若逐行查字典，
// 会变成 5000 次往返；一次拉回整张类目表在内存里比对是唯一合理做法。
func loadDictionaryMap(
	ctx context.Context, repo *repository.Repository, category model.DictionaryCategory,
) (map[string]model.Dictionary, error) {
	m, err := repo.Dictionary.Resolve(ctx, category)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "读取字典失败", err)
	}
	return m, nil
}

func toDictionaryViews(items []model.Dictionary) []DictionaryView {
	out := make([]DictionaryView, 0, len(items))
	for i := range items {
		out = append(out, toDictionaryView(&items[i]))
	}
	return out
}

func toDictionaryView(d *model.Dictionary) DictionaryView {
	return DictionaryView{
		ID:          d.ID,
		Category:    string(d.Category),
		Code:        d.Code,
		Name:        d.Name,
		Weight:      d.Weight,
		Description: d.Description,
		IsBuiltin:   d.IsBuiltin,
		Enabled:     d.Enabled,
		SortOrder:   d.SortOrder,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
}
