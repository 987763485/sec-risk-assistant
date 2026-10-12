package service

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/optional"
	"secrisk/server/internal/repository"
)

const (
	assetNameMaxRunes        = 128
	assetNoMaxRunes          = 64
	assetIPMaxRunes          = 64
	assetHostnameMaxRunes    = 128
	assetOSTypeMaxRunes      = 64
	assetOwnerMaxRunes       = 64
	assetDepartmentMaxRunes  = 64
	assetDescriptionMaxRunes = 512
	assetTagMaxRunes         = 32
	assetMaxTagCount         = 10
)

// assetNoPattern 资产编号的格式：字母数字开头，可含 _ . - /
//
// 允许斜杠是因为企业台账里「2026/Q1/NET-001」这类带分层的编号很常见。
var assetNoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,63}$`)

// hostnamePattern 主机名/域名形式。
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// AssetView 资产的对外视图。
type AssetView struct {
	ID      uint64 `json:"id"`
	AssetNo string `json:"asset_no"`
	Name    string `json:"name"`
	// AssetType 是字典码，AssetTypeName 是它的显示名。
	//
	// 两个都下发，是为了让前端渲染列表时不必再拉一次字典；更重要的是
	// 当某个类型被停用后，名称仍然能正确显示——如果只给码，前端自己
	// 去字典里查会查不到，那一列就变成空白了。
	AssetType     string `json:"asset_type"`
	AssetTypeName string `json:"asset_type_name"`

	GroupID   *uint64 `json:"group_id"`
	GroupName string  `json:"group_name"`

	IPAddress string `json:"ip_address"`
	// Port 未填写时为 0，前端据此显示「—」。
	Port        uint16    `json:"port"`
	Hostname    string    `json:"hostname"`
	OSType      string    `json:"os_type"`
	Importance  uint8     `json:"importance"`
	Owner       string    `json:"owner"`
	Department  string    `json:"department"`
	Status      string    `json:"status"`
	Tags        []string  `json:"tags"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateAssetInput 新建资产入参。
type CreateAssetInput struct {
	AssetNo     string
	Name        string
	AssetType   string
	GroupID     *uint64
	IPAddress   string
	Port        *uint16
	Hostname    string
	OSType      string
	Importance  *uint8
	Owner       string
	Department  string
	Status      string
	Tags        []string
	Description string
}

// UpdateAssetInput 编辑资产入参。
//
// 三个可空字段用 optional.Value 表达三态（不修改 / 清空 / 设值）：
// 资产编号、所属资产组、端口。理由见 pkg/optional 的包注释——
// 用 `*T` 时「清空端口」与「不修改端口」在 Go 里是同一个值，
// 用户会发现清空操作怎么点都不生效。
//
// 其余字符串字段用 *string：对它们来说「空串」天然就是「清空」，
// 不需要第三种状态。
type UpdateAssetInput struct {
	AssetNo     optional.Value[string]
	Name        *string
	AssetType   *string
	GroupID     optional.Value[uint64]
	IPAddress   *string
	Port        optional.Value[uint16]
	Hostname    *string
	OSType      *string
	Importance  *uint8
	Owner       *string
	Department  *string
	Status      *string
	Tags        *[]string
	Description *string
}

// AssetListResult 资产列表结果。
type AssetListResult struct {
	Items    []AssetView
	Total    int64
	Page     int
	PageSize int
}

// AssetService 资产台账服务。
type AssetService struct {
	cfg    *config.Config
	repo   *repository.Repository
	groups *AssetGroupService
	audit  *auditor
	logger *slog.Logger
}

// NewAssetService 构建资产服务。
//
// 依赖 AssetGroupService 而不是直接用仓储：按资产组筛选要展开子树，
// 那是分组服务的领域规则（含子树语义、组不存在要报 404），
// 不该在资产服务里再实现一遍。
func NewAssetService(
	cfg *config.Config, repo *repository.Repository,
	groups *AssetGroupService, logger *slog.Logger,
) *AssetService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AssetService{
		cfg: cfg, repo: repo, groups: groups,
		audit: newAuditor(repo, logger), logger: logger,
	}
}

// List 分页查询资产。
func (s *AssetService) List(
	ctx context.Context, q repository.AssetListQuery,
) (*AssetListResult, error) {
	assets, total, err := s.repo.Asset.List(ctx, q)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询资产列表失败", err)
	}

	views, err := s.decorate(ctx, assets)
	if err != nil {
		return nil, err
	}
	return &AssetListResult{
		Items: views, Total: total, Page: q.Page, PageSize: q.PageSize,
	}, nil
}

// Get 查询单个资产。
func (s *AssetService) Get(ctx context.Context, id uint64) (*AssetView, error) {
	a, err := s.repo.Asset.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrAssetNotFound) {
			return nil, errAssetNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "查询资产失败", err)
	}

	views, err := s.decorate(ctx, []model.Asset{*a})
	if err != nil {
		return nil, err
	}
	return &views[0], nil
}

// Create 新建资产。
func (s *AssetService) Create(
	ctx context.Context, in CreateAssetInput,
	operator *auth.Principal, meta RequestMeta,
) (*AssetView, error) {
	name, err := validateAssetName(in.Name)
	if err != nil {
		return nil, err
	}

	assetNo, err := validateAssetNo(in.AssetNo)
	if err != nil {
		return nil, err
	}

	assetType := strings.TrimSpace(in.AssetType)
	if err := s.validateAssetTypeForNew(ctx, assetType); err != nil {
		return nil, err
	}

	if err := validateIPAddress(in.IPAddress); err != nil {
		return nil, err
	}
	if in.Port != nil {
		if err := validatePort(*in.Port); err != nil {
			return nil, err
		}
	}

	status, err := resolveAssetStatus(in.Status, model.AssetStatusInUse)
	if err != nil {
		return nil, err
	}

	importance := model.ImportanceDefault
	if in.Importance != nil {
		if !model.ValidImportance(*in.Importance) {
			return nil, errImportanceInvalid()
		}
		importance = *in.Importance
	}

	tags, err := normalizeTags(in.Tags)
	if err != nil {
		return nil, err
	}

	if in.GroupID != nil {
		if err := s.ensureGroupExists(ctx, *in.GroupID); err != nil {
			return nil, err
		}
	}

	if assetNo != "" {
		taken, err := s.repo.Asset.ExistsAssetNo(ctx, assetNo, 0)
		if err != nil {
			return nil, wrapError(500, errcode.CodeInternal, "创建资产失败", err)
		}
		if taken {
			return nil, errAssetNoTaken()
		}
	}

	a := &model.Asset{
		Name:        name,
		AssetType:   assetType,
		GroupID:     in.GroupID,
		IPAddress:   strings.TrimSpace(in.IPAddress),
		Port:        in.Port,
		Hostname:    trimTo(in.Hostname, assetHostnameMaxRunes),
		OSType:      trimTo(in.OSType, assetOSTypeMaxRunes),
		Importance:  importance,
		Owner:       trimTo(in.Owner, assetOwnerMaxRunes),
		Department:  trimTo(in.Department, assetDepartmentMaxRunes),
		Status:      status,
		Tags:        strings.Join(tags, ","),
		Description: trimTo(in.Description, assetDescriptionMaxRunes),
	}
	if assetNo != "" {
		a.AssetNo = &assetNo
	}
	if operator != nil {
		creator := operator.UserID
		a.CreatedBy = &creator
	}

	if err := s.repo.Asset.Create(ctx, a); err != nil {
		if isDuplicateKey(err) {
			return nil, errAssetNoTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "创建资产失败", err)
	}

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetCreate,
		"asset", strconv.FormatUint(a.ID, 10), map[string]any{
			"name":       name,
			"asset_no":   assetNo,
			"asset_type": assetType,
			"group_id":   in.GroupID,
			"ip_address": a.IPAddress,
			"importance": importance,
		}))

	return s.Get(ctx, a.ID)
}

// Update 编辑资产。
func (s *AssetService) Update(
	ctx context.Context, id uint64, in UpdateAssetInput,
	operator *auth.Principal, meta RequestMeta,
) (*AssetView, error) {
	current, err := s.repo.Asset.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrAssetNotFound) {
			return nil, errAssetNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "更新资产失败", err)
	}

	fields := make(map[string]any, 8)
	changed := make([]string, 0, 8)

	if in.Name != nil {
		name, err := validateAssetName(*in.Name)
		if err != nil {
			return nil, err
		}
		fields["name"] = name
		changed = append(changed, "name")
	}

	// 资产编号：Present 才动；Value 为 nil 表示清空（写 NULL）
	if in.AssetNo.Present {
		if in.AssetNo.Value == nil {
			fields["asset_no"] = nil
		} else {
			assetNo, err := validateAssetNo(*in.AssetNo.Value)
			if err != nil {
				return nil, err
			}
			if assetNo != "" {
				taken, err := s.repo.Asset.ExistsAssetNo(ctx, assetNo, id)
				if err != nil {
					return nil, wrapError(500, errcode.CodeInternal, "更新资产失败", err)
				}
				if taken {
					return nil, errAssetNoTaken()
				}
			}
			if assetNo == "" {
				fields["asset_no"] = nil
			} else {
				fields["asset_no"] = assetNo
			}
		}
		changed = append(changed, "asset_no")
	}

	if in.AssetType != nil {
		next := strings.TrimSpace(*in.AssetType)
		// 只在类型**真的变了**的时候校验「是否存在且启用」。
		// 否则一个用着已停用类型的资产永远保存不了——用户明明只是在改备注，
		// 却被告知「资产类型不存在」，而且改不了（除非换类型）。
		if next != current.AssetType {
			if err := s.validateAssetTypeForNew(ctx, next); err != nil {
				return nil, err
			}
		}
		fields["asset_type"] = next
		changed = append(changed, "asset_type")
	}

	if in.GroupID.Present {
		if in.GroupID.Value == nil {
			fields["group_id"] = nil
		} else {
			if err := s.ensureGroupExists(ctx, *in.GroupID.Value); err != nil {
				return nil, err
			}
			fields["group_id"] = *in.GroupID.Value
		}
		changed = append(changed, "group_id")
	}

	if in.IPAddress != nil {
		if err := validateIPAddress(*in.IPAddress); err != nil {
			return nil, err
		}
		fields["ip_address"] = strings.TrimSpace(*in.IPAddress)
		changed = append(changed, "ip_address")
	}

	if in.Port.Present {
		if in.Port.Value == nil {
			fields["port"] = nil
		} else {
			if err := validatePort(*in.Port.Value); err != nil {
				return nil, err
			}
			fields["port"] = *in.Port.Value
		}
		changed = append(changed, "port")
	}

	if in.Hostname != nil {
		fields["hostname"] = trimTo(*in.Hostname, assetHostnameMaxRunes)
		changed = append(changed, "hostname")
	}
	if in.OSType != nil {
		fields["os_type"] = trimTo(*in.OSType, assetOSTypeMaxRunes)
		changed = append(changed, "os_type")
	}
	if in.Importance != nil {
		if !model.ValidImportance(*in.Importance) {
			return nil, errImportanceInvalid()
		}
		fields["importance"] = *in.Importance
		changed = append(changed, "importance")
	}
	if in.Owner != nil {
		fields["owner"] = trimTo(*in.Owner, assetOwnerMaxRunes)
		changed = append(changed, "owner")
	}
	if in.Department != nil {
		fields["department"] = trimTo(*in.Department, assetDepartmentMaxRunes)
		changed = append(changed, "department")
	}
	if in.Status != nil {
		status, err := resolveAssetStatus(*in.Status, current.Status)
		if err != nil {
			return nil, err
		}
		fields["status"] = status
		changed = append(changed, "status")
	}
	if in.Tags != nil {
		tags, err := normalizeTags(*in.Tags)
		if err != nil {
			return nil, err
		}
		fields["tags"] = strings.Join(tags, ",")
		changed = append(changed, "tags")
	}
	if in.Description != nil {
		fields["description"] = trimTo(*in.Description, assetDescriptionMaxRunes)
		changed = append(changed, "description")
	}

	if len(changed) == 0 {
		return s.Get(ctx, id)
	}
	fields["updated_at"] = time.Now()

	if err := s.repo.Asset.Update(ctx, id, fields); err != nil {
		if isDuplicateKey(err) {
			return nil, errAssetNoTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "更新资产失败", err)
	}

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetUpdate,
		"asset", strconv.FormatUint(id, 10), map[string]any{
			"name":   current.Name,
			"fields": changed,
		}))

	return s.Get(ctx, id)
}

// Delete 删除资产。
func (s *AssetService) Delete(
	ctx context.Context, id uint64, operator *auth.Principal, meta RequestMeta,
) error {
	current, err := s.repo.Asset.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrAssetNotFound) {
			return errAssetNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "删除资产失败", err)
	}

	if err := s.repo.Asset.Delete(ctx, id); err != nil {
		if errors.Is(err, repository.ErrAssetNotFound) {
			return errAssetNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "删除资产失败", err)
	}

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetDelete,
		"asset", strconv.FormatUint(id, 10), map[string]any{
			"name":       current.Name,
			"asset_no":   current.AssetNoValue(),
			"asset_type": current.AssetType,
			"ip_address": current.IPAddress,
		}))

	return nil
}

// ------------------------------------------------------------------ 内部

// decorate 把模型补全成对外视图（补齐类型名与组名）。
//
// 类型名与组名各用一次批量查询取回，而不是逐行查——列表页一页 100 条，
// 逐行查就是 200 次往返。
func (s *AssetService) decorate(ctx context.Context, assets []model.Asset) ([]AssetView, error) {
	if len(assets) == 0 {
		return []AssetView{}, nil
	}

	types, err := loadDictionaryMap(ctx, s.repo, model.CategoryAssetType)
	if err != nil {
		return nil, err
	}
	groupNames, err := s.repo.AssetGroup.NameMap(ctx)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询资产组失败", err)
	}

	out := make([]AssetView, 0, len(assets))
	for i := range assets {
		out = append(out, toAssetView(&assets[i], types, groupNames))
	}
	return out, nil
}

// ensureGroupExists 确认资产组存在。
func (s *AssetService) ensureGroupExists(ctx context.Context, groupID uint64) error {
	if _, err := s.repo.AssetGroup.FindByID(ctx, groupID); err != nil {
		if errors.Is(err, repository.ErrAssetGroupNotFound) {
			return errAssetGroupNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "查询资产组失败", err)
	}
	return nil
}

// validateAssetTypeForNew 校验「新建资产时选用的类型」。
//
// 必须存在**且启用**。停用的类型不允许被新资产选用，但已有资产可以
// 继续沿用（那条规则在 Update 里，见那里的注释）。
func (s *AssetService) validateAssetTypeForNew(ctx context.Context, code string) error {
	if code == "" {
		return errAssetTypeUnknown("")
	}
	types, err := loadDictionaryMap(ctx, s.repo, model.CategoryAssetType)
	if err != nil {
		return err
	}
	item, ok := types[code]
	if !ok {
		return errAssetTypeUnknown(code)
	}
	if !item.Enabled {
		return newError(400, errcode.CodeAssetTypeUnknown,
			"资产类型「"+item.Name+"」已停用，不能用于新建资产")
	}
	return nil
}

func toAssetView(
	a *model.Asset, types map[string]model.Dictionary, groupNames map[uint64]string,
) AssetView {
	view := AssetView{
		ID:          a.ID,
		AssetNo:     a.AssetNoValue(),
		Name:        a.Name,
		AssetType:   a.AssetType,
		GroupID:     a.GroupID,
		IPAddress:   a.IPAddress,
		Port:        a.PortValue(),
		Hostname:    a.Hostname,
		OSType:      a.OSType,
		Importance:  a.Importance,
		Owner:       a.Owner,
		Department:  a.Department,
		Status:      string(a.Status),
		Tags:        splitTags(a.Tags),
		Description: a.Description,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}

	// 类型名兜底为码本身：字典项被停用后仍能显示中文名（Resolve 不过滤
	// enabled），但万一字典项被删掉了，至少不会显示成空白。
	view.AssetTypeName = a.AssetType
	if d, ok := types[a.AssetType]; ok {
		view.AssetTypeName = d.Name
	}
	if a.GroupID != nil {
		view.GroupName = groupNames[*a.GroupID]
	}

	return view
}

// ------------------------------------------------------------------ 校验

func validateAssetName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", newError(400, errcode.CodeInvalidParam, "资产名称不能为空")
	}
	if len([]rune(name)) > assetNameMaxRunes {
		return "", newError(400, errcode.CodeInvalidParam, "资产名称不得超过 128 个字符")
	}
	return name, nil
}

// validateAssetNo 校验资产编号。返回空串表示「不填」。
func validateAssetNo(raw string) (string, error) {
	no := strings.TrimSpace(raw)
	if no == "" {
		return "", nil
	}
	if !assetNoPattern.MatchString(no) {
		return "", newError(400, errcode.CodeInvalidParam,
			"资产编号需为 1–64 位字母、数字或 _ . - /，且以字母或数字开头")
	}
	return no, nil
}

// validateIPAddress 校验 IP 地址字段。
//
// 接受四类写法：IPv4、IPv6、CIDR 网段、主机名/域名。最后一类的存在
// 是因为台账里确实有「还没分配 IP、先填主机名」和「这一栏填的是域名」
// 这两种真实情况——把它们一律拒掉只会逼用户去备注里乱写。
//
// 关键在于**只含数字、点、冒号的字符串必须真的是 IP**：
// 若仅做「符合主机名字符集就放行」，"999.1.1.1" 会被当成一个合法的
// 主机名收下，而它几乎必然是用户敲错了 IP。这是本函数唯一需要
// 额外写代码的地方，也是最容易被漏掉的地方。
func validateIPAddress(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}

	numericOnly := true
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != ':' {
			numericOnly = false
			break
		}
	}
	if numericOnly {
		return newError(400, errcode.CodeInvalidParam, "IP 地址格式不正确")
	}

	if len(s) > assetIPMaxRunes || !hostnamePattern.MatchString(s) {
		return newError(400, errcode.CodeInvalidParam,
			"IP 地址格式不正确（可填 IPv4 / IPv6 / CIDR 网段 / 主机名）")
	}
	return nil
}

func validatePort(port uint16) error {
	if port == 0 {
		return newError(400, errcode.CodeInvalidParam, "端口需在 1–65535 之间")
	}
	return nil
}

func errImportanceInvalid() *Error {
	return newError(400, errcode.CodeInvalidParam, "重要性需为 1–5 之间的整数")
}

func resolveAssetStatus(raw string, fallback model.AssetStatus) (model.AssetStatus, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fallback, nil
	}
	status := model.AssetStatus(s)
	if !status.Valid() {
		return "", newError(400, errcode.CodeInvalidParam,
			"资产状态只能是 in_use / idle / offline / scrapped")
	}
	return status, nil
}

// normalizeTags 规整标签：去空白、丢空项、去重、限数量与长度。
//
// 顺序保持不变（不做排序）：标签在界面上按用户输入顺序展示，
// 擅自排序会让「我明明把重要的放前面」这个预期落空。
func normalizeTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		t := strings.TrimSpace(tag)
		if t == "" {
			continue
		}
		if len([]rune(t)) > assetTagMaxRunes {
			return nil, newError(400, errcode.CodeInvalidParam, "单个标签不得超过 32 个字符")
		}
		// 标签用逗号存储，因此标签内部不能有逗号——否则一个标签会在
		// 读出来的时候裂成两个。
		if strings.ContainsAny(t, ",") {
			return nil, newError(400, errcode.CodeInvalidParam, "标签内不能包含逗号")
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) > assetMaxTagCount {
		return nil, newError(400, errcode.CodeInvalidParam,
			"标签最多 "+strconv.Itoa(assetMaxTagCount)+" 个")
	}
	return out, nil
}

// splitTags 把逗号分隔的标签串拆成切片。永不返回 nil，
// 保证 JSON 里是 [] 而不是 null。
func splitTags(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// trimTo 裁掉首尾空白并限制字符数。
func trimTo(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if runes := []rune(s); len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return s
}
