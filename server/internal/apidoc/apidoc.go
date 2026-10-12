// Package apidoc 加载并校验手写的 OpenAPI 契约文件。
//
// 为什么自己写校验器，而不是引入 kin-openapi 之类的库：
//
//  1. 需要校验的规则非常具体且数量有限（见 validateXxx），其中最有价值的一条
//     ——「spec 与 gin 真实路由表双向对齐」——任何现成库都不提供，
//     因为库不可能知道你用的是什么 Web 框架。这一条必须自己写。
//  2. kin-openapi 会带来约 30 个传递依赖。为一个 YAML 文件付出这个体积与
//     供应链面积并不划算，而且本项目在 P0 阶段已经被 `go get` 把 go 指令
//     顶到高版本坑过一次（与本机 Go 工具链冲突）。
//  3. 校验逻辑是纯函数，无需连数据库、无需起 HTTP 服务，因此可以被极快地
//     跑在本地与 CI 上。
//
// 代价说清楚：本包**不做**完整的 OpenAPI 3.1 规范符合性验证（那需要实现
// JSON Schema 2020-12 的校验器）。它只覆盖「手写 spec 最容易出的错」：
// 悬空 $ref、漏写 operationId、路径参数没声明、安全方案写错名字、
// 以及最关键的——契约与代码走偏。
package apidoc

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// openAPIVersionPrefix 本包只接受这一主版本的 spec。
//
// 钉住 3.1 而不是「3.x 都行」：3.0 与 3.1 的可空写法不兼容
// （3.0 用 `nullable: true`，3.1 必须用 `type: [string, "null"]`），
// 混用会产生「看起来对、生成出来的类型却是错的」这种最难查的问题。
const openAPIVersionPrefix = "3.1"

// httpMethods 路径项下属于「操作」的键。其余键（parameters / summary /
// servers / $ref）不是操作，不能参与路由比对。
var httpMethods = map[string]struct{}{
	"get": {}, "put": {}, "post": {}, "delete": {},
	"options": {}, "head": {}, "patch": {}, "trace": {},
}

// validHTTPStatus 合法的响应状态码键："default" 或 100–599 的三位数字。
var validHTTPStatus = regexp.MustCompile(`^(default|[1-5][0-9][0-9])$`)

// pathTemplateVar 匹配路径模板变量 {id}。
var pathTemplateVar = regexp.MustCompile(`\{([^{}]+)\}`)

// Spec 已解析的 OpenAPI 文档。
type Spec struct {
	// FilePath 源文件路径，仅用于错误信息定位。
	FilePath string
	// Root 反序列化后的整棵文档树。保留原始树是为了让 $ref 能按
	// JSON Pointer 逐段解析——这是唯一能可靠判断「引用是否悬空」的办法。
	Root map[string]any
	// Paths 路径模板 → 该路径上声明的操作。
	Paths map[string][]Operation
}

// Operation 一个具体的方法 + 路径。
type Operation struct {
	// Method 大写 HTTP 方法，如 GET
	Method string
	// Path spec 中写的原始路径，如 /api/users/{id}
	Path string
	// OperationID operationId
	OperationID string
	// Raw 操作节点的原始数据，供需要进一步检查的规则使用
	Raw map[string]any
}

// RouteKey 返回与 gin 路由表对齐的比较键，形如 "GET /api/users/{id}"。
func (o Operation) RouteKey() string { return o.Method + " " + o.Path }

// Load 从文件加载 spec。
func Load(filePath string) (*Spec, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取 OpenAPI 契约文件失败（%s）: %w", filePath, err)
	}
	return Parse(raw, filePath)
}

// Parse 解析 spec 字节内容。
func Parse(raw []byte, filePath string) (*Spec, error) {
	var root map[string]any

	// 反序列化进 map[string]any 而不是定义一堆 struct，是刻意的：
	// ① yaml.v3 默认开启唯一键检查，重复的路径键会在此直接报错
	//   （YAML 规范允许重复键、后者覆盖前者，是极隐蔽的事故来源）；
	// ② $ref 解析需要在原始树上按指针行走，struct 会丢掉未声明的字段。
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("解析 YAML 失败: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("OpenAPI 契约文件为空: %s", filePath)
	}

	// yaml.v3 只在「映射的所有键都是字符串」时才把值解成 map[string]any；
	// 一旦某层出现非字符串键（最典型的是把状态码写成不带引号的 200:），
	// 那一层就会退化成 map[interface{}]interface{}。
	//
	// 这会让下游所有「按 key 取值」的代码静默拿不到东西，并且报出与真实原因
	// 毫不相干的错误（例如把「responses 里有个整数键」报成「未声明任何 responses」）。
	// 因此在解析出口处统一归一化：让后续每一处遍历都只面对 map[string]any。
	normalized, err := normalizeKeys(root, "")
	if err != nil {
		return nil, err
	}
	root, _ = normalized.(map[string]any)

	spec := &Spec{FilePath: filePath, Root: root, Paths: map[string][]Operation{}}

	pathsNode, ok := asMap(root["paths"])
	if !ok {
		return nil, fmt.Errorf("缺少 paths 节点或类型不是映射: %s", filePath)
	}

	for path, itemNode := range pathsNode {
		item, ok := asMap(itemNode)
		if !ok {
			return nil, fmt.Errorf("paths.%s 不是映射", path)
		}
		for key, opNode := range item {
			if _, isMethod := httpMethods[key]; !isMethod {
				continue
			}
			op, ok := asMap(opNode)
			if !ok {
				return nil, fmt.Errorf("%s 上的 %s 操作不是映射", path, key)
			}
			id, _ := op["operationId"].(string)
			spec.Paths[path] = append(spec.Paths[path], Operation{
				Method:      strings.ToUpper(key),
				Path:        path,
				OperationID: id,
				Raw:         op,
			})
		}
		// 路径内部的 map 遍历顺序是随机的，排序后才能得到稳定输出
		sort.Slice(spec.Paths[path], func(i, j int) bool {
			return spec.Paths[path][i].Method < spec.Paths[path][j].Method
		})
	}

	return spec, nil
}

// Operations 以稳定的「路径字典序 + 方法字典序」返回全部操作。
func (s *Spec) Operations() []Operation {
	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out := make([]Operation, 0, len(paths))
	for _, p := range paths {
		out = append(out, s.Paths[p]...)
	}
	return out
}

// RouteSet 返回全部操作的 RouteKey 集合。
func (s *Spec) RouteSet() map[string]string {
	out := make(map[string]string, len(s.Paths))
	for _, op := range s.Operations() {
		out[op.RouteKey()] = op.OperationID
	}
	return out
}

// Validate 执行结构化校验，返回全部问题（而不是遇到第一个就返回）。
//
// 一次性给出全部问题，是为了让「改一版 spec」这个动作只需要一轮：
// 逐个报错会逼着人反复跑 CI。
func (s *Spec) Validate() []error {
	var errs []error

	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	// ── 1. 版本与元信息 ──────────────────────────────────────────────
	version, _ := s.Root["openapi"].(string)
	if version == "" {
		add("缺少 openapi 版本声明")
	} else if !strings.HasPrefix(version, openAPIVersionPrefix) {
		add("openapi 版本为 %q，本契约要求 %s.x（3.0 与 3.1 的可空写法不兼容，不可混用）",
			version, openAPIVersionPrefix)
	}

	info, ok := asMap(s.Root["info"])
	if !ok {
		add("缺少 info 节点")
	} else {
		if title, _ := info["title"].(string); strings.TrimSpace(title) == "" {
			add("info.title 不能为空")
		}
		if v, _ := info["version"].(string); strings.TrimSpace(v) == "" {
			add("info.version 不能为空")
		}
	}

	if len(s.Paths) == 0 {
		add("paths 下没有任何路径")
	}

	// ── 2. 标签：每个操作都必须属于已声明的标签 ─────────────────────
	declaredTags := map[string]struct{}{}
	if tagsNode, ok := s.Root["tags"].([]any); ok {
		for i, t := range tagsNode {
			tagMap, ok := asMap(t)
			if !ok {
				add("tags[%d] 不是映射", i)
				continue
			}
			name, _ := tagMap["name"].(string)
			if name == "" {
				add("tags[%d] 缺少 name", i)
				continue
			}
			declaredTags[name] = struct{}{}
		}
	}

	// ── 3. 安全方案：security 里引用的名字必须真实存在 ───────────────
	definedSchemes := map[string]struct{}{}
	if comps, ok := asMap(s.Root["components"]); ok {
		if schemes, ok := asMap(comps["securitySchemes"]); ok {
			for name := range schemes {
				definedSchemes[name] = struct{}{}
			}
		}
	}
	if len(definedSchemes) == 0 {
		add("components.securitySchemes 为空，但文档中使用了 security 声明")
	}

	checkSecurity := func(where string, node any) {
		reqs, ok := node.([]any)
		if !ok {
			return
		}
		for i, req := range reqs {
			reqMap, ok := asMap(req)
			if !ok {
				add("%s 的 security[%d] 不是映射", where, i)
				continue
			}
			for name, scopesNode := range reqMap {
				if _, ok := definedSchemes[name]; !ok {
					add("%s 的 security 引用了未定义的安全方案 %q", where, name)
				}
				// apiKey 类型的安全方案没有 scope 概念，非空数组几乎总是
				// 从别处复制粘贴留下的痕迹
				if scopes, ok := scopesNode.([]any); ok && len(scopes) > 0 {
					add("%s 的安全方案 %q 声明了 scope，但 apiKey 类型不支持 scope", where, name)
				}
			}
		}
	}
	checkSecurity("根级", s.Root["security"])

	// ── 4. 逐操作检查 ────────────────────────────────────────────────
	seenOperationIDs := map[string]string{}
	usedRefs := map[string]struct{}{}

	for _, op := range s.Operations() {
		where := op.RouteKey()

		if !strings.HasPrefix(op.Path, "/") {
			add("%s 的路径必须以 / 开头", where)
		}

		// operationId 是前端代码生成的函数名来源，重复会导致生成代码互相覆盖
		if strings.TrimSpace(op.OperationID) == "" {
			add("%s 缺少 operationId", where)
		} else if prev, dup := seenOperationIDs[op.OperationID]; dup {
			add("operationId %q 重复出现：%s 与 %s", op.OperationID, prev, where)
		} else {
			seenOperationIDs[op.OperationID] = where
		}

		// 每个操作至少要有一个响应
		responses, ok := asMap(op.Raw["responses"])
		if !ok || len(responses) == 0 {
			add("%s 未声明任何 responses", where)
		} else {
			for status := range responses {
				if !validHTTPStatus.MatchString(status) {
					add("%s 的响应键 %q 不是合法状态码（应为三位数字或 default，"+
						"注意 YAML 里必须写成带引号的字符串，否则会被解析成整数）", where, status)
				}
			}
		}

		// 标签必须是已声明的，否则文档工具会静默把接口丢进「未分类」
		if !checkTags(op.Raw, declaredTags) {
			add("%s 使用了未在根级 tags 中声明的标签", where)
		}

		checkSecurity(where, op.Raw["security"])

		// 路径模板变量必须被声明为 path 参数，否则前端按契约生成的
		// 调用代码会漏参数
		if err := s.checkPathParameters(op); err != nil {
			errs = append(errs, err...)
		}

		collectRefs(op.Raw, usedRefs)
	}

	collectRefs(s.Root["components"], usedRefs)

	// ── 5. $ref 必须都能解析，且不能指向外部文件 ─────────────────────
	for _, ref := range sortedKeys(usedRefs) {
		if !strings.HasPrefix(ref, "#/") {
			add("$ref %q 指向外部文档；契约必须自包含，否则校验与代码生成会依赖网络", ref)
			continue
		}
		if _, err := s.resolveRef(ref); err != nil {
			add("$ref %q 无法解析: %v", ref, err)
		}
	}

	// ── 6. 3.1 兼容性：禁止使用 3.0 的 nullable ──────────────────────
	for _, bad := range findNullable(s.Root, "") {
		add("%s 使用了 3.0 的 nullable 写法；OpenAPI 3.1 请改用 type: [\"<类型>\", \"null\"]", bad)
	}

	// ── 7. 未使用的 schema ──────────────────────────────────────────
	// 手写 spec 时最常见的遗留物：schema 定义了但忘了接上去，
	// 前端据此生成的类型于是永远用不到，而真正的响应形状无人校验。
	if comps, ok := asMap(s.Root["components"]); ok {
		if schemas, ok := asMap(comps["schemas"]); ok {
			names := make([]string, 0, len(schemas))
			for name := range schemas {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if _, used := usedRefs["#/components/schemas/"+name]; !used {
					add("schema %q 已定义但未被任何位置引用", name)
				}
			}
		}
	}

	return errs
}

// checkPathParameters 校验路径模板变量与 path 参数声明一一对应。
func (s *Spec) checkPathParameters(op Operation) []error {
	var errs []error

	// 模板里出现的变量
	declared := map[string]bool{}
	for _, m := range pathTemplateVar.FindAllStringSubmatch(op.Path, -1) {
		declared[m[1]] = true
	}

	// 实际声明的参数：路径项级 + 操作级，两者叠加生效
	provided := map[string]bool{}
	collector := func(node any) {
		list, ok := node.([]any)
		if !ok {
			return
		}
		for _, raw := range list {
			param := s.deref(raw)
			if param == nil {
				continue
			}
			if in, _ := param["in"].(string); in != "path" {
				continue
			}
			if name, _ := param["name"].(string); name != "" {
				provided[name] = true
				if required, _ := param["required"].(bool); !required {
					errs = append(errs, fmt.Errorf(
						"%s 的路径参数 %q 必须声明 required: true", op.RouteKey(), name))
				}
			}
		}
	}

	if item, ok := asMap(s.Root["paths"]); ok {
		if itemNode, ok := asMap(item[op.Path]); ok {
			collector(itemNode["parameters"])
		}
	}
	collector(op.Raw["parameters"])

	for name := range declared {
		if !provided[name] {
			errs = append(errs, fmt.Errorf(
				"%s 的路径模板变量 {%s} 没有对应的 path 参数声明", op.RouteKey(), name))
		}
	}
	for name := range provided {
		if !declared[name] {
			errs = append(errs, fmt.Errorf(
				"%s 声明了 path 参数 %q，但路径模板里没有 {%s}", op.RouteKey(), name, name))
		}
	}

	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errs
}

// resolveRef 按 JSON Pointer 解析本地 $ref。
func (s *Spec) resolveRef(ref string) (any, error) {
	node := any(s.Root)

	for _, token := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		// JSON Pointer 的转义规则：先解 ~1 再解 ~0，顺序不能反
		token = strings.ReplaceAll(token, "~1", "/")
		token = strings.ReplaceAll(token, "~0", "~")

		switch cur := node.(type) {
		case map[string]any:
			next, ok := cur[token]
			if !ok {
				return nil, fmt.Errorf("路径段 %q 不存在", token)
			}
			node = next
		case []any:
			var idx int
			if _, err := fmt.Sscanf(token, "%d", &idx); err != nil ||
				idx < 0 || idx >= len(cur) {
				return nil, fmt.Errorf("数组下标 %q 越界", token)
			}
			node = cur[idx]
		default:
			return nil, fmt.Errorf("路径段 %q 无法继续下钻（当前节点是标量）", token)
		}
	}
	return node, nil
}

// deref 若节点是 $ref 则解析之，否则原样返回映射形式。
func (s *Spec) deref(node any) map[string]any {
	m, ok := asMap(node)
	if !ok {
		return nil
	}
	if ref, ok := m["$ref"].(string); ok {
		resolved, err := s.resolveRef(ref)
		if err != nil {
			return nil
		}
		resolvedMap, ok := asMap(resolved)
		if !ok {
			return nil
		}
		return resolvedMap
	}
	return m
}

// collectRefs 递归收集节点树中出现的全部 $ref 字符串。
func collectRefs(node any, out map[string]struct{}) {
	switch cur := node.(type) {
	case map[string]any:
		for k, v := range cur {
			if k == "$ref" {
				if ref, ok := v.(string); ok {
					out[ref] = struct{}{}
				}
				continue
			}
			collectRefs(v, out)
		}
	case []any:
		for _, v := range cur {
			collectRefs(v, out)
		}
	}
}

// findNullable 找出所有使用 3.0 风格 nullable 的位置。
func findNullable(node any, path string) []string {
	var out []string

	switch cur := node.(type) {
	case map[string]any:
		if v, ok := cur["nullable"]; ok && v == true {
			out = append(out, path)
		}
		for k, v := range cur {
			out = append(out, findNullable(v, path+"/"+k)...)
		}
	case []any:
		for i, v := range cur {
			out = append(out, findNullable(v, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	sort.Strings(out)
	return out
}

// checkTags 校验操作声明的标签都在根级 tags 里登记过。
func checkTags(op map[string]any, declared map[string]struct{}) bool {
	list, ok := op["tags"].([]any)
	if !ok || len(list) == 0 {
		return false
	}
	for _, t := range list {
		name, ok := t.(string)
		if !ok {
			return false
		}
		if _, ok := declared[name]; !ok {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ 工具

// normalizeKeys 递归把所有映射的键统一为字符串。
//
// 归一化而非报错，是因为「状态码写成不带引号的 200:」在实践中完全无害：
// YAML 只是把它解析成整数键，而 OpenAPI 的语义里状态码就是字符串。
// js-yaml 等前端工具链读到这里会自动转成字符串，因此拒绝它属于过度严格——
// 真正需要防的是它引发的下游静默失败，归一化正好消除这一根源。
//
// 唯一需要拦截的是归一化之后会撞在一起的重复键（同时写了 `200` 与 `"200"`），
// 那是真实的歧义。
func normalizeKeys(node any, path string) (any, error) {
	switch cur := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(cur))
		for k, v := range cur {
			nv, err := normalizeKeys(v, path+"/"+k)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		}
		return out, nil

	case map[any]any:
		out := make(map[string]any, len(cur))
		for k, v := range cur {
			key, err := keyToString(k)
			if err != nil {
				return nil, fmt.Errorf("%s 下的映射键 %v 无法作为字符串使用", path, k)
			}
			if _, dup := out[key]; dup {
				return nil, fmt.Errorf(
					"%s 下同时出现了 %q 与其它会被归一化为同一字符串的键，存在歧义", path, key)
			}
			nv, err := normalizeKeys(v, path+"/"+key)
			if err != nil {
				return nil, err
			}
			out[key] = nv
		}
		return out, nil

	case []any:
		out := make([]any, len(cur))
		for i, v := range cur {
			nv, err := normalizeKeys(v, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil

	default:
		return node, nil
	}
}

// keyToString 把 YAML 标量键转成字符串。
func keyToString(key any) (string, error) {
	switch k := key.(type) {
	case string:
		return k, nil
	case int, int64, uint64, float64, bool:
		return fmt.Sprint(k), nil
	default:
		return "", fmt.Errorf("不支持的键类型 %T", key)
	}
}

func asMap(node any) (map[string]any, bool) {
	m, ok := node.(map[string]any)
	return m, ok
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------------ 路由比对

// NormalizeGinPath 把 gin 的路径语法转成 OpenAPI 模板语法。
//
//	/api/users/:id          → /api/users/{id}
//	/api/files/*filepath    → /api/files/{filepath}
//
// 存在的意义是让「spec 与真实路由表」这两个不同来源的路径能放在一起比较。
// 只比方法 + 规范化后的模板，不比较参数名——gin 的 :id 与 spec 的 {userId}
// 描述的是同一条路由，参数名不一致只是风格差异，不应导致契约校验失败。
func NormalizeGinPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") || strings.HasPrefix(p, "*") {
			parts[i] = "{" + p[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}

// Methods 返回本包认可的 HTTP 方法集合，供调用方过滤（例如排除 HEAD）。
func Methods() []string {
	out := make([]string, 0, len(httpMethods))
	for m := range httpMethods {
		out = append(out, strings.ToUpper(m))
	}
	sort.Strings(out)
	return out
}
