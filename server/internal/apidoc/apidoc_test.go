package apidoc

import (
	"strings"
	"testing"
)

// validSpec 一份结构完备的最小契约。
//
// 各负向用例都在它的基础上做「只改一处」的破坏，这样一旦某个用例失败，
// 原因必然是那一处改动——而不是用例自身写错了。
const validSpec = `
openapi: 3.1.0
info:
  title: 测试契约
  version: 0.0.1
tags:
  - name: system
security: []
components:
  securitySchemes:
    SessionCookie:
      type: apiKey
      in: cookie
      name: sr_at
  schemas:
    Pong:
      type: object
      required: [ok]
      properties:
        ok:
          type: boolean
paths:
  /ping:
    get:
      tags: [system]
      operationId: ping
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Pong"
`

func parseSpec(t *testing.T, body string) *Spec {
	t.Helper()
	spec, err := Parse([]byte(body), "test.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	return spec
}

// TestParse_ValidSpecHasNoProblems 是基线用例：
// 若它失败，说明校验器存在误报，后续所有负向用例的结论都不可信。
func TestParse_ValidSpecHasNoProblems(t *testing.T) {
	spec := parseSpec(t, validSpec)
	if problems := spec.Validate(); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("合法契约被误报: %v", p)
		}
		t.Fatalf("合法契约产生了 %d 个误报", len(problems))
	}
}

// TestParse_RejectsDuplicateKeys 覆盖 YAML 最隐蔽的坑。
//
// YAML 规范允许映射里出现重复的键，且规定「后者覆盖前者」。对一个手写的
// 契约文件来说，这意味着一条重复的路径会静默地吃掉前一条——文档里看着
// 两条都在，实际只剩一条，而且没有任何提示。
func TestParse_RejectsDuplicateKeys(t *testing.T) {
	body := strings.Replace(validSpec,
		"  /ping:\n",
		"  /ping:\n    get:\n      tags: [system]\n      operationId: shadow\n      responses:\n        \"200\":\n          description: shadow\n  /ping:\n",
		1)

	if _, err := Parse([]byte(body), "test.yaml"); err == nil {
		t.Fatal("重复的路径键应当导致解析失败，实际通过了")
	}
}

func TestParse_RejectsEmptyDocument(t *testing.T) {
	if _, err := Parse([]byte("# 只有注释\n"), "test.yaml"); err == nil {
		t.Fatal("空文档应当导致解析失败")
	}
}

// TestValidate_RejectsWrongOpenAPIVersion 钉住 3.1。
//
// 3.0 用 nullable、3.1 用 type 数组，两者生成出的 TypeScript 类型完全不同。
// 容忍「3.x 都行」会让契约悄悄退回 3.0 写法而不被发现。
func TestValidate_RejectsWrongOpenAPIVersion(t *testing.T) {
	body := strings.Replace(validSpec, "openapi: 3.1.0", "openapi: 3.0.3", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "可空写法不兼容") {
		t.Fatalf("未拒绝 3.0 契约，问题清单: %v", problems)
	}
}

func TestValidate_RejectsDanglingRef(t *testing.T) {
	body := strings.Replace(validSpec,
		`"#/components/schemas/Pong"`, `"#/components/schemas/DoesNotExist"`, 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "无法解析") {
		t.Fatalf("悬空 $ref 未被发现，问题清单: %v", problems)
	}
}

func TestValidate_RejectsExternalRef(t *testing.T) {
	body := strings.Replace(validSpec,
		`"#/components/schemas/Pong"`, `"common.yaml#/Pong"`, 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "指向外部文档") {
		t.Fatalf("外部 $ref 未被拒绝，问题清单: %v", problems)
	}
}

func TestValidate_RejectsMissingOperationID(t *testing.T) {
	body := strings.Replace(validSpec, "      operationId: ping\n", "", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "缺少 operationId") {
		t.Fatalf("缺失 operationId 未被发现，问题清单: %v", problems)
	}
}

func TestValidate_RejectsDuplicateOperationID(t *testing.T) {
	// 新增一条路径，复用已有的 operationId
	body := validSpec + `
  /pong:
    get:
      tags: [system]
      operationId: ping
      responses:
        "200":
          description: ok
`
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "重复出现") {
		t.Fatalf("重复 operationId 未被发现，问题清单: %v", problems)
	}
}

func TestValidate_RejectsMissingResponses(t *testing.T) {
	body := strings.Replace(validSpec,
		"      responses:\n        \"200\":\n          description: ok\n          content:\n            application/json:\n              schema:\n                $ref: \"#/components/schemas/Pong\"\n",
		"", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "未声明任何 responses") {
		t.Fatalf("缺失 responses 未被发现，问题清单: %v", problems)
	}
}

// TestParse_NormalizesUnquotedStatusCode 覆盖 yaml.v3 的一个关键行为。
//
// 映射里只要出现非字符串键，yaml.v3 就会把**那一层**从 map[string]any
// 降级成 map[interface{}]interface{}。若不归一化，下游按 key 取值会静默
// 拿不到东西，并且报出与真实原因毫不相干的错误——实测中「状态码没加引号」
// 会被报成「未声明任何 responses」，足以让人排查方向完全跑偏。
//
// 归一化而不是报错，是因为不带引号的状态码在实践中无害：OpenAPI 语义里
// 状态码本就是字符串，前端工具链读到这里也会自动转换。
func TestParse_NormalizesUnquotedStatusCode(t *testing.T) {
	body := strings.Replace(validSpec, `        "200":`, "        200:", 1)

	spec := parseSpec(t, body)
	ops := spec.Operations()
	if len(ops) != 1 {
		t.Fatalf("期望 1 个操作，实际 %d 个", len(ops))
	}

	responses, ok := ops[0].Raw["responses"].(map[string]any)
	if !ok {
		t.Fatalf("responses 未被归一化为 map[string]any，实际 %T",
			ops[0].Raw["responses"])
	}
	if _, ok := responses["200"]; !ok {
		t.Fatalf("未加引号的 200 未归一化为字符串键，实际键集合: %v", keysOf(responses))
	}

	// 归一化之后不应产生任何误报
	if problems := spec.Validate(); len(problems) > 0 {
		t.Fatalf("归一化后仍出现误报: %v", problems)
	}
}

// TestParse_RejectsAmbiguousNormalizedKeys 拦截归一化之后会撞车的真实歧义。
func TestParse_RejectsAmbiguousNormalizedKeys(t *testing.T) {
	body := strings.Replace(validSpec, `        "200":`,
		"        \"200\":\n          description: 字符串键\n        200:", 1)

	if _, err := Parse([]byte(body), "test.yaml"); err == nil {
		t.Fatal("同时出现 200 与 \"200\" 应当被拒绝，实际通过了")
	}
}

func TestValidate_RejectsUndeclaredTag(t *testing.T) {
	body := strings.Replace(validSpec, "      tags: [system]", "      tags: [nosuchtag]", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "未在根级 tags") {
		t.Fatalf("未声明的标签未被发现，问题清单: %v", problems)
	}
}

func TestValidate_RejectsUnknownSecurityScheme(t *testing.T) {
	body := strings.Replace(validSpec, "security: []", "security:\n  - NoSuchScheme: []", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "未定义的安全方案") {
		t.Fatalf("未知安全方案未被发现，问题清单: %v", problems)
	}
}

func TestValidate_RejectsScopesOnAPIKey(t *testing.T) {
	body := strings.Replace(validSpec, "security: []",
		"security:\n  - SessionCookie: [read]", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "apiKey 类型不支持 scope") {
		t.Fatalf("apiKey 上的 scope 未被发现，问题清单: %v", problems)
	}
}

// TestValidate_RejectsUndeclaredPathParameter 是防止前端生成代码漏参的护栏。
func TestValidate_RejectsUndeclaredPathParameter(t *testing.T) {
	body := strings.Replace(validSpec, "  /ping:", "  /users/{id}:", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "没有对应的 path 参数声明") {
		t.Fatalf("未声明的路径参数未被发现，问题清单: %v", problems)
	}
}

func TestValidate_RejectsOptionalPathParameter(t *testing.T) {
	body := strings.Replace(validSpec, "  /ping:", "  /users/{id}:", 1)
	body = strings.Replace(body, "      tags: [system]",
		"      parameters:\n        - name: id\n          in: path\n          schema:\n            type: string\n      tags: [system]", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "必须声明 required: true") {
		t.Fatalf("非必填的路径参数未被发现，问题清单: %v", problems)
	}
}

func TestValidate_RejectsNullableKeyword(t *testing.T) {
	body := strings.Replace(validSpec,
		"        ok:\n          type: boolean",
		"        ok:\n          type: boolean\n          nullable: true", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, "nullable") {
		t.Fatalf("3.0 风格的 nullable 未被发现，问题清单: %v", problems)
	}
}

// TestValidate_RejectsUnusedSchema 抓「定义了但忘了接上」的遗留物。
func TestValidate_RejectsUnusedSchema(t *testing.T) {
	body := strings.Replace(validSpec,
		"  schemas:\n",
		"  schemas:\n    Orphan:\n      type: object\n", 1)
	problems := parseSpec(t, body).Validate()

	if !containsProblem(problems, `"Orphan" 已定义但未被任何位置引用`) {
		t.Fatalf("未被引用的 schema 未被发现，问题清单: %v", problems)
	}
}

// TestOperation_RouteKey 确认路径模板不被改写。
func TestOperation_RouteKey(t *testing.T) {
	spec := parseSpec(t, validSpec)
	ops := spec.Operations()
	if len(ops) != 1 {
		t.Fatalf("期望 1 个操作，实际 %d 个", len(ops))
	}
	if got, want := ops[0].RouteKey(), "GET /ping"; got != want {
		t.Errorf("RouteKey = %q，期望 %q", got, want)
	}
}

// TestNormalizeGinPath 覆盖 gin 路径语法到 OpenAPI 模板的转换。
func TestNormalizeGinPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/api/users", "/api/users"},
		{"/api/users/:id", "/api/users/{id}"},
		{"/api/users/:id/reset-password", "/api/users/{id}/reset-password"},
		{"/api/files/*filepath", "/api/files/{filepath}"},
		{"/api/a/:b/c/:d", "/api/a/{b}/c/{d}"},
	}
	for _, c := range cases {
		if got := NormalizeGinPath(c.in); got != c.want {
			t.Errorf("NormalizeGinPath(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// containsProblem 判断问题清单里是否有条目包含指定子串。
func containsProblem(problems []error, substr string) bool {
	for _, p := range problems {
		if strings.Contains(p.Error(), substr) {
			return true
		}
	}
	return false
}

// keysOf 返回映射的键集合，仅用于测试失败时的可读输出。
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
