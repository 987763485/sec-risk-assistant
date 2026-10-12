// Package intelfeed 实现三方漏洞情报源的适配器与**出站安全约束**。
//
// 这个包与 `pkg/riskengine` 有一处重要的不同：riskengine 是纯函数，
// 而这里要发起网络请求。因此它的设计重心不在「算得对不对」，
// 而在「**哪些地址允许访问**」——`base_url` 是用户在界面上填的，
// 也就是说，谁能改集成配置，谁就能决定这台服务器下一步向哪里发起请求。
//
// ▍头号风险：SSRF
//
// 一个能填任意 `base_url` 的「拉取」按钮，等价于给攻击者一个
// 「让内网服务器替我发请求」的原语。典型利用：
//
//	http://169.254.169.254/latest/meta-data/iam/security-credentials/
//	http://127.0.0.1:3306/            （用响应时间探测内网端口）
//	http://10.0.0.5:8080/admin        （带着服务器的网络身份访问内网管理面）
//
// 本包的防护分**两层**，缺一不可（见 guard.go）：
//
//  1. 发起请求前解析域名并校验 IP —— 给出明确的 400，而不是一句
//     「连接被拒绝」让用户以为是网络问题；
//  2. 连接建立时（`net.Dialer.Control`）再校验一次实际要连的 IP ——
//     第一层与真正 connect 之间存在时间差，攻击者可以让 DNS 在这之间
//     返回不同答案（DNS rebinding / TOCTOU），只有第二层能拦住它。
//
// ▍为什么是「校验解析后的 IP」而不是「校验字符串」
//
// 同一台主机有无数种写法：`127.0.0.1` / `0x7f.1` / `2130706433` /
// `[::ffff:127.0.0.1]` / `127.1`。任何基于字符串匹配的黑名单都能被绕过，
// 而基于**解析结果**的判定只需要覆盖一次网段列表。
//
// ▍适配器类型与严重度的取值只在这里定义
//
// `TypeNVD` / `TypeLocal` 与 `Severity*` 是本包导出的常量，
// 数据库列（`integrations.type` / `vuln_intel.source` / `vuln_intel.severity`）
// 与契约枚举都指向它们，不存在第二份字面量。
// 因此 model 里只声明「这个字段是字符串」，不再重复一份取值列表——
// 两份定义的分叉不会报错，只会在某次比较里静默不相等。
//
// ▍适配器只做「取数与归一」
//
// 本包不碰数据库、不碰权限、不写审计——那些是 service 层的事。
// 这样适配器可以被纯 Go 测试直接驱动（含 local 离线驱动），
// 无须起 HTTP 服务或连库。
package intelfeed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 适配器类型标识。
const (
	// TypeNVD NVD（美国国家漏洞数据库）REST API 2.0。
	TypeNVD = "nvd"
	// TypeLocal 离线驱动：不访问网络，按内置数据返回。
	//
	// 它存在的理由不是「测试方便」，而是让**验收标志与外部可达性解耦**：
	// 守门脚本必须能在没有外网、没有 API Key 的环境里跑出全绿，
	// 否则 CI 一断网守门就失效——而失效的守门比没有守门更糟，
	// 因为它会让人相信「系统是好的」。
	TypeLocal = "local"
)

// 严重度归一化后的五个取值。
//
// ⚠️ 它是**入库时一次性归一化**的结果，之后不再重算：情报表的定位是快照，
// 而快照的本分就是「记下当时上游说的是什么」。刻意**不**在读取时按
// cvss_score 现算档位——那会让「上游标 high 但我们算出 6.5（medium）」
// 在同一行里给出两个互相矛盾的答案。
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	// SeverityUnknown 上游未给出可识别的严重度，且分数也没有。
	// 刻意不用「默认 medium」：把未知当中间值会在统计图里
	// 凭空造出一批「中危」，而它们其实只是没数据。
	SeverityUnknown = "unknown"
)

// 出站请求的硬约束。
//
// 这些值刻意写成常量而不是配置项：它们是**安全上限**，
// 不是「部署时可调的参数」。放成配置项意味着一次误配就能
// 把「响应体上限 2 MB」改成 2 GB，而失败模式是进程 OOM。
const (
	// MaxBodyBytes 单个响应的最大读取字节数。
	// 用 io.LimitReader 截断而不是信任 Content-Length：
	// 上游可以不给这个头，也可以给一个远小于实际流的假值。
	MaxBodyBytes = 2 << 20 // 2 MiB
	// MinTimeout / MaxTimeout 单次请求的超时区间。
	// 上限与 server.write_timeout 是同一条理由：一个配置成 10 分钟的超时
	// 会把一个 HTTP 请求连同它的数据库连接一起占住十分钟，而用户早已离开。
	MinTimeout = 1 * time.Second
	// MaxTimeout 单次请求超时上限。
	MaxTimeout = 30 * time.Second
	// DefaultTimeout 配置里没写超时时的取值。
	DefaultTimeout = 10 * time.Second
)

// ErrNotFound 上游**明确回答**「没有这条 CVE」。
//
// 必须与「网络失败」区分开，因为下一步动作完全不同：
// 前者是结论（该 CVE 号可能拼错了，或者上游确实没收录），
// 后者要重试。合成一个错误会让用户对着一个「拉取失败」反复点，
// 而其实再点一百次也是同一个答案。
var ErrNotFound = errors.New("intelfeed: 上游没有这条 CVE")

// ErrEndpointBlocked 出站目标被安全策略拒绝（SSRF 防护，见 guard.go）。
var ErrEndpointBlocked = errors.New("intelfeed: 出站目标被安全策略拒绝")

// ErrUnknownType 适配器类型不受支持。
var ErrUnknownType = errors.New("intelfeed: 不支持的情报源类型")

// Request 一次拉取的输入。
//
// Credential 是**已经解析好的凭据明文**——本包不读环境变量。
// 读环境变量是 service 层的动作（那里才做「变量名是否在白名单里」的判定），
// 把这一步留在包外，本包才能被测试直接驱动而不必污染进程环境。
type Request struct {
	// BaseURL 上游基址。空串表示该适配器不需要地址（local）。
	BaseURL string
	// Credential 凭据明文；空串表示无凭据。
	// ⚠️ 任何错误信息都**不得**包含它（见 nvd.go 的错误构造）。
	Credential string
	// CVEID 目标 CVE 编号，形如 CVE-2021-44228。
	CVEID string
	// Timeout 单次请求超时；超出 [MinTimeout, MaxTimeout] 时自动收敛。
	Timeout time.Duration
}

// Record 一次拉取得到的一条情报（归一化后的形态）。
//
// 字段刻意与 model.VulnIntel 一一对应但**不引用它**：
// 本包不依赖领域模型，它只回答「上游说了什么」，
// 「这句话在我们的库里怎么存」是 service 层的事。
type Record struct {
	CVEID       string
	Title       string
	Description string
	// Severity 归一化到 Severity* 之一。
	Severity string
	// CVSSScore 为空表示上游未给出分数。
	CVSSScore  *float64
	CVSSVector string
	Published  *time.Time
	// References 参考链接。
	References []string
	// Raw 上游原始片段（已截断），落库供追溯「界面显示的与上游是否一致」。
	Raw []byte
}

// Feed 情报源适配器。
//
// 只有一个方法：拉取单条 CVE。批量、缓存、落库、限流全部不在适配器职责内——
// 它们要么属于 service 层（批量编排），要么属于「P7 明确不做」的范畴
// （定时同步、订阅推送）。
type Feed interface {
	// Type 适配器类型标识。
	Type() string
	// Fetch 按 CVE 编号拉取一条情报。
	//
	// 返回 ErrNotFound 表示上游明确没有这条 CVE；
	// 返回 ErrEndpointBlocked 表示出站目标被拒（service 层据此回 400，
	// 而不是把配置问题伪装成「上游挂了」）。
	Fetch(ctx context.Context, req Request) (*Record, error)
}

// 适配器注册表。
//
// 用包级 map 而不是 switch：新增一个情报源只需要加一个文件 + 一行注册，
// 而「哪些源受支持」这件事只在这一个地方回答。
var registry = map[string]func() Feed{
	TypeNVD:   func() Feed { return nvdFeed{} },
	TypeLocal: func() Feed { return localFeed{} },
}

// Supported 返回受支持的适配器类型（顺序即界面下拉框顺序）。
func Supported() []string {
	return []string{TypeNVD, TypeLocal}
}

// IsSupportedType 判断类型是否受支持。
func IsSupportedType(typeName string) bool {
	_, ok := registry[typeName]
	return ok
}

// New 按类型构建适配器。
func New(typeName string) (Feed, error) {
	factory, ok := registry[typeName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownType, typeName)
	}
	return factory(), nil
}

// RequiresCredential 该类型是否必须配置凭据。
//
// 只有 NVD 需要：它自 2023 年起对无 Key 的调用实施严格限流
// （约 5 次/30 秒），生产上必须带 API Key。
func RequiresCredential(typeName string) bool {
	return typeName == TypeNVD
}

// DefaultBaseURL 该类型的默认上游基址，仅用于界面预填。
//
// ⚠️ 默认值不会被当作「可信地址」跳过校验：base_url 无论如何
// 都要过一遍 CheckEndpoint。把它当成白名单是一个典型的降级路径——
// 用户只要把地址改回默认值再配一个同名 hosts 记录就能绕过。
func DefaultBaseURL(typeName string) string {
	switch typeName {
	case TypeNVD:
		return "https://services.nvd.nist.gov"
	default:
		return ""
	}
}

// ClampTimeout 把超时收敛到 [MinTimeout, MaxTimeout]。
//
// 越界值**收敛而不是报错**，与 handler 层分页参数的处理一致：
// 一个不合理的超时不值得打断一次用户发起的拉取，
// 但也绝不能让它穿透到网络层。
func ClampTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTimeout
	}
	if d < MinTimeout {
		return MinTimeout
	}
	if d > MaxTimeout {
		return MaxTimeout
	}
	return d
}

// Severities 返回全部严重度取值。
func Severities() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown}
}

// SeverityFromCVSS 由 CVSS 基础分推导档位。
//
// 仅在**上游没有给出可识别的 severity 文本**时作为兜底使用
// （NVD 的多数响应带 `baseSeverity`，那时以它为准）。
// 分档边界采用 CVSS v3.1 规范的定义：9.0+ / 7.0+ / 4.0+ / >0 / 其余。
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// NormalizeSeverity 把上游给的严重度文案归一化到 Severity* 之一。
//
// 上游的写法并不统一（NVD 用大写的 `CRITICAL`，别的源可能给
// `严重` / `Moderate` / 空串），而归一化只在**写库前发生一次**。
// raw 无法识别时退回 cvssScore 推导；两者都没有才落到 unknown。
func NormalizeSeverity(raw string, cvssScore *float64) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case SeverityCritical, "严重", "极高":
		return SeverityCritical
	case SeverityHigh, "高":
		return SeverityHigh
	case SeverityMedium, "中", "moderate", "中等":
		return SeverityMedium
	case SeverityLow, "低":
		return SeverityLow
	case SeverityUnknown, "未知":
		return SeverityUnknown
	}
	if cvssScore != nil {
		return SeverityFromCVSS(*cvssScore)
	}
	return SeverityUnknown
}
