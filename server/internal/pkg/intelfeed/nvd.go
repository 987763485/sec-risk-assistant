package intelfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// nvdFeed NVD（美国国家漏洞数据库）适配器。
//
// ▍为什么是 NVD
//
// 它是漏洞情报里**唯一**有正式公开 REST API、无需商业授权、
// 且覆盖全量 CVE 的来源。接入它就能证明「外部网络这条路是通的」——
// 这正是 P7 验收标志的真实含义。
//
// ▍限流
//
// NVD API 2.0 对无 Key 的调用限到约 5 次/30 秒，带 Key 约 50 次/30 秒。
// 本适配器不做排队与重试（那属于「定时同步」范畴，P7 明确不做），
// 但把 429 单独识别出来给出可操作的提示——「稍后再试或配 Key」，
// 而不是让它落进通用的「拉取失败」。
type nvdFeed struct{}

// nvdCVEPath NVD API 2.0 的按 CVE 查询路径。
//
// 基址与路径分开：`base_url` 允许用户指向代理入口（很多内网部署会这么做），
// 因此不能把整条 URL 写死。
const nvdCVEPath = "/rest/json/cves/2.0"

// Type 实现 Feed。
func (nvdFeed) Type() string { return TypeNVD }

// nvdCVEDoc 我们关心的那部分 CVE 文档结构。
//
// 只声明用得到的字段：NVD 的响应有几十个字段（配置、弱点、影响范围……），
// 全量建模既无必要，也会在下游加字段时留下「这个字段为什么没人用」的困惑。
type nvdCVEDoc struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
	References   []nvdReference   `json:"references"`
}

// nvdDescription 多语言描述。取哪一条见 englishDescription。
type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// nvdMetrics CVSS 度量集合。
type nvdMetrics struct {
	// 优先级：V3.1 → V3.0 → V2。同一个 CVE 可能三种都有，
	// 取最新的一版才是「今天该怎么理解它」。
	CVSSMetricV31 []nvdMetricV3 `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdMetricV3 `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdMetricV2 `json:"cvssMetricV2"`
}

// nvdMetricV3 CVSS v3.x 的度量块。
type nvdMetricV3 struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// nvdMetricV2 CVSS v2 的度量块。
//
// 与 v3 的结构差异是真实存在的：v2 把 `baseSeverity` 放在 metric 层级，
// 不在 `cvssData` 里。照着 v3 的结构去解 v2 会静默拿到空字符串。
type nvdMetricV2 struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// nvdReference 参考链接。
type nvdReference struct {
	URL string `json:"url"`
}

// nvdResponse NVD API 2.0 的响应信封。
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVEDoc `json:"cve"`
	} `json:"vulnerabilities"`
}

// Fetch 实现 Feed。
func (f nvdFeed) Fetch(ctx context.Context, req Request) (*Record, error) {
	cveID := strings.ToUpper(strings.TrimSpace(req.CVEID))
	if cveID == "" {
		return nil, errors.New("intelfeed: 未指定 CVE 编号")
	}

	base := strings.TrimSpace(req.BaseURL)
	if base == "" {
		base = DefaultBaseURL(TypeNVD)
	}

	// 拉取时**再校验一次**出站目标，而不是只在保存配置时校验：
	// 保存与拉取之间可能隔了很多天，期间这个域名的 DNS 记录完全可以
	// 被改成内网地址。只在保存时校验，等于把一次检查当成了永久授权。
	endpoint, err := CheckEndpoint(ctx, base)
	if err != nil {
		return nil, err
	}

	timeout := ClampTimeout(req.Timeout)
	client := newGuardedClient(timeout)

	target := endpoint + nvdCVEPath + "?cveId=" + url.QueryEscape(cveID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("构造 NVD 请求失败: %w", err)
	}
	if req.Credential != "" {
		// ⚠️ 凭据只出现在请求头里。它绝不能出现在 URL、日志或错误信息中——
		// 本文件所有 fmt.Errorf 都只带状态码与 CVE 编号，不带 req.Credential。
		httpReq.Header.Set("apiKey", req.Credential)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "sec-risk-assistant-intelfeed/0.1")

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, ErrEndpointBlocked) {
			// 连接阶段被 Control 拦下：说明预检之后 DNS 答案变了。
			// 这一条比普通失败严重得多（可能是 rebinding 尝试），
			// 因此保留 ErrEndpointBlocked 这个身份让上层能区分对待。
			return nil, fmt.Errorf("%w：主机 %q 在连接阶段解析到受限地址",
				ErrEndpointBlocked, hostOf(endpoint))
		}
		return nil, fmt.Errorf("请求 NVD 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 先截断再判断状态码：一个错误页也可能是无限流，
	// 而我们要读它只是为了记一句原因。
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 NVD 响应失败: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// 继续解析
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf(
			"NVD 拒绝了本次请求（HTTP %d）：请检查集成配置里的凭据环境变量是否指向有效的 API Key",
			resp.StatusCode)
	case http.StatusTooManyRequests:
		return nil, errors.New(
			"NVD 限流（HTTP 429）：请稍后重试，或为集成配置 API Key 以提高配额")
	default:
		return nil, fmt.Errorf("NVD 返回异常状态 HTTP %d", resp.StatusCode)
	}

	var parsed nvdResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("解析 NVD 响应失败: %w", err)
	}
	// NVD 对未知 CVE 返回 200 + totalResults=0，而不是 404。
	// 漏掉这一条会让「CVE 号拼错了」被报成「上游没反应」，用户查不出原因。
	if parsed.TotalResults == 0 || len(parsed.Vulnerabilities) == 0 {
		return nil, ErrNotFound
	}

	cve := parsed.Vulnerabilities[0].CVE
	score, severity, vector := cve.bestSeverity()

	rec := &Record{
		CVEID: cve.ID,
		// NVD 不提供标题字段，如实留空；展示层回退显示 CVE 编号。
		// 不用 description 截一段当标题：那会在界面上造出一句
		// 与上游任何字段都不对应的文本。
		Title:       "",
		Description: cve.englishDescription(),
		CVSSVector:  vector,
		References:  cve.referenceURLs(),
		Published:   parseNVDTime(cve.Published),
		CVSSScore:   score,
	}
	if rec.CVEID == "" {
		rec.CVEID = cveID
	}
	rec.Severity = NormalizeSeverity(severity, rec.CVSSScore)

	// Raw 只保留 cve 文档本身，不整包存响应：一个 CVE 的完整响应
	// 可能有几十 KB，而我们要追溯的只是「这个 CVE 的字段当时长什么样」。
	if raw, err := json.Marshal(cve); err == nil && len(raw) <= MaxBodyBytes {
		rec.Raw = raw
	}

	return rec, nil
}

// bestSeverity 按 V3.1 → V3.0 → V2 的优先级取出分数、严重度文案与向量。
func (c nvdCVEDoc) bestSeverity() (*float64, string, string) {
	if len(c.Metrics.CVSSMetricV31) > 0 {
		d := c.Metrics.CVSSMetricV31[0].CVSSData
		score := d.BaseScore
		return &score, d.BaseSeverity, d.VectorString
	}
	if len(c.Metrics.CVSSMetricV30) > 0 {
		d := c.Metrics.CVSSMetricV30[0].CVSSData
		score := d.BaseScore
		return &score, d.BaseSeverity, d.VectorString
	}
	if len(c.Metrics.CVSSMetricV2) > 0 {
		m := c.Metrics.CVSSMetricV2[0]
		score := m.CVSSData.BaseScore
		return &score, m.BaseSeverity, m.CVSSData.VectorString
	}
	return nil, "", ""
}

// englishDescription 取英文描述。
//
// 优先英文而不是「第一条」：NVD 的描述数组里第一条不保证是英文
// （CVE 记录可以被各国 CNA 提交），而界面是中文语境，英文描述
// 至少是可读的通用语；抓错语言会让详情页出现一段谁也看不懂的文本。
func (c nvdCVEDoc) englishDescription() string {
	for _, d := range c.Descriptions {
		if strings.EqualFold(d.Lang, "en") && strings.TrimSpace(d.Value) != "" {
			return d.Value
		}
	}
	for _, d := range c.Descriptions {
		if strings.TrimSpace(d.Value) != "" {
			return d.Value
		}
	}
	return ""
}

// referenceURLs 提取参考链接（去掉空项）。
func (c nvdCVEDoc) referenceURLs() []string {
	out := make([]string, 0, len(c.References))
	for _, r := range c.References {
		if u := strings.TrimSpace(r.URL); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// hostOf 从归一化后的地址里取主机名，仅用于错误信息。
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

// parseNVDTime 解析 NVD 的时间串。
//
// 上游的写法不稳定：带 `Z`、带毫秒、不带毫秒、偶尔带偏移量都出现过。
// 逐个 layout 尝试比「假定一种格式」可靠——后者在格式变化时会静默
// 返回零值时间，而界面只会显示成一片空白。
func parseNVDTime(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return &t
		}
	}
	return nil
}
