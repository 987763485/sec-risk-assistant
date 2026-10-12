package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// 默认超时。
//
// 两个值不一样是有原因的：docgen 是纯内存的 OpenXML 拼装，几十毫秒级；
// Gotenberg 要起一个 Chromium 进程渲染排版，秒级起步。给它们同一个超时，
// 要么委屈了 Gotenberg（大报告被误杀），要么纵容了 docgen（真挂了也要
// 等满 60 秒才报错）。
const (
	DefaultDocgenTimeout    = 30 * time.Second
	DefaultGotenbergTimeout = 60 * time.Second
)

// ErrUpstream 表示渲染所依赖的上游服务不可用。
//
// service 层据此返回 REPORT_RENDER_FAILED（503）而不是笼统的 500。
// 这个区分对用户是有意义的：503 表示「稍后重试大概率就好了」，
// 500 表示「系统自己有毛病」——前者可以再点一次导出，后者点了也白点。
var ErrUpstream = errors.New("上游渲染服务不可用")

// upstreamHTTPError 上游返回了非 2xx。
type upstreamHTTPError struct {
	Service string
	Status  int
	Detail  string
}

func (e *upstreamHTTPError) Error() string {
	return fmt.Sprintf("%s 返回 HTTP %d：%s", e.Service, e.Status, e.Detail)
}

// Client 渲染依赖的两个上游服务客户端。
//
// 两者合成一个对象而不是各写一个：它们总是一起被用（一份报告要么只要
// docgen，要么只要 gotenberg，但调用方不必关心），而且重试、超时、
// 错误包装的策略完全相同——拆成两个类会让这套策略有两份实现。
type Client struct {
	docgenURL        string
	gotenbergURL     string
	secret           string
	docgenTimeout    time.Duration
	gotenbergTimeout time.Duration

	// httpClient 不设 Timeout，超时一律由 per-request 的 context 控制。
	//
	// 理由：设了 http.Client.Timeout 之后，超时与「调用方取消」在错误里
	// 无法区分（都是 context.DeadlineExceeded）。而这两件事的处置完全不同：
	// 前者该重试，后者（用户已经关掉页面了）该立刻放弃。
	httpClient *http.Client
}

// NewClient 构建上游客户端。
//
// 超时为 0 时取默认值：让调用方可以「只想配 URL」而不用重复写两个时间。
func NewClient(docgenURL, gotenbergURL, secret string,
	docgenTimeout, gotenbergTimeout time.Duration) *Client {
	if docgenTimeout <= 0 {
		docgenTimeout = DefaultDocgenTimeout
	}
	if gotenbergTimeout <= 0 {
		gotenbergTimeout = DefaultGotenbergTimeout
	}
	return &Client{
		docgenURL:        trimSlash(docgenURL),
		gotenbergURL:     trimSlash(gotenbergURL),
		secret:           secret,
		docgenTimeout:    docgenTimeout,
		gotenbergTimeout: gotenbergTimeout,
		httpClient:       &http.Client{},
	}
}

// RenderDocx 调 docgen 渲染 docx。
func (c *Client) RenderDocx(ctx context.Context, req docxRenderRequest) ([]byte, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		// 序列化失败是我们自己的结构问题，不是上游问题，因此不包 ErrUpstream
		return nil, fmt.Errorf("序列化 docgen 请求失败: %w", err)
	}

	var out []byte
	err = c.withRetry(func() error {
		reqCtx, cancel := context.WithTimeout(ctx, c.docgenTimeout)
		defer cancel()

		httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
			c.docgenURL+"/api/v1/render/docx", bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("构造 docgen 请求失败: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("X-Internal-Secret", c.secret)

		body, err := c.do(httpReq, "docgen")
		if err != nil {
			return err
		}
		out = body
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	return out, nil
}

// renderOptions PDF 的版面参数。
type renderOptions struct {
	marginTop    string
	marginBottom string
	marginLeft   string
	marginRight  string
}

// defaultRenderOptions A4 中文报告的版面。
//
// 上下 20mm、左右 18mm：比 Word 的默认窄一点，因为报告里有多张宽表，
// 横向空间比纵向值钱。页脚（页码）绘制在下边距区域内，20mm 够放。
func defaultRenderOptions() renderOptions {
	return renderOptions{
		marginTop:    "0.79in", // ≈20mm
		marginBottom: "0.79in",
		marginLeft:   "0.71in", // ≈18mm
		marginRight:  "0.71in",
	}
}

// RenderPDF 调 Gotenberg 把 HTML 转成 PDF。
//
// ▍字段名与文件名的约定（实测确认，不是猜的）
//
// 主文档与页脚都是 multipart 的 `files` 字段，**靠文件名区分**：
// 叫 index.html 的当主文档，叫 footer.html 的当页脚。文件名字符串写错
// 不会报错，只是那一部分静默不生效（页脚不出现），因此这里的常量
// 与 Gotenberg 的约定必须逐字一致。
func (c *Client) RenderPDF(ctx context.Context, html, footer string) ([]byte, error) {
	var out []byte
	err := c.withRetry(func() error {
		body, contentType, err := buildGotenbergForm(html, footer, defaultRenderOptions())
		if err != nil {
			return err
		}

		reqCtx, cancel := context.WithTimeout(ctx, c.gotenbergTimeout)
		defer cancel()

		httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
			c.gotenbergURL+"/forms/chromium/convert/html", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("构造 gotenberg 请求失败: %w", err)
		}
		httpReq.Header.Set("Content-Type", contentType)

		res, err := c.do(httpReq, "gotenberg")
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	return out, nil
}

// buildGotenbergForm 组装 multipart 请求体。
func buildGotenbergForm(html, footer string, opt renderOptions) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// 主文档
	if err := writeFormFile(w, "index.html", html); err != nil {
		return nil, "", err
	}
	// 页脚（含页码）。为空时不传，Gotenberg 就不画页脚。
	if footer != "" {
		if err := writeFormFile(w, "footer.html", footer); err != nil {
			return nil, "", err
		}
	}

	// 版面参数
	for k, v := range map[string]string{
		"marginTop":    opt.marginTop,
		"marginBottom": opt.marginBottom,
		"marginLeft":   opt.marginLeft,
		"marginRight":  opt.marginRight,
		// 让 Chromium 用 CSS 里声明的 @page size（A4），而不是它自己的默认
		// Letter。少一处「代码里的纸张尺寸」与「模板里的纸张尺寸」不一致。
		"preferCssPageSize": "true",
		// 背景必须打印：等级色带与矩阵热力块都靠背景色，关掉就只剩灰边框。
		"printBackground": "true",
	} {
		if err := w.WriteField(k, v); err != nil {
			return nil, "", fmt.Errorf("写入 gotenberg 参数 %s 失败: %w", k, err)
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("关闭 multipart 失败: %w", err)
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// writeFormFile 往 multipart 里写一个「文件」字段。
//
// Gotenberg 只认 multipart 的**文件**部分（带 filename），普通文本字段
// 会被当成配置参数而不是内容——把 HTML 当文本字段发过去，它会返回
// 「至少需要一个文件」之类的错误，或干脆渲染出一个空白页。
func writeFormFile(w *multipart.Writer, filename, content string) error {
	part, err := w.CreateFormFile("files", filename)
	if err != nil {
		return fmt.Errorf("创建 multipart 部件 %s 失败: %w", filename, err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		return fmt.Errorf("写入 multipart 部件 %s 失败: %w", filename, err)
	}
	return nil
}

// do 发送请求并读回响应体。
func (c *Client) do(req *http.Request, service string) ([]byte, error) {
	res, err := c.httpClient.Do(req)
	if err != nil {
		// 网络层失败（连接被拒、DNS、超时、EOF）。
		// 不包装 ErrUpstream：那是调用方在外面统一加的，这里保留原始原因。
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	// 上传产物最大也就几 MB，但上游若返回异常内容也可能很大，
	// 加一个上限避免一次故障把内存吃满。
	body, err := io.ReadAll(io.LimitReader(res.Body, maxUpstreamBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 %s 响应失败: %w", service, err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &upstreamHTTPError{
			Service: service,
			Status:  res.StatusCode,
			Detail:  truncateText(string(body), 300),
		}
	}
	return body, nil
}

// maxUpstreamBytes 单次上游响应的读取上限（16 MB）。
const maxUpstreamBytes = 16 << 20

// withRetry 失败时重试一次。
//
// ▍为什么只重试一次、且只对特定错误重试
//
// 调用量极低（人工点一次导出），重试的收益是「上游偶发 5xx / 连接抖动时
// 用户不必再点一次」；代价是多等一个超时周期。重试超过一次会让最坏耗时
// 继续膨胀，而收益趋近于零。
//
// 只重试**网络错误与 5xx**：
//   - 4xx 是我们自己的请求构造错了（比如 docgen 改了契约），重试一百次
//     也是同样的 4xx，只是把错误暴露时间推迟了。
//   - 两个调用都是 POST，但都**没有副作用**（docgen 与 gotenberg 都是
//     无状态的纯渲染，不写任何数据），因此重试是安全的。这一点必须在
//     这里写清楚——换成一个有副作用的接口时，重试就成了重复下单。
func (c *Client) withRetry(fn func() error) error {
	firstErr := fn()
	if firstErr == nil {
		return nil
	}
	if !retryable(firstErr) {
		return firstErr
	}
	if secondErr := fn(); secondErr != nil {
		// 返回第二次的错误：重试之后的失败才是最终状态，
		// 而第一次的错误往往只是抖动。
		return secondErr
	}
	return nil
}

// retryable 判断错误是否值得重试。
func retryable(err error) bool {
	var he *upstreamHTTPError
	if errors.As(err, &he) {
		return he.Status >= 500
	}
	// 不是 HTTP 层的非 2xx，就是网络层错误 —— 值得重试。
	// 但**调用方取消**（用户关掉页面）不该重试：重试只会拖住 goroutine。
	if errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

// trimSlash 去掉 URL 结尾的斜杠，避免拼出 //api/... 这种路径。
func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// truncateText 截断长文本（上游的错误页可能有整页 HTML）。
func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
