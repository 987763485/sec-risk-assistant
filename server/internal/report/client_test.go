package report

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSecret = "test-internal-secret-0123456789"

// TestDocgenSendsSecretAndRetries5xx 上游 5xx 时重试一次，且带上内部密钥。
//
// 重试的价值在于「上游偶发抖动时用户不必再点一次导出」；这里同时钉住
// 请求头 —— docgen 会用恒定时间比较校验 X-Internal-Secret，漏了就是 401。
func TestDocgenSendsSecretAndRetries5xx(t *testing.T) {
	var calls int32
	seenSecret := make(chan string, 4)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		seenSecret <- r.Header.Get("X-Internal-Secret")

		if r.URL.Path != "/api/v1/render/docx" {
			t.Errorf("请求路径 = %q，期望 /api/v1/render/docx", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q，期望 application/json", ct)
		}
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "第一次故意失败")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "FAKE-DOCX-BYTES")
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, testSecret, 2*time.Second, 2*time.Second)
	out, err := c.RenderDocx(context.Background(), docxRenderRequest{Title: "测试"})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if string(out) != "FAKE-DOCX-BYTES" {
		t.Errorf("返回内容 = %q", out)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("请求次数 = %d，期望 2（第一次 5xx 后应重试一次）", got)
	}
	if got := <-seenSecret; got != testSecret {
		t.Errorf("X-Internal-Secret = %q，期望 %q", got, testSecret)
	}
}

// TestDocgenDoesNotRetry4xx 4xx 不重试。
//
// 4xx 意味着我们自己的请求构造错了（比如 docgen 改了契约）。
// 重试一百次也是同一个 4xx，只是把错误暴露时间推迟、还多占两个超时周期。
func TestDocgenDoesNotRetry4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"INVALID_REQUEST","message":"title 与 sections 不能同时为空"}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, testSecret, time.Second, time.Second)
	_, err := c.RenderDocx(context.Background(), docxRenderRequest{})
	if err == nil {
		t.Fatal("期望报错，实际成功")
	}
	if !errors.Is(err, ErrUpstream) {
		t.Errorf("错误应可被 errors.Is(err, ErrUpstream) 识别，实际: %v", err)
	}
	// 错误信息里必须能看到上游名字与状态码，否则排查时不知道是谁挂了
	if !strings.Contains(err.Error(), "docgen") || !strings.Contains(err.Error(), "400") {
		t.Errorf("错误信息应指名上游与状态码，实际: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("请求次数 = %d，期望 1（4xx 不应重试）", got)
	}
}

// TestDocgenFailsAfterRetry 两次都 5xx 时报错，且错误可被识别为上游故障。
func TestDocgenFailsAfterRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "上游自己也不舒服")
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, testSecret, time.Second, time.Second)
	_, err := c.RenderDocx(context.Background(), docxRenderRequest{Title: "x"})
	if err == nil {
		t.Fatal("期望报错，实际成功")
	}
	if !errors.Is(err, ErrUpstream) {
		t.Errorf("错误应可被识别为上游故障，实际: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("请求次数 = %d，期望 2（重试一次后放弃）", got)
	}
}

// TestDocgenTimeoutRetries 超时算网络错误，会重试一次。
func TestDocgenTimeoutRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(120 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, testSecret, 30*time.Millisecond, 30*time.Millisecond)
	start := time.Now()
	_, err := c.RenderDocx(context.Background(), docxRenderRequest{Title: "x"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("期望超时报错，实际成功")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("请求次数 = %d，期望 2（超时后重试一次）", got)
	}
	// 两次超时约 60ms；给它一个宽松上界，只要求「没有无限等下去」
	if elapsed > 2*time.Second {
		t.Errorf("耗时 %v 远超预期，重试策略可能失控", elapsed)
	}
}

// TestGotenbergMultipartFields 发给 Gotenberg 的 multipart 结构。
//
// ⚠️ 这条测试挡的是一个**静默失效**：Gotenberg 靠**文件名**区分主文档与
// 页脚（都挂在 files 字段下）。文件名字符串写错不报错，只是页脚不出现 ——
// 报告照样生成，只是没有页码。所以要把字段名逐字钉死。
func TestGotenbergMultipartFields(t *testing.T) {
	type captured struct {
		files  map[string]string
		fields map[string]string
	}
	got := make(chan captured, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/forms/chromium/convert/html" {
			t.Errorf("请求路径 = %q，期望 /forms/chromium/convert/html", r.URL.Path)
		}
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			t.Errorf("解析 multipart 失败: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c := captured{files: map[string]string{}, fields: map[string]string{}}
		for _, fh := range r.MultipartForm.File["files"] {
			f, err := fh.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(f)
			_ = f.Close()
			c.files[fh.Filename] = string(b)
		}
		for k, v := range r.MultipartForm.Value {
			if len(v) > 0 {
				c.fields[k] = v[0]
			}
		}
		got <- c

		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "%PDF-1.4 fake")
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, testSecret, time.Second, time.Second)
	pdf, err := c.RenderPDF(context.Background(), "<html>正文</html>", "<html>页脚</html>")
	if err != nil {
		t.Fatalf("渲染 PDF 失败: %v", err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF-") {
		t.Errorf("返回内容不像 PDF: %q", pdf)
	}

	c1 := <-got
	if _, ok := c1.files["index.html"]; !ok {
		t.Errorf("缺少 index.html 部件；实际文件：%v", keysOf(c1.files))
	}
	if v, ok := c1.files["footer.html"]; !ok {
		t.Errorf("缺少 footer.html 部件；实际文件：%v", keysOf(c1.files))
	} else if !strings.Contains(v, "页脚") {
		t.Errorf("footer.html 内容 = %q", v)
	}

	// printBackground 必须为 true：等级色带与矩阵热力块都靠背景色
	if c1.fields["printBackground"] != "true" {
		t.Error("printBackground 应为 true（否则报告里的色块全丢了）")
	}
	if c1.fields["preferCssPageSize"] != "true" {
		t.Error("preferCssPageSize 应为 true（让纸张尺寸由模板的 CSS 决定）")
	}
	if c1.fields["marginTop"] == "" || c1.fields["marginBottom"] == "" {
		t.Error("上下页边距未设置（页脚会与正文重叠）")
	}
}

// TestRenderExcelNeedsNoUpstream Excel 不走任何外部服务。
//
// 这不是「顺便测一下」：上游挂掉时 Excel 依然可用，意味着用户在
// docgen/gotenberg 故障期间还能拿到数据。它依赖的是「Render 对 Excel
// 不碰 client」这个事实，因此这里传一个**指向不可能地址**的 client，
// Excel 仍然必须成功。
func TestRenderExcelNeedsNoUpstream(t *testing.T) {
	dead := NewClient("http://127.0.0.1:1", "http://127.0.0.1:1", testSecret,
		10*time.Millisecond, 10*time.Millisecond)

	out, err := Render(context.Background(), dead, FormatExcel, testData())
	if err != nil {
		t.Fatalf("Excel 导出不应依赖上游服务，却失败了: %v", err)
	}
	if len(out) == 0 {
		t.Error("Excel 内容为空")
	}
	if !strings.HasPrefix(string(out), "PK") {
		t.Error("xlsx 本质是 zip，应以 PK 开头")
	}
}

// TestRenderRejectsUnknownFormat 未知格式直接报错。
func TestRenderRejectsUnknownFormat(t *testing.T) {
	if _, err := ParseFormat("doc"); err == nil {
		t.Error("ParseFormat 应当拒绝未知格式")
	}
	for _, ok := range []string{"word", "excel", "pdf", "WORD", "PDF"} {
		if _, err := ParseFormat(ok); err != nil {
			t.Errorf("ParseFormat(%q) 不应报错: %v", ok, err)
		}
	}
}

// TestFormatHelpers 扩展名 / MIME / 标签三者必须自洽。
func TestFormatHelpers(t *testing.T) {
	cases := []struct {
		f     Format
		ext   string
		ct    string
		label string
	}{
		{FormatWord, "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word"},
		{FormatExcel, "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel"},
		{FormatPDF, "pdf", "application/pdf", "PDF"},
	}
	for _, c := range cases {
		if c.f.Ext() != c.ext {
			t.Errorf("%s.Ext() = %q，期望 %q", c.f, c.f.Ext(), c.ext)
		}
		if c.f.ContentType() != c.ct {
			t.Errorf("%s.ContentType() = %q，期望 %q", c.f, c.f.ContentType(), c.ct)
		}
		if c.f.Label() != c.label {
			t.Errorf("%s.Label() = %q，期望 %q", c.f, c.f.Label(), c.label)
		}
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
