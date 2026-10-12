package intelfeed

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestIsBlockedAddrCoversLiteralForms 是本包最重要的一条测试。
//
// 它逐条列出「同一台内网主机」的不同写法。任何一条漏判都意味着
// SSRF 防护被绕过，而漏判不会让任何功能表现异常——所以必须靠枚举来守。
//
// ⚠️ 这些用例只覆盖**字面量**形式（不需要 DNS）。域名形式的绕过
// （`localhost`、`*.nip.io`）走的是解析路径，由 CheckEndpoint 里的
// 逐 IP 校验覆盖——那条路径的判定函数就是这里被测的 isBlockedAddr，
// 因此这两个测试合起来才是完整的证据。
func TestIsBlockedAddrCoversLiteralForms(t *testing.T) {
	blocked := []string{
		// 回环
		"127.0.0.1", "127.1.2.3", "127.255.255.254",
		"::1",
		// IPv4-mapped：最常见的绕过写法，必须先 Unmap 才判得出来
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.5",
		// 私有段
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.1.1",
		// 云元数据（169.254.169.254 是 AWS/GCP/阿里云的凭据端点）
		"169.254.169.254",
		// CGNAT
		"100.64.0.1", "100.127.255.255",
		// 「本网络」
		"0.0.0.0",
		// 组播与保留
		"224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
		// IPv6 内网与特殊段
		"fc00::1", "fd12:3456::1", "fe80::1", "ff02::1",
		"::",
		// NAT64 / 6to4：IPv4 内网地址可以嵌在 IPv6 里
		"64:ff9b::7f00:1",
		"2002:7f00:0001::1",
		// 文档/测试段
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1",
	}

	for _, raw := range blocked {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("测试用例 %q 不是合法 IP 字面量，请修正用例本身: %v", raw, err)
		}
		if !isBlockedAddr(addr) {
			t.Errorf("%s 应当被判定为受限地址，但被放行了（SSRF 防护被绕过）", raw)
		}
	}
}

// TestIsBlockedAddrAllowsPublicAddresses 反向对照：
// 公网地址必须放行，否则这个功能一上线就谁也拉不到数据。
//
// 没有这条反向断言，「全部拒绝」也能让上面那条测试通过——
// 那是一个看起来完美、实际不可用的实现。
func TestIsBlockedAddrAllowsPublicAddresses(t *testing.T) {
	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"104.16.132.229", // services.nvd.nist.gov 所在的公网段（Cloudflare）
		"2606:4700:4700::1111",
	}
	for _, raw := range allowed {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("测试用例 %q 不是合法 IP 字面量: %v", raw, err)
		}
		if isBlockedAddr(addr) {
			t.Errorf("%s 是公网地址，却被判为受限——这会让所有情报源都不可用", raw)
		}
	}
}

// TestIsBlockedAddrRejectsInvalid 无效地址按拒绝处理。
//
// 判据是「不知道它是什么」不是放行的理由：解析不出地址的输入
// 出现在出站路径上，本身就说明上游给了一个我们无法理解的目标。
func TestIsBlockedAddrRejectsInvalid(t *testing.T) {
	if !isBlockedAddr(netip.Addr{}) {
		t.Error("零值地址应当被拒绝")
	}
}

// TestCheckEndpointRejectsDangerousForms 校验第一层预检的各类拒绝分支。
func TestCheckEndpointRejectsDangerousForms(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name   string
		in     string
		reason string
	}{
		{"非 http(s) 协议", "file:///etc/passwd", "只允许 http 或 https"},
		{"gopher 协议", "gopher://127.0.0.1:6379/_INFO", "只允许 http 或 https"},
		{"内嵌凭据", "https://user:pass@example.com/", "不得内嵌用户名口令"},
		{"缺少主机名", "http:///path", "缺少主机名"},
		{"回环字面量", "http://127.0.0.1:8080/", "内网或保留地址"},
		{"IPv6 回环字面量", "http://[::1]:8080/", "内网或保留地址"},
		{"IPv4-mapped 回环", "http://[::ffff:127.0.0.1]/", "内网或保留地址"},
		{"云元数据地址", "http://169.254.169.254/latest/meta-data/", "内网或保留地址"},
		{"私有段", "http://10.1.2.3/api", "内网或保留地址"},
		{"ULA 段", "http://[fd00::1]/api", "内网或保留地址"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckEndpoint(ctx, tc.in)
			if err == nil {
				t.Fatalf("%q 应当被拒绝，但通过了校验", tc.in)
			}
			if !errors.Is(err, ErrEndpointBlocked) {
				t.Fatalf("错误应当包装 ErrEndpointBlocked，实际为 %v", err)
			}
			// 错误信息必须能指导用户改配置，而不是一句含糊的拒绝
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("错误信息应包含 %q 以便用户知道该改什么，实际为 %q",
					tc.reason, err.Error())
			}
		})
	}
}

// TestCheckEndpointAcceptsAndNormalizes 合法地址被接受并归一化。
//
// ⚠️ 这里用 IP 字面量而不是域名（如 services.nvd.nist.gov），是刻意的：
// 域名解析结果取决于**运行环境**——企业内网 DNS、沙箱代理、运营商劫持
// 都可能把一个公网域名指到私有或保留网段。用域名会让这条测试在
// 某些环境下莫名变红，而失败原因（本机 DNS 特殊）与它要断言的东西
// （尾部斜杠与空白是否被去掉）毫不相干。
// 域名路径的判定由 TestIsBlockedAddrCoversLiteralForms 覆盖的
// isBlockedAddr 承担——CheckEndpoint 对域名做的事就是「解析后逐个调它」。
func TestCheckEndpointAcceptsAndNormalizes(t *testing.T) {
	ctx := context.Background()

	got, err := CheckEndpoint(ctx, "  https://1.1.1.1/  ")
	if err != nil {
		t.Fatalf("公网地址应当被接受，实际报错: %v", err)
	}
	if got != "https://1.1.1.1" {
		t.Errorf("尾部斜杠与空白应被去掉，实际得到 %q", got)
	}
}

// TestCheckEndpointAllowsEmpty 空串是合法输入。
//
// local 这类适配器不需要上游地址；若把空串也判为「被拦截」，
// service 层就无法区分「没配地址」与「配了个危险地址」，
// 只能对 local 类型跳过整段校验——那样 SSRF 校验就出现了例外分支。
func TestCheckEndpointAllowsEmpty(t *testing.T) {
	got, err := CheckEndpoint(context.Background(), "   ")
	if err != nil {
		t.Fatalf("空地址不应报错: %v", err)
	}
	if got != "" {
		t.Errorf("空地址应归一化为空串，实际为 %q", got)
	}
}

// TestNormalizeSeverity 归一化上游的严重度文案。
func TestNormalizeSeverity(t *testing.T) {
	score := 7.5
	low := 3.1

	cases := []struct {
		raw    string
		score  *float64
		expect string
	}{
		{"CRITICAL", nil, SeverityCritical},
		{"critical", nil, SeverityCritical},
		{"High", nil, SeverityHigh},
		{"  medium  ", nil, SeverityMedium},
		{"Moderate", nil, SeverityMedium},
		{"严重", nil, SeverityCritical},
		{"高", nil, SeverityHigh},
		// 文案无法识别时退到分数推导
		{"", &score, SeverityHigh},
		{"我们没见过的写法", &score, SeverityHigh},
		{"", &low, SeverityLow},
		// 两者都没有才 unknown
		{"", nil, SeverityUnknown},
		{"未知", nil, SeverityUnknown},
	}

	for _, tc := range cases {
		if got := NormalizeSeverity(tc.raw, tc.score); got != tc.expect {
			t.Errorf("NormalizeSeverity(%q, %v) = %q，期望 %q", tc.raw, tc.score, got, tc.expect)
		}
	}
}

// TestSeverityFromCVSS 分档边界都取在 CVSS v3.1 规范的定义上。
func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score  float64
		expect string
	}{
		{10.0, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0, SeverityUnknown},
	}
	for _, tc := range cases {
		if got := SeverityFromCVSS(tc.score); got != tc.expect {
			t.Errorf("SeverityFromCVSS(%v) = %q，期望 %q", tc.score, got, tc.expect)
		}
	}
}

// TestClampTimeout 超时收敛到允许区间。
func TestClampTimeout(t *testing.T) {
	cases := []struct {
		in     time.Duration
		expect time.Duration
	}{
		{0, DefaultTimeout},
		{-1 * time.Second, DefaultTimeout},
		{10 * time.Millisecond, MinTimeout},
		{5 * time.Second, 5 * time.Second},
		{10 * time.Minute, MaxTimeout},
	}
	for _, tc := range cases {
		if got := ClampTimeout(tc.in); got != tc.expect {
			t.Errorf("ClampTimeout(%v) = %v，期望 %v", tc.in, got, tc.expect)
		}
	}
}

// TestRegistryRejectsUnknownType 未知类型必须报错，而不是回退到某个默认适配器。
//
// 回退是危险设计：把类型字段写错（比如 `nvd-api`）会让系统静默地
// 用一个「默认」适配器去请求，而用户以为自己配的是另一个源。
func TestRegistryRejectsUnknownType(t *testing.T) {
	if _, err := New("nvd-api"); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("未知类型应当返回 ErrUnknownType，实际为 %v", err)
	}
	for _, name := range Supported() {
		f, err := New(name)
		if err != nil {
			t.Fatalf("受支持的类型 %q 应当能构建: %v", name, err)
		}
		if f.Type() != name {
			t.Errorf("适配器 %q 的 Type() 返回 %q，两者必须一致", name, f.Type())
		}
	}
}

// TestLocalFeedFetch 离线驱动的命中与未命中语义。
func TestLocalFeedFetch(t *testing.T) {
	f, err := New(TypeLocal)
	if err != nil {
		t.Fatalf("构建 local 适配器失败: %v", err)
	}
	ctx := context.Background()

	t.Run("命中", func(t *testing.T) {
		rec, err := f.Fetch(ctx, Request{CVEID: "cve-2021-44228"})
		if err != nil {
			t.Fatalf("应当命中内置数据: %v", err)
		}
		// CVE 编号统一大写：库里存小写会让「同一漏洞的同一个 CVE」
		// 因大小写不同被唯一键当成两条
		if rec.CVEID != "CVE-2021-44228" {
			t.Errorf("CVE 编号应归一化为大写，实际为 %q", rec.CVEID)
		}
		if rec.Severity != SeverityCritical {
			t.Errorf("严重度应为 critical，实际为 %q", rec.Severity)
		}
		if rec.CVSSScore == nil || *rec.CVSSScore != 10.0 {
			t.Errorf("CVSS 分数应为 10.0，实际为 %v", rec.CVSSScore)
		}
		if len(rec.References) == 0 {
			t.Error("参考链接不应为空")
		}
		if len(rec.Raw) == 0 {
			t.Error("raw_json 的内容不应为空——界面显示的必须可追溯到上游片段")
		}
	})

	t.Run("未命中", func(t *testing.T) {
		_, err := f.Fetch(ctx, Request{CVEID: "CVE-1999-0001"})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("未收录的 CVE 应返回 ErrNotFound，实际为 %v", err)
		}
	})

	t.Run("空编号", func(t *testing.T) {
		if _, err := f.Fetch(ctx, Request{CVEID: "  "}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("空 CVE 编号应返回 ErrNotFound，实际为 %v", err)
		}
	})

	t.Run("数据不被调用方污染", func(t *testing.T) {
		first, _ := f.Fetch(ctx, Request{CVEID: "CVE-2017-5638"})
		first.References[0] = "被改坏了"
		second, _ := f.Fetch(ctx, Request{CVEID: "CVE-2017-5638"})
		if second.References[0] == "被改坏了" {
			t.Error("每次拉取必须返回独立的切片，否则一次误改会污染全局数据")
		}
	})
}

// TestGuardedClientBlocksAtDialTime 覆盖**第二层**出站防护：`Dialer.Control`。
//
// 这一层防的是 DNS rebinding / TOCTOU —— 预检（CheckEndpoint）与真正 connect
// 之间，DNS 可以给出不同的答案，因此必须在**连接建立之前**复核实际要连的
// sockaddr，而不是重新解析一次域名。
//
// 本测试不去构造一个恶意 DNS（那要改 hosts 或起 DNS 服务器，在 CI 里不可靠），
// 而是**直接调用客户端**去连一个受限字面量地址 —— 这条路径上
// `CheckEndpoint` 根本不参与，于是错误只有两种可能：
//
//	· 连接被 Control 拒绝 → errors.Is(err, ErrEndpointBlocked) 成立；
//	· 连接被内核拒绝     → `connection refused`，说明 Control 没生效。
//
// ⚠️ 这个区分是整条测试的关键：只断言「报错了」是不够的 ——
// 端口没人监听同样会报错，那样即使 Control 整段被删掉也测不出来。
func TestGuardedClientBlocksAtDialTime(t *testing.T) {
	// 超时给足：这里要区分的是「谁拒绝了连接」，不是快慢
	client := newGuardedClient(3 * time.Second)

	// 本机 9 号端口上刻意不放任何服务：Control 生效时连接根本不会发起
	resp, err := client.Get("http://127.0.0.1:9/")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("连接受限地址应当失败")
	}
	if !errors.Is(err, ErrEndpointBlocked) {
		t.Fatalf("应当由 Dialer.Control 在 connect 之前拒绝（ErrEndpointBlocked），实际为 %v；\n"+
			"若为 connection refused，说明 Control 未生效 —— 那时 DNS rebinding 可以直接打到内网", err)
	}
}

// TestGuardedClientDisablesRedirectAndProxy 结构断言。
//
// 这两条约束**没有**可靠的行为断言：「不跟随重定向」需要一个公网可达的
// 重定向端点（所有本地测试服务都在 127.0.0.1 上，会被 Control 直接拒掉），
// 「不走代理」需要一个真的代理。因此退而断言客户端的构造结果 ——
// 它能防住的是「有人把这两行删掉」，防不住「有人换一种写法绕过」。
//
// ⚠️ 它的价值随代码演进下降：若将来改用自定义 RoundTripper，
// 本测试会静默失效（`Proxy` 字段还在，但已不被使用）。
// 这属于「结构可验证、行为不可离线验证」的典型，记在文档里比假装测到了好。
func TestGuardedClientDisablesRedirectAndProxy(t *testing.T) {
	client := newGuardedClient(time.Second)

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport 应是 *http.Transport，实际为 %T", client.Transport)
	}
	if tr.Proxy != nil {
		t.Error("Proxy 必须置零：HTTP_PROXY 会让请求经代理发出，而代理侧的解析与连接不受本包约束")
	}
	if tr.DialContext == nil {
		t.Error("DialContext 必须指定为带 Control 的 dialer，否则第二层防护整段失效")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("必须禁跟随重定向（返回 ErrUseLastResponse），实际为 %v", err)
	}
}

// TestDefaultBaseURL 只有需要网络的适配器有默认地址。
func TestDefaultBaseURL(t *testing.T) {
	if DefaultBaseURL(TypeNVD) == "" {
		t.Error("nvd 应当有默认地址，否则界面预填不出来")
	}
	if DefaultBaseURL(TypeLocal) != "" {
		t.Error("local 不访问网络，默认地址必须为空——给它一个地址会让人以为它真的会去请求")
	}
	if !RequiresCredential(TypeNVD) {
		t.Error("nvd 需要凭据（无 Key 会被严格限流）")
	}
	if RequiresCredential(TypeLocal) {
		t.Error("local 不访问网络，不应要求凭据")
	}
}
