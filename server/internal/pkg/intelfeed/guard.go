package intelfeed

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// blockedPrefixes 禁止出站的地址段。
//
// ▍这份清单的判据
//
// 不是「哪些看起来危险」，而是「**这台服务器能访问而外部用户访问不到的**」。
// SSRF 的价值恰恰来自这种不对称：攻击者用自己的机器连不上 10.0.0.5，
// 但让这台服务器去连就能连上，而且带着服务器的网络身份与信任关系。
// 因此回环、私有段、链路本地、CGNAT、云元数据地址全部在列。
//
// ▍为什么 IPv6 段一个都不能少
//
// 只在 IPv4 上做过滤是最常见的漏法。`http://[::1]:8080/` 与
// `http://[fd00::1]/` 都能直达内网，而很多实现只看 `net.ParseIP().To4()`，
// 对纯 IPv6 返回 nil 就当「不是内网」放过去了。
// IPv4-mapped（`::ffff:127.0.0.1`）由 isBlockedAddr 里的 Unmap 统一还原。
var blockedPrefixes = []netip.Prefix{
	// —— IPv4 ——
	netip.MustParsePrefix("0.0.0.0/8"),       // 「本网络」：Linux 上 0.0.0.0 会被当作本机
	netip.MustParsePrefix("10.0.0.0/8"),      // 私有
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT（运营商级 NAT，云上常被当作内网互访段）
	netip.MustParsePrefix("127.0.0.0/8"),     // 回环
	netip.MustParsePrefix("169.254.0.0/16"),  // 链路本地：含 169.254.169.254（云元数据）
	netip.MustParsePrefix("172.16.0.0/12"),   // 私有
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF 协议分配
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 中继
	netip.MustParsePrefix("192.168.0.0/16"),  // 私有
	netip.MustParsePrefix("198.18.0.0/15"),   // 基准测试网段
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // 组播
	netip.MustParsePrefix("240.0.0.0/4"),     // 保留（含 255.255.255.255）

	// —— IPv6 ——
	netip.MustParsePrefix("::/128"),       // 未指定地址
	netip.MustParsePrefix("::1/128"),      // 回环
	netip.MustParsePrefix("fc00::/7"),     // 唯一本地地址（ULA，等价于 IPv4 私有段）
	netip.MustParsePrefix("fe80::/10"),    // 链路本地
	netip.MustParsePrefix("ff00::/8"),     // 组播
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64：可把 IPv4 内网地址嵌进来
	netip.MustParsePrefix("2002::/16"),    // 6to4：同上，IPv4 地址嵌在 IPv6 里
}

// isBlockedAddr 判断一个已解析的地址是否属于禁止出站的段。
//
// ⚠️ 先 Unmap 再判：`::ffff:127.0.0.1` 是一个合法的、能连到本机回环的
// IPv6 写法。若不还原成 IPv4，它不会命中任何 IPv4 段，
// 会被当成「一个普通的公网 IPv6」放过去。
func isBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		// 解析不出地址的输入一律拒绝——「不知道它是什么」不是放行的理由
		return true
	}
	a := addr.Unmap()
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// errEndpointBlocked 由 Dialer.Control 返回的哨兵错误。
//
// 单独定义一个内部哨兵而不是直接返回 ErrEndpointBlocked，
// 是为了在错误链上区分「第一层预检拒绝了」与「连接时拒绝了」——
// 两者的处置不同：前者是用户配错了地址（400 引导他改），
// 后者是 DNS 在两次解析之间变了（属于可疑行为，要记日志）。
var errEndpointBlocked = fmt.Errorf("%w（连接阶段复核）", ErrEndpointBlocked)

// CheckEndpoint 校验并归一化一个**用户可控**的上游基址。
//
// 返回归一化后的地址（去掉尾部斜杠）供后续拼接路径。
// 拒绝时返回包装了 ErrEndpointBlocked 的错误，其 message 面向用户，
// 必须能指导他改配置（「只允许 http/https」「不允许指向内网地址」），
// 而不是一句「连接被拒绝」让他去查网络。
//
// ⚠️ 它是**第一层**防护，不能单独使用：域名解析在这里发生一次，
// 真正 connect 时会发生第二次（甚至第 N 次），两次之间 DNS 可以变。
// 必须与 newGuardedClient 的 Control 一起用。
func CheckEndpoint(ctx context.Context, rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		// 空串是合法输入：local 这类适配器不需要上游地址。
		// 调用方（service）负责判断「该类型是否要求非空」。
		return "", nil
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w：地址无法解析", ErrEndpointBlocked)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		// 拦掉 file:// gopher:// dict:// 之类：它们绕开 HTTP 语义，
		// 却能读本地文件或与任意 TCP 服务对话。
		return "", fmt.Errorf("%w：只允许 http 或 https，当前为 %q", ErrEndpointBlocked, u.Scheme)
	}
	if u.User != nil {
		// `http://user:pass@host/` 这种写法会把凭据写进 URL，
		// 而 URL 会出现在错误信息与访问日志里。凭据有专门的承载方式
		// （credential_env），这里一律拒绝。
		return "", fmt.Errorf("%w：上游地址不得内嵌用户名口令，请改用凭据环境变量", ErrEndpointBlocked)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("%w：地址缺少主机名", ErrEndpointBlocked)
	}

	// 字面量 IP 与域名走同一条判定路径：先得到 IP 集合，再逐个校验。
	addrs, err := resolveHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("%w：主机名 %q 无法解析", ErrEndpointBlocked, host)
	}
	for _, a := range addrs {
		if isBlockedAddr(a) {
			return "", fmt.Errorf(
				"%w：主机 %q 解析到 %s，属于内网或保留地址。情报源必须是外部公网地址",
				ErrEndpointBlocked, host, a)
		}
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("%w：主机名 %q 没有解析出任何地址", ErrEndpointBlocked, host)
	}

	return strings.TrimRight(trimmed, "/"), nil
}

// resolveHost 得到主机名对应的全部 IP。
//
// 只取第一个是不够的：一个域名可以同时解析出公网 A 记录与内网 AAAA 记录，
// 后者会被连接时选中，于是「只检查第一个」的实现在这里失守。
func resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	// 解析超时收敛：DNS 卡住时不应该让整个拉取请求无限等下去
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// newGuardedClient 构造一个出站目标受限的 HTTP 客户端。
//
// 三个约束各自对应一类绕过手法：
//
//  1. **Dialer.Control 复核实际连接的 IP** —— 防 DNS rebinding / TOCTOU。
//     预检与 connect 之间的时间差足够让一个恶意 DNS 服务器先返回公网地址
//     通过检查、再返回 127.0.0.1 完成连接。Control 在 connect(2) 之前
//     拿到的是**真正要连的那个 sockaddr**，不受 DNS 影响。
//
//  2. **禁止跟随重定向** —— 一个位于公网的善意地址可以 302 到
//     http://169.254.169.254/。跟随重定向等于把第一层的全部判定作废。
//     NVD API 不重定向，因此这个约束没有实际代价。
//
//  3. **不设 Proxy** —— 环境变量 HTTP_PROXY 会让请求经由代理发出，
//     而代理侧的解析与连接完全在我们看不到的地方发生。
//     置零而不是依赖「没设这个变量」：部署环境的变量不由我们决定。
func newGuardedClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errEndpointBlocked
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return errEndpointBlocked
			}
			if isBlockedAddr(addr) {
				return errEndpointBlocked
			}
			return nil
		},
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			Proxy:                 nil,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			// 上游不可能复用同一条连接（每次都是一个独立请求），
			// 关掉连接池也就关掉了「池里那条连接当时连的是谁」这类隐性状态
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
