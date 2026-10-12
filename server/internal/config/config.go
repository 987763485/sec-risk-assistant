// Package config 负责加载与校验运行配置。
//
// 配置来源优先级（高 → 低）：
//  1. 进程环境变量（前缀 SR_，点号替换为下划线，如 SR_DATABASE_HOST）
//  2. .env 文件（依次查找 ./.env、../.env、../../.env，**不覆盖已存在的环境变量**）
//  3. 内置默认值
//
// 关键设计：.env 的定位是「把变量放进进程环境」的本地便利手段，
// 而不是一种配置格式。这样本地开发与容器部署走的是**完全相同**的读取路径，
// 不会出现「本地正常、容器里配置读不到」这类问题。
//
// 设计原则：配置校验不通过直接拒绝启动。带残缺配置启动的故障排查成本，
// 远高于启动失败。
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// App 应用级配置
type App struct {
	Env      string `mapstructure:"env"` // dev | test | prod
	Name     string `mapstructure:"name"`
	LogLevel string `mapstructure:"log_level"` // debug | info | warn | error
}

// Server HTTP 服务配置
type Server struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	CORSOrigins     []string      `mapstructure:"cors_origins"`
	// TrustedProxies 可信反向代理网段。
	//
	// ⚠️ 必须显式配置且不能是 0.0.0.0/0。gin 默认信任所有代理，
	// 那会让 X-Forwarded-For 可被客户端随意伪造——后果是限流被绕过、
	// 审计日志里的客户端 IP 完全失真。这里默认只信任回环与私有网段，
	// 正好覆盖「本机 Nginx」与「compose 内网 Nginx」两种部署形态。
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

// Auth 认证与会话配置
type Auth struct {
	// JWTSecret 访问令牌签名密钥。HS256 的安全性完全依赖它的熵，
	// 泄露即等于任何人都能伪造任意身份。
	JWTSecret string `mapstructure:"jwt_secret"`
	// AccessTTL 访问令牌有效期。短有效期 + 刷新机制，
	// 把令牌泄露后的可利用窗口压缩到分钟级。
	AccessTTL time.Duration `mapstructure:"access_ttl"`
	// RefreshTTL 刷新令牌有效期，同时也是会话的最长空闲时长。
	RefreshTTL time.Duration `mapstructure:"refresh_ttl"`
	// CookieSecure 是否给 Cookie 加 Secure 属性。
	// 生产（HTTPS）必须为 true；开发环境走 http://localhost 时必须为 false，
	// 否则浏览器会直接丢弃 Cookie，表现为「登录后立刻又变未登录」。
	CookieSecure bool `mapstructure:"cookie_secure"`

	// MaxLoginAttempts 连续登录失败多少次后锁定账号
	MaxLoginAttempts uint32 `mapstructure:"max_login_attempts"`
	// LockDuration 账号锁定时长
	LockDuration time.Duration `mapstructure:"lock_duration"`
	// LoginRateLimit 同一来源 IP 在 LoginRateWindow 内允许的登录尝试次数。
	// 与账号锁定互补：账号锁定防「盯着一个账号猛试」，
	// 这里防「用一堆用户名轮着试」。
	LoginRateLimit  int           `mapstructure:"login_rate_limit"`
	LoginRateWindow time.Duration `mapstructure:"login_rate_window"`

	// BootstrapUsername 引导管理员登录名
	BootstrapUsername string `mapstructure:"bootstrap_username"`
	// BootstrapPassword 引导管理员初始密码。
	// 仅在系统内一个账号都没有时用于创建首个管理员，
	// 创建后立即打上「必须改密」标记。生产环境必须显式设置。
	BootstrapPassword    string `mapstructure:"bootstrap_password"`
	BootstrapDisplayName string `mapstructure:"bootstrap_display_name"`
}

// Database 数据库配置
type Database struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Name            string        `mapstructure:"name"`
	Charset         string        `mapstructure:"charset"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// DSN 生成 GORM 使用的 MySQL 连接串。
//
// multiStatements=true 是 golang-migrate 执行含多语句迁移文件所必需的；
// 业务查询一律走 GORM 预编译语句，不受其影响。
func (d Database) DSN() string {
	charset := d.Charset
	if charset == "" {
		charset = "utf8mb4"
	}
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=Local&multiStatements=true&timeout=5s",
		d.User, d.Password, d.Host, d.Port, d.Name, charset,
	)
}

// Internal 内部服务间调用配置（docgen / gotenberg 等）
//
// 两个上游各有一个超时键，值刻意不同：docgen 是纯内存的 OpenXML 拼装
// （几十毫秒级），Gotenberg 要起一个 Chromium 进程做排版（秒级起步）。
// 共用一个超时，要么把大报告误杀在 Chromium 里，要么让挂掉的 docgen
// 拖满整个 Chromium 的时长才报错。
type Internal struct {
	SharedSecret string `mapstructure:"shared_secret"`
	DocGenURL    string `mapstructure:"docgen_url"`
	// DocGenTimeout docgen 单次调用的超时（超时或 5xx 会重试一次）
	DocGenTimeout time.Duration `mapstructure:"docgen_timeout"`

	// GotenbergURL Gotenberg 服务地址（HTML → PDF）。
	// 默认指向回环：生产由 compose 内网按服务名覆盖，
	// 本地开发靠 deploy/compose.dev.yml 把它映射到回环端口。
	GotenbergURL string `mapstructure:"gotenberg_url"`
	// GotenbergTimeout Gotenberg 单次调用的超时（超时或 5xx 会重试一次）
	GotenbergTimeout time.Duration `mapstructure:"gotenberg_timeout"`
}

// Storage 上传文件存储配置。
type Storage struct {
	// UploadDir 上传文件的落盘根目录。
	// 文件与 Web 根物理隔离、绝不由任何静态文件服务直接暴露——
	// 下载必须走 API（过权限校验 + 强制 octet-stream），
	// 这是上传安全基线里「存储目录与 Web 根物理隔离」的落点。
	UploadDir string `mapstructure:"upload_dir"`
	// MaxFileBytes 单文件体积上限。
	// 与 pkg/spreadsheet.MaxFileSize 保持同一默认（10 MB），
	// 但允许按部署环境放宽或收紧而不动代码常量。
	MaxFileBytes int64 `mapstructure:"max_file_bytes"`
}

// Config 顶层配置
type Config struct {
	App      App      `mapstructure:"app"`
	Server   Server   `mapstructure:"server"`
	Database Database `mapstructure:"database"`
	Auth     Auth     `mapstructure:"auth"`
	Internal Internal `mapstructure:"internal"`
	Storage  Storage  `mapstructure:"storage"`
}

// Load 加载并校验配置。
func Load() (*Config, error) {
	// ① .env 只在进程环境里尚无该变量时生效（godotenv.Load 不覆盖已有值），
	//    因此容器 / CI 注入的真实环境变量天然拥有更高优先级。
	if path := findEnvFile(); path != "" {
		if err := godotenv.Load(path); err != nil {
			return nil, fmt.Errorf("加载 %s 失败: %w", path, err)
		}
	}

	// ② 环境变量 → 结构体。前缀 SR_ 隔离命名空间，
	//    避免与 PATH、HOME 等系统变量或同机的其他服务撞名。
	v := viper.New()
	v.SetEnvPrefix("SR")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// 每个键都必须有默认值：viper 的 AutomaticEnv 只对「已知的键」生效，
	// 没有默认值的键不会去查环境变量。
	setDefaults(v)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// findEnvFile 依次向上查找 .env，返回首个命中的路径。
func findEnvFile() string {
	for _, p := range []string{".env", "../.env", "../../.env"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// DevBootstrapPassword 开发环境默认的引导管理员密码。
//
// 单独抽成常量是为了让生产环境校验能明确拦住它：
// 「用默认密码上了生产」是这类系统最典型也最致命的部署事故。
const DevBootstrapPassword = "Admin@12345"

func setDefaults(v *viper.Viper) {
	v.SetDefault("app.env", "dev")
	v.SetDefault("app.name", "sec-risk-assistant")
	v.SetDefault("app.log_level", "info")

	// 默认只监听本机 —— 安全默认值。容器内需显式设置 SR_SERVER_HOST=0.0.0.0
	v.SetDefault("server.host", "127.0.0.1")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "30s")
	// write_timeout 必须覆盖「最慢的一条业务链路」，当前是 PDF 报告导出：
	//
	//   docgen 30s × 最多 2 次（超时或 5xx 重试一次）= 60s
	//   gotenberg 60s × 最多 2 次                    = 120s
	//
	// 取 180s 留出余量与数据库查询时间。写在 120s 的话，一次
	// 「Gotenberg 超时 → 重试 → 又超时」会把请求正好顶在 WriteTimeout 上，
	// 用户拿到的是一个**被截断的响应**而不是我们的 JSON 503——同一个故障，
	// 报错质量天差地别。
	// 配套：deploy/nginx/default.conf 的 proxy_read/send_timeout 必须比它更大。
	v.SetDefault("server.write_timeout", "180s")
	v.SetDefault("server.shutdown_timeout", "10s")
	v.SetDefault("server.cors_origins", []string{"http://localhost:5173", "http://127.0.0.1:5173"})
	// 默认只信任回环与私有网段，覆盖「本机 Nginx」与「compose 内网 Nginx」
	v.SetDefault("server.trusted_proxies", []string{
		"127.0.0.1/32", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	})

	v.SetDefault("database.host", "127.0.0.1")
	v.SetDefault("database.port", 3306)
	v.SetDefault("database.user", "secrisk")
	v.SetDefault("database.password", "")
	v.SetDefault("database.name", "sec_risk")
	v.SetDefault("database.charset", "utf8mb4")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.conn_max_lifetime", "1h")

	// dev 默认密钥仅供本机开发；生产环境由 Validate 强制要求替换
	v.SetDefault("auth.jwt_secret", "dev-only-jwt-secret-please-change-in-production")
	v.SetDefault("auth.access_ttl", "15m")
	v.SetDefault("auth.refresh_ttl", "168h")
	v.SetDefault("auth.cookie_secure", false)
	v.SetDefault("auth.max_login_attempts", 5)
	v.SetDefault("auth.lock_duration", "15m")
	v.SetDefault("auth.login_rate_limit", 20)
	v.SetDefault("auth.login_rate_window", "15m")
	v.SetDefault("auth.bootstrap_username", "admin")
	v.SetDefault("auth.bootstrap_password", DevBootstrapPassword)
	v.SetDefault("auth.bootstrap_display_name", "系统管理员")

	v.SetDefault("internal.shared_secret", "dev-only-shared-secret-please-change")
	v.SetDefault("internal.docgen_url", "http://127.0.0.1:8090")
	v.SetDefault("internal.docgen_timeout", "30s")
	v.SetDefault("internal.gotenberg_url", "http://127.0.0.1:3000")
	v.SetDefault("internal.gotenberg_timeout", "60s")

	v.SetDefault("storage.upload_dir", "./storage/uploads")
	v.SetDefault("storage.max_file_bytes", 10<<20) // 10 MB，与 spreadsheet.MaxFileSize 一致
}

// Validate 配置校验。所有问题一次性列出，避免逐个试错。
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	switch c.App.Env {
	case "dev", "test", "prod":
	default:
		add("app.env 必须是 dev/test/prod 之一，当前为 %q", c.App.Env)
	}

	switch c.App.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		add("app.log_level 必须是 debug/info/warn/error 之一，当前为 %q", c.App.LogLevel)
	}

	if c.Server.Host == "" {
		add("server.host 不能为空")
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		add("server.port 非法: %d", c.Server.Port)
	}

	if c.Database.Host == "" {
		add("database.host 不能为空")
	}
	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		add("database.port 非法: %d", c.Database.Port)
	}
	if c.Database.User == "" {
		add("database.user 不能为空")
	}
	if c.Database.Name == "" {
		add("database.name 不能为空")
	}

	// 可信代理段不能包含全网段：那等于把客户端 IP 的判定权交给请求方
	for _, p := range c.Server.TrustedProxies {
		if p == "0.0.0.0/0" || p == "::/0" {
			add("server.trusted_proxies 不得包含 %q（会导致限流可被绕过、审计 IP 失真）", p)
		}
	}

	if len(c.Auth.JWTSecret) < 32 {
		add("auth.jwt_secret 长度 %d 不足 32，HS256 的签名强度直接由密钥熵决定",
			len(c.Auth.JWTSecret))
	}
	if c.Auth.AccessTTL <= 0 {
		add("auth.access_ttl 必须为正数，当前 %s", c.Auth.AccessTTL)
	}
	if c.Auth.RefreshTTL <= c.Auth.AccessTTL {
		add("auth.refresh_ttl(%s) 必须大于 auth.access_ttl(%s)",
			c.Auth.RefreshTTL, c.Auth.AccessTTL)
	}
	if c.Auth.MaxLoginAttempts == 0 {
		add("auth.max_login_attempts 必须大于 0")
	}
	if c.Auth.LockDuration <= 0 {
		add("auth.lock_duration 必须为正数")
	}
	if c.Auth.LoginRateLimit <= 0 {
		add("auth.login_rate_limit 必须大于 0")
	}
	if c.Auth.BootstrapUsername == "" {
		add("auth.bootstrap_username 不能为空")
	}

	if c.Storage.UploadDir == "" {
		add("storage.upload_dir 不能为空")
	}
	if c.Storage.MaxFileBytes <= 0 {
		add("storage.max_file_bytes 必须为正数")
	}

	// 报告渲染的两个上游。URL 为空时按启动即失败处理，而不是等到用户
	// 点导出才报 503——「配置漏了」与「上游恰好挂了」在对用户的表现上
	// 完全一样（都是 503），但在运维上是两件事，必须在启动期分开。
	if strings.TrimSpace(c.Internal.DocGenURL) == "" {
		add("internal.docgen_url 不能为空（Word 报告依赖它）")
	}
	if strings.TrimSpace(c.Internal.GotenbergURL) == "" {
		add("internal.gotenberg_url 不能为空（PDF 报告依赖它）")
	}
	if c.Internal.DocGenTimeout <= 0 {
		add("internal.docgen_timeout 必须为正数，当前 %s", c.Internal.DocGenTimeout)
	}
	if c.Internal.GotenbergTimeout <= 0 {
		add("internal.gotenberg_timeout 必须为正数，当前 %s", c.Internal.GotenbergTimeout)
	}
	if c.Internal.SharedSecret == "" {
		add("internal.shared_secret 不能为空（docgen 用它校验调用方身份）")
	}

	// 生产环境的额外强制要求不能省
	if c.App.Env == "prod" {
		if c.Database.Password == "" {
			add("生产环境 database.password 不能为空")
		}
		if c.Server.Host == "0.0.0.0" {
			// 允许，但必须由反向代理暴露，仅作提醒
			_ = c
		}
		if len(c.Internal.SharedSecret) < 16 {
			add("生产环境 internal.shared_secret 长度不得少于 16（服务间调用鉴权）")
		}
		if len(c.Server.CORSOrigins) == 0 {
			add("生产环境 server.cors_origins 必须显式配置，不允许留空")
		}
		if !c.Auth.CookieSecure {
			add("生产环境 auth.cookie_secure 必须为 true（会话 Cookie 必须带 Secure 属性）")
		}
		if c.Auth.JWTSecret == "dev-only-jwt-secret-please-change-in-production" {
			add("生产环境 auth.jwt_secret 仍是开发默认值，请替换：openssl rand -hex 32")
		}
		if c.Auth.BootstrapPassword == "" || c.Auth.BootstrapPassword == DevBootstrapPassword {
			add("生产环境 auth.bootstrap_password 必须显式设置为强随机值（不得沿用开发默认值）")
		}
	}

	if len(errs) > 0 {
		return errors.New("配置校验失败:\n  - " + strings.Join(errs, "\n  - "))
	}
	return nil
}
