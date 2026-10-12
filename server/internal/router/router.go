// Package router 组装路由与中间件链。
package router

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/handler"
	"secrisk/server/internal/middleware"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/filestore"
	"secrisk/server/internal/report"
	"secrisk/server/internal/repository"
	"secrisk/server/internal/service"
	"secrisk/server/internal/version"
)

// Deps 路由装配所需的依赖。
type Deps struct {
	Config       *config.Config
	Repo         *repository.Repository
	Logger       *slog.Logger
	Tokens       *auth.TokenManager
	LoginLimiter *middleware.RateLimiter
}

// PublicRoute 公开路由清单：无需认证即可访问的端点。
//
// 这份清单是**唯一**的公开边界声明，并由 TestPublicRouteWhitelistIsAccurate
// 强制与实际路由表对齐——新增公开端点必须显式登记，
// 杜绝「不小心把内部接口暴露出去」这类事故。
var PublicRoute = []string{
	"GET /api/health",
	"GET /api/version",
	"GET /api/auth/csrf",
	"POST /api/auth/login",
	"POST /api/auth/refresh",
	"POST /api/auth/logout",
	"GET /healthz",
}

// IsPublicRoute 判断路由是否属于公开清单。
func IsPublicRoute(method, path string) bool {
	for _, r := range PublicRoute {
		if r == method+" "+path {
			return true
		}
	}
	return false
}

// New 构建 gin.Engine。
//
// 中间件顺序有讲究，按此顺序不得随意调整：
//
//	engine: RequestID → Recovery → AccessLog → SecurityHeaders → CORS
//	/api  : CSRF → Audit
//	受保护: Authn → RequirePasswordChanged → RBAC
//
// 几个容易踩的点：
//   - RequestID 必须最靠前，否则后续中间件的日志里拿不到 request_id
//   - Recovery 必须在 AccessLog 之前，才能让 panic 也产出访问日志
//   - Audit 必须排在 Authn **之前**注册：它在 c.Next() 返回后才读审计标注，
//     此时 Authn 已把认证主体写进上下文，才拿得到操作人
//   - CSRF 必须在 Authn 之前：跨站请求的令牌校验不应消耗数据库查询
//
// New 组装路由。返回 error 的原因只有一个：上传存储目录不可用属于
// 启动期配置错误，按项目原则「带残缺配置启动不如不启动」拒绝返回引擎。
func New(deps Deps, db *gorm.DB) (*gin.Engine, error) {
	cfg, logger, repo := deps.Config, deps.Logger, deps.Repo
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.App.Env == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// 可信代理必须显式配置。gin 的默认值是「信任所有代理」，
	// 那会让 X-Forwarded-For 可被客户端伪造，进而绕过限流、污染审计 IP。
	if err := r.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
		logger.Warn("可信代理配置非法，退化为不信任任何代理（ClientIP 取直连地址）",
			"err", err, "trusted_proxies", cfg.Server.TrustedProxies)
		_ = r.SetTrustedProxies(nil)
	}

	r.Use(
		middleware.RequestID(),
		middleware.Recovery(logger),
		middleware.AccessLog(logger),
		middleware.SecurityHeaders(),
		middleware.CORS(cfg.Server.CORSOrigins),
	)

	// 404 也返回统一 JSON 结构，避免前端拿到 gin 默认的纯文本
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"code":       errcode.CodeNotFound,
			"message":    "接口不存在",
			"path":       c.Request.URL.Path,
			"request_id": middleware.GetRequestID(c),
		})
	})

	healthHandler := handler.NewHealth(cfg, db)

	// 容器 healthcheck 专用：不含数据库依赖
	r.GET("/healthz", healthHandler.Live)

	// 组装业务依赖
	base := handler.Base{Logger: logger}
	authSvc := service.NewAuthService(cfg, repo, deps.Tokens, logger)
	userSvc := service.NewUserService(cfg, repo, logger)

	// 资产组服务先建，资产服务依赖它做「按分组筛选要展开子树」。
	// 依赖方向是单向的（资产 → 资产组），两者都不反向依赖资产，
	// 因此不存在循环。
	dictionarySvc := service.NewDictionaryService(cfg, repo, logger)
	assetGroupSvc := service.NewAssetGroupService(cfg, repo, logger)
	assetSvc := service.NewAssetService(cfg, repo, assetGroupSvc, logger)

	// 文件存储先于文件服务构建：存储失败是启动期配置错误，直接拒绝启动
	// 比等第一个上传请求才失败更好排查。
	fileStore, err := filestore.New(cfg.Storage.UploadDir, cfg.Storage.MaxFileBytes)
	if err != nil {
		return nil, fmt.Errorf("初始化上传存储失败: %w", err)
	}
	fileSvc := service.NewFileService(cfg, repo, fileStore, logger)
	vulnSvc := service.NewVulnService(cfg, repo, logger)

	// 风险配置服务先于评估服务构建：评估引擎取配置只有这一条路径
	// （试算用「当前配置 + 可选覆盖」，计算用「快照」），不留第二种读法。
	riskCfgSvc := service.NewRiskConfigService(repo, logger)
	assessSvc := service.NewAssessmentService(repo, riskCfgSvc, logger)

	// 报告渲染客户端（P5）。两个上游地址都允许在启动时不可达：
	// 本地开发时 docgen 与 Gotenberg 很常见地没起来，而此时拒绝启动
	// 会让「只想调一下评估接口」的人也被挡住。Word / PDF 导出会各自
	// 返回 503，Excel 导出完全不依赖上游、照常可用。
	reportClient := report.NewClient(
		cfg.Internal.DocGenURL,
		cfg.Internal.GotenbergURL,
		cfg.Internal.SharedSecret,
		cfg.Internal.DocGenTimeout,
		cfg.Internal.GotenbergTimeout,
	)
	reportSvc := service.NewReportService(repo, assessSvc, reportClient, logger)

	// 整改跟踪与仪表盘（P6）。两个服务各自持有 time.Now 注入点，
	// 但它们必须在**同一次请求内**看到同一个「今天」——仪表盘上的
	// 「逾期 N 条」与整改列表页 `?overdue=true` 筛出来的条数是同一个数，
	// 各自取时刻会在跨零点时对不上（见 service/dashboard.go）。
	// 当前实现里两者都退化为 time.Now，差异只在测试中被注入。
	remediationSvc := service.NewRemediationService(repo, logger)
	dashboardSvc := service.NewDashboardService(repo, logger)

	authHandler := handler.NewAuthHandler(base, authSvc)
	userHandler := handler.NewUserHandler(base, userSvc)
	auditHandler := handler.NewAuditHandler(base, repo)
	dictionaryHandler := handler.NewDictionaryHandler(base, dictionarySvc)
	assetGroupHandler := handler.NewAssetGroupHandler(base, assetGroupSvc)
	assetHandler := handler.NewAssetHandler(base, assetSvc, assetGroupSvc)
	assetImportHandler := handler.NewAssetImportHandler(base, assetSvc)
	fileHandler := handler.NewFileHandler(base, fileSvc)
	parseHandler := handler.NewParseHandler(base, fileSvc)
	vulnHandler := handler.NewVulnHandler(base, vulnSvc)
	assessHandler := handler.NewAssessmentHandler(base, assessSvc)
	sysCfgHandler := handler.NewSystemConfigHandler(base, riskCfgSvc)
	reportHandler := handler.NewReportHandler(base, reportSvc)
	remediationHandler := handler.NewRemediationHandler(base, remediationSvc)
	dashboardHandler := handler.NewDashboardHandler(base, dashboardSvc)

	guard := middleware.NewGuard(logger)

	api := r.Group("/api")

	// ── 全组生效：CSRF 与审计 ────────────────────────────────────────────
	api.Use(middleware.CSRF(middleware.CSRFConfig{
		TrustedOrigins: cfg.Server.CORSOrigins,
	}))

	// 认证事件（登录 / 刷新 / 登出 / 改密）由 service 层自行记录，
	// 因为失败路径同样需要留痕，而失败请求不会走到「业务成功」的审计分支。
	api.Use(middleware.Audit(repo.Audit, logger,
		"/api/auth/login",
		"/api/auth/refresh",
		"/api/auth/logout",
		"/api/auth/password",
	))

	// ── 公开端点 ────────────────────────────────────────────────────────
	api.GET("/health", healthHandler.Ready)
	api.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service":    cfg.App.Name,
			"version":    version.Version,
			"commit":     version.Commit,
			"build_time": version.BuildTime,
			"env":        cfg.App.Env,
		})
	})

	// ── 认证 ────────────────────────────────────────────────────────────
	authGroup := api.Group("/auth")
	{
		authGroup.GET("/csrf", authHandler.CSRF)

		// 登录是唯一需要 IP 限流保护的公开写接口：
		// 账号锁定防「盯着一个账号猛试」，这里防「换着用户名轮着试」
		authGroup.POST("/login",
			middleware.RateLimit(deps.LoginLimiter, logger),
			authHandler.Login)

		authGroup.POST("/refresh", authHandler.Refresh)

		// 登出使用可选认证：访问令牌过期时也必须能退得出去
		authGroup.POST("/logout",
			middleware.OptionalAuthn(deps.Tokens, authSvc),
			authHandler.Logout)

		authed := authGroup.Group("")
		authed.Use(
			middleware.Authn(deps.Tokens, authSvc, logger),
			middleware.RequirePasswordChanged(),
		)
		{
			authed.GET("/me", authHandler.Me)
			authed.PATCH("/password", authHandler.ChangePassword)
		}
	}

	// ── 业务端点（需认证 + 权限）────────────────────────────────────────
	secured := api.Group("")
	secured.Use(
		middleware.Authn(deps.Tokens, authSvc, logger),
		middleware.RequirePasswordChanged(),
	)
	{
		users := secured.Group("/users")
		{
			users.GET("", guard.RequirePermission(auth.PermUserRead), userHandler.List)
			users.POST("", guard.RequirePermission(auth.PermUserWrite), userHandler.Create)
			users.GET("/:id", guard.RequirePermission(auth.PermUserRead), userHandler.Get)
			users.PATCH("/:id", guard.RequirePermission(auth.PermUserWrite), userHandler.Update)
			users.POST("/:id/reset-password",
				guard.RequirePermission(auth.PermUserWrite), userHandler.ResetPassword)
			users.POST("/:id/unlock",
				guard.RequirePermission(auth.PermUserWrite), userHandler.Unlock)
		}

		// 角色字典：能看用户的人一般也需要看角色（用于分配界面），
		// 因此 user:read 与 role:read 二者取其一即可
		secured.GET("/roles",
			guard.RequirePermission(auth.PermRoleRead, auth.PermUserRead), userHandler.Roles)

		secured.GET("/audit-logs", guard.RequirePermission(auth.PermAuditRead), auditHandler.List)

		// ── 业务字典（P2）──────────────────────────────────────────────
		//
		// 读接口同时接受 dictionary:read 与 asset:read：填资产表单时要从这里
		// 拉「启用中的资产类型」，而评估员/审计员都可能只有 asset:read。
		// 与 /roles 的处理同理（能看用户的人也需要看角色）。写接口则严格
		// 只认 dictionary:write —— 改字典会影响所有资产的分类口径。
		secured.GET("/dictionaries",
			guard.RequirePermission(auth.PermDictRead, auth.PermAssetRead),
			dictionaryHandler.List)
		secured.POST("/dictionaries",
			guard.RequirePermission(auth.PermDictWrite), dictionaryHandler.Create)
		secured.PATCH("/dictionaries/:id",
			guard.RequirePermission(auth.PermDictWrite), dictionaryHandler.Update)
		secured.DELETE("/dictionaries/:id",
			guard.RequirePermission(auth.PermDictWrite), dictionaryHandler.Delete)

		// ── 资产分组（P2）──────────────────────────────────────────────
		//
		// 分组整个挂在 asset 权限下：它没有独立的管理场景，只是资产的
		// 组织方式；单开一对权限码只会让角色配置页面多出两个没人会改的开关。
		groups := secured.Group("/asset-groups")
		{
			groups.GET("", guard.RequirePermission(auth.PermAssetRead), assetGroupHandler.Tree)
			groups.POST("", guard.RequirePermission(auth.PermAssetWrite), assetGroupHandler.Create)
			groups.PATCH("/:id",
				guard.RequirePermission(auth.PermAssetWrite), assetGroupHandler.Update)
			// 移动是独立端点而不是 PATCH 里的一个字段：混在一起的话，
			// 「移到根」与「不移动」在 JSON 里都是 parent_id 缺失。
			groups.POST("/:id/move",
				guard.RequirePermission(auth.PermAssetWrite), assetGroupHandler.Move)
			groups.DELETE("/:id",
				guard.RequirePermission(auth.PermAssetWrite), assetGroupHandler.Delete)
		}

		// ── 资产台账与批量导入（P2）────────────────────────────────────
		assets := secured.Group("/assets")
		{
			// 注意路由注册顺序无关紧要（gin 的树能区分静态段与参数段），
			// 但阅读顺序上把 import 放在 :id 之前更有助于确认两者不冲突。
			assets.GET("/import/template",
				guard.RequirePermission(auth.PermAssetWrite), assetImportHandler.Template)
			assets.POST("/import/preview",
				guard.RequirePermission(auth.PermAssetWrite), assetImportHandler.Preview)
			assets.POST("/import/commit",
				guard.RequirePermission(auth.PermAssetWrite), assetImportHandler.Commit)

			assets.GET("", guard.RequirePermission(auth.PermAssetRead), assetHandler.List)
			assets.POST("", guard.RequirePermission(auth.PermAssetWrite), assetHandler.Create)
			assets.GET("/:id", guard.RequirePermission(auth.PermAssetRead), assetHandler.Get)
			assets.PATCH("/:id",
				guard.RequirePermission(auth.PermAssetWrite), assetHandler.Update)
			assets.DELETE("/:id",
				guard.RequirePermission(auth.PermAssetWrite), assetHandler.Delete)
		}

		// ── 扫描文件与解析（P3）────────────────────────────────────
		//
		// 文件挂在 file 权限下；解析的两个端点一并挂 file:write——
		// 「解析入库」写的是漏洞，但动作的发起对象是文件，按文件授权
		// 与前端交互（文件列表页里发起解析）一致。
		// 漏洞清单另有一组 vulnerability 权限（见下）。
		files := secured.Group("/files")
		{
			files.POST("/upload",
				guard.RequirePermission(auth.PermFileWrite), fileHandler.Upload)
			files.GET("", guard.RequirePermission(auth.PermFileRead), fileHandler.List)
			files.GET("/:id", guard.RequirePermission(auth.PermFileRead), fileHandler.Get)
			files.GET("/:id/download",
				guard.RequirePermission(auth.PermFileRead), fileHandler.Download)
			files.DELETE("/:id",
				guard.RequirePermission(auth.PermFileWrite), fileHandler.Delete)
		}

		parse := secured.Group("/parser")
		{
			parse.GET("/template",
				guard.RequirePermission(auth.PermFileWrite), parseHandler.Template)
			parse.POST("/preview",
				guard.RequirePermission(auth.PermFileWrite), parseHandler.Preview)
			parse.POST("/commit",
				guard.RequirePermission(auth.PermFileWrite), parseHandler.Commit)
		}

		// ── 漏洞清单（P3）──────────────────────────────────────────
		//
		// 挂 vulnerability 权限：手工录入漏洞的人不一定能传文件，
		// 反过来解析报告的人不一定能改漏洞结论。两组权限解耦。
		// 挂载资产是写操作（改变漏洞-资产关系），认 vulnerability:write。
		vulns := secured.Group("/vulnerabilities")
		{
			vulns.GET("", guard.RequirePermission(auth.PermVulnRead), vulnHandler.List)
			vulns.POST("", guard.RequirePermission(auth.PermVulnWrite), vulnHandler.Create)
			vulns.GET("/:id", guard.RequirePermission(auth.PermVulnRead), vulnHandler.Get)
			vulns.PATCH("/:id",
				guard.RequirePermission(auth.PermVulnWrite), vulnHandler.Update)
			vulns.DELETE("/:id",
				guard.RequirePermission(auth.PermVulnWrite), vulnHandler.Delete)
			vulns.POST("/:id/assets",
				guard.RequirePermission(auth.PermVulnWrite), vulnHandler.SetAssets)
		}

		// ── 风险评估（P4）──────────────────────────────────────────
		//
		// 权限码在 P1 就已登记，这里只做挂载（与 P2 / P3 的结论一致）。
		// 逐项覆盖威胁写在 /risk-items/:itemId 而不是 /vulnerabilities：
		// 它改的是**那次评估的结果**，不是漏洞本身——同一条漏洞在两次
		// 评估里可以有不同威胁。
		assess := secured.Group("/assessments")
		{
			assess.GET("", guard.RequirePermission(auth.PermAssessRead), assessHandler.List)
			assess.POST("", guard.RequirePermission(auth.PermAssessWrite), assessHandler.Create)

			// 静态段排在 :id 之前（gin 的路由树能区分两者，顺序只影响可读性）。
			assess.POST("/preview",
				guard.RequirePermission(auth.PermAssessRead), assessHandler.Preview)

			assess.GET("/:id", guard.RequirePermission(auth.PermAssessRead), assessHandler.Get)
			assess.PATCH("/:id", guard.RequirePermission(auth.PermAssessWrite), assessHandler.Update)
			assess.DELETE("/:id", guard.RequirePermission(auth.PermAssessWrite), assessHandler.Delete)
			assess.POST("/:id/calculate",
				guard.RequirePermission(auth.PermAssessWrite), assessHandler.Calculate)
			assess.GET("/:id/risk-items",
				guard.RequirePermission(auth.PermAssessRead), assessHandler.RiskItems)
			assess.PATCH("/:id/risk-items/:itemId",
				guard.RequirePermission(auth.PermAssessWrite), assessHandler.SetRiskItemThreat)
			assess.GET("/:id/matrix",
				guard.RequirePermission(auth.PermAssessRead), assessHandler.Matrix)
			assess.GET("/:id/export-data",
				guard.RequirePermission(auth.PermAssessRead), assessHandler.ExportData)
		}

		// ── 整改跟踪（P6）──────────────────────────────────────────
		//
		// 权限码在 P1 就已登记 remediation:read / remediation:write，
		// 这里只做挂载（与 P2 / P3 / P4 的结论一致）：admin / assessor
		// 可写，auditor 由 readOnlyPermissions() 自动派生只读——
		// 审计员要能看整改全貌但不能改，这正是「只读角色」的定义。
		//
		// 状态流转单开一个 POST 端点而不是并进 PATCH：
		// 它写两张表、有必填说明规则、且会写独立的审计动作码。
		rems := secured.Group("/remediations")
		{
			// 静态段排在 :id 之前（gin 的路由树能区分两者，顺序只影响可读性，
			// 与 assets 的 import/* 同一风格）。
			rems.POST("/batch",
				guard.RequirePermission(auth.PermRemedWrite), remediationHandler.BatchCreate)

			rems.GET("", guard.RequirePermission(auth.PermRemedRead), remediationHandler.List)
			rems.POST("", guard.RequirePermission(auth.PermRemedWrite), remediationHandler.Create)
			rems.GET("/:id", guard.RequirePermission(auth.PermRemedRead), remediationHandler.Get)
			rems.PATCH("/:id",
				guard.RequirePermission(auth.PermRemedWrite), remediationHandler.Update)
			rems.POST("/:id/transition",
				guard.RequirePermission(auth.PermRemedWrite), remediationHandler.Transition)
			rems.DELETE("/:id",
				guard.RequirePermission(auth.PermRemedWrite), remediationHandler.Delete)
		}

		// ── 首页统计（P6）──────────────────────────────────────────
		//
		// 三个权限取其一：仪表盘把资产 / 漏洞 / 评估 / 整改四个区块拼在一起，
		// 而内置角色的权限拆分使得没有任何一个角色同时拥有全部四组读权限下的
		// 最小集（比如 auditor 只有读权限，assessor 没有 system:read）。
		// 要求「同时具备」会让仪表盘对多数角色 403；要求「任一具备」则
		// 与「能看某个页面的人就能看到首页汇总」一致。
		//
		// 越权风险已由「区块内不含敏感字段」控制：汇总里的每个数字都与
		// 对应列表页可见的数字同源，没有超出各页面的信息量。
		secured.GET("/dashboard/summary",
			guard.RequirePermission(auth.PermAssessRead, auth.PermAssetRead, auth.PermRemedRead),
			dashboardHandler.Summary)

		// ── 报告导出（P5）──────────────────────────────────────────
		//
		// 权限挂 report:read 而不是 assessment:read：
		// 「看评估结果」与「把结果导成文件带走」是两件事。内置角色里
		// admin / assessor / auditor 三者都有 report:read（审计员正是
		// 最需要拿报告的人），而 report:write 保留给之后的「报告模板配置」，
		// 现在没有端点消费它。
		reports := secured.Group("/reports")
		{
			reports.POST("/export",
				guard.RequirePermission(auth.PermReportRead), reportHandler.Export)
		}

		// ── 系统配置（P4）──────────────────────────────────────────
		//
		// 读接口同时接受 system:read 与 assessment:read：评估员没有系统
		// 设置权限，但他在评估执行页必须能看到当前阈值才能理解结果。
		// 与 /roles、/dictionaries 是同一处理。写接口只认 system:write。
		sys := secured.Group("/system")
		{
			sys.GET("/configs",
				guard.RequirePermission(auth.PermSystemRead, auth.PermAssessRead),
				sysCfgHandler.Get)
			sys.PATCH("/configs",
				guard.RequirePermission(auth.PermSystemWrite), sysCfgHandler.Update)
		}
	}

	return r, nil
}
