using System.Reflection;

using Microsoft.AspNetCore.Http.Json;

using SecRisk.DocGen.Endpoints;
using SecRisk.DocGen.Security;

// ============================================================================
// docgen 服务入口
//
// 职责边界（铁律）：只做「结构化 JSON → docx 二进制流」。
//   ✅ 接收契约化 JSON、渲染 docx、返回字节流
//   ❌ 不连数据库、不判权限、不做风险计算、不执行任何用户提供的模板或表达式
//
// 这样它才能被独立部署、独立重启、独立压测，
// 也不会因为拥有数据访问能力而成为绕过权限的后门。
// ============================================================================

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------- JSON
builder.Services.Configure<JsonOptions>(options =>
{
    // 与 Go 侧、前端保持一致的驼峰命名
    options.SerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
    options.SerializerOptions.DefaultIgnoreCondition =
        System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
});

// ------------------------------------------------------------- 请求体大小上限
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
{
    // docgen 只接收结构化 JSON，正常请求远小于此；限制上限以抵御内存放大攻击
    options.Limits.MaxRequestBodySize = 16 * 1024 * 1024;
});

var app = builder.Build();

// 服务间调用鉴权 —— 必须最先执行，未通过校验的请求不进任何业务代码
app.UseMiddleware<InternalSecretMiddleware>();

// ------------------------------------------------------------------ 健康检查
// 该端点不参与密钥校验，否则容器 healthcheck 需要额外配置密钥
app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "secrisk-docgen",
    version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.1.0",
    runtime = Environment.Version.ToString(),
    time = DateTimeOffset.Now.ToString("O"),
}));

app.MapDocxEndpoints();

app.Run();
