using System.Security.Cryptography;
using System.Text;

namespace SecRisk.DocGen.Security;

/// <summary>
/// 服务间调用鉴权中间件。
///
/// <para>
/// docgen 不映射端口到宿主机，只存在于 compose 的内部网络，但那只挡住了外部流量，
/// 挡不住同一网络内其他被攻陷的容器。这里再做一次共享密钥校验。
/// </para>
/// <para>
/// 比较使用 <see cref="CryptographicOperations.FixedTimeEquals"/> 做恒定时间比较，
/// 避免按字节短路比较带来的时序侧信道。
/// </para>
/// </summary>
public sealed class InternalSecretMiddleware
{
    /// <summary>请求头名称，与 Go 侧调用方约定一致。</summary>
    public const string HeaderName = "X-Internal-Secret";

    /// <summary>最短密钥长度。低于此长度视为未配置。</summary>
    public const int MinSecretLength = 16;

    private static readonly string[] BypassPaths = ["/health"];

    private readonly RequestDelegate _next;
    private readonly byte[] _expectedSecret;

    public InternalSecretMiddleware(
        RequestDelegate next,
        IConfiguration configuration,
        ILogger<InternalSecretMiddleware> logger)
    {
        _next = next;

        var secret = configuration["DOCGEN_INTERNAL_SECRET"]
                     ?? Environment.GetEnvironmentVariable("DOCGEN_INTERNAL_SECRET");

        if (string.IsNullOrWhiteSpace(secret) || secret.Length < MinSecretLength)
        {
            // 密钥缺失直接拒绝启动。
            // 一个「忘记配密钥」的 docgen 服务，等于对内部网络完全敞开且毫无告警，
            // 所以宁可启动失败，也不能带着空密钥跑起来。
            throw new InvalidOperationException(
                $"DOCGEN_INTERNAL_SECRET 未配置或长度不足 {MinSecretLength} 位，拒绝启动。");
        }

        _expectedSecret = Encoding.UTF8.GetBytes(secret);
        logger.LogInformation("内部密钥校验已启用（密钥长度 {Length} 字节）", _expectedSecret.Length);
    }

    public async Task InvokeAsync(HttpContext context, ILogger<InternalSecretMiddleware> logger)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        if (BypassPaths.Any(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!context.Request.Headers.TryGetValue(HeaderName, out var provided) || provided.Count == 0)
        {
            logger.LogWarning("拒绝请求：缺少 {Header} 请求头，path={Path}", HeaderName, path);
            await WriteUnauthorizedAsync(context, "缺少内部密钥").ConfigureAwait(false);
            return;
        }

        var providedBytes = Encoding.UTF8.GetBytes(provided[0] ?? string.Empty);
        if (!CryptographicOperations.FixedTimeEquals(providedBytes, _expectedSecret))
        {
            logger.LogWarning("拒绝请求：内部密钥不匹配，path={Path}", path);
            await WriteUnauthorizedAsync(context, "内部密钥无效").ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    private static async Task WriteUnauthorizedAsync(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response
            .WriteAsJsonAsync(new { code = "UNAUTHORIZED", message })
            .ConfigureAwait(false);
    }
}
