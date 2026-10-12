using System.Text;

using SecRisk.DocGen.Models;
using SecRisk.DocGen.Rendering;

namespace SecRisk.DocGen.Endpoints;

/// <summary>docx 渲染接口。</summary>
public static class DocxEndpoints
{
    private const string DocxContentType =
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

    public static IEndpointRouteBuilder MapDocxEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/render");

        group.MapPost("/docx", (DocxRenderRequest request, ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("SecRisk.DocGen.Render");

            if (request.Sections.Count == 0 && string.IsNullOrWhiteSpace(request.Title))
            {
                return Results.BadRequest(new
                {
                    code = "INVALID_REQUEST",
                    message = "title 与 sections 不能同时为空",
                });
            }

            try
            {
                var bytes = DocxRenderer.Render(request, logger);
                var fileName = SanitizeFileName(request.Title) + ".docx";

                logger.LogInformation(
                    "docx 渲染完成：{FileName}，{Size} 字节，{SectionCount} 个章节",
                    fileName, bytes.Length, request.Sections.Count);

                return Results.File(bytes, DocxContentType, fileName);
            }
            catch (Exception ex)
            {
                // 对外只返回通用信息：异常详情可能包含内部路径与结构细节
                logger.LogError(ex, "docx 渲染失败");
                return Results.Problem(
                    title: "docx 渲染失败",
                    detail: "渲染过程中发生错误，请查看服务日志（已记录完整堆栈）",
                    statusCode: StatusCodes.Status500InternalServerError);
            }
        });

        return app;
    }

    /// <summary>
    /// 清洗文件名：只保留安全字符。
    ///
    /// 必要性：文件名会进入 <c>Content-Disposition</c> 响应头，
    /// 未清洗时可能造成响应头注入（CRLF）或路径穿越。
    /// </summary>
    private static string SanitizeFileName(string? raw)
    {
        var name = string.IsNullOrWhiteSpace(raw) ? "report" : raw.Trim();

        var builder = new StringBuilder(name.Length);
        foreach (var ch in name)
        {
            var keep = char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.' or ' '
                       || ch >= 0x4E00; // 保留中日韩汉字
            builder.Append(keep ? ch : '_');
        }

        var sanitized = builder.ToString().Trim().Trim('.');
        if (sanitized.Length == 0)
        {
            sanitized = "report";
        }
        if (sanitized.Length > 80)
        {
            sanitized = sanitized[..80];
        }
        return sanitized;
    }
}
