# ============================================================================
# docgen 服务镜像（C# / .NET 10 + DocumentFormat.OpenXml）
#
# 多阶段构建：
#   build   —— 用 SDK 镜像编译发布（约 1GB，不进最终镜像）
#   runtime —— 用 ASP.NET 运行时镜像，仅含运行所需
#
# 安全：
#   - 以镜像内置非 root 用户 APP_UID 运行
#   - 只暴露 8090，且 compose 中不映射到宿主机
#   - 启动时强制校验 DOCGEN_INTERNAL_SECRET，未配置则拒绝启动
# ============================================================================

# ---------------------------------------------------------------- 构建阶段
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

# 先只拷贝工程文件并还原依赖，让 NuGet 层可被缓存
COPY services/docgen/SecRisk.DocGen.csproj ./
RUN dotnet restore

# 再拷贝源码并发布
COPY services/docgen/ ./
RUN dotnet publish \
      -c Release \
      -o /app/publish \
      --no-restore \
      /p:UseAppHost=false \
      /p:DebugType=none

# ---------------------------------------------------------------- 运行阶段
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

# curl 仅用于容器 healthcheck（该镜像不含 curl/wget）
# ⚠️ 注意：这条 apt 安装需要出网，构建机需能访问 Debian 源
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/publish ./

ENV ASPNETCORE_URLS=http://+:8090 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false \
    TZ=Asia/Shanghai

EXPOSE 8090

# 以非 root 运行（aspnet 镜像预置了 APP_UID）
USER $APP_UID

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8090/health || exit 1

ENTRYPOINT ["dotnet", "SecRisk.DocGen.dll"]
