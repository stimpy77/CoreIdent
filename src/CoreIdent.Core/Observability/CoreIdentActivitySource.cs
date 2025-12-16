using System.Diagnostics;
using System.Reflection;

namespace CoreIdent.Core.Observability;

public static class CoreIdentActivitySource
{
    public const string ActivitySourceName = "CoreIdent";

    private static readonly string? Version =
        typeof(CoreIdentActivitySource).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(CoreIdentActivitySource).Assembly.GetName().Version?.ToString();

    public static readonly ActivitySource ActivitySource =
        Version is null ? new(ActivitySourceName) : new(ActivitySourceName, Version);
}
