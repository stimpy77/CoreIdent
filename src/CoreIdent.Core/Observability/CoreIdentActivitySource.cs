using System.Diagnostics;
using System.Reflection;

namespace CoreIdent.Core.Observability;

/// <summary>
/// Provides a shared <see cref="ActivitySource"/> for CoreIdent tracing.
/// </summary>
public static class CoreIdentActivitySource
{
    /// <summary>
    /// The CoreIdent activity source name.
    /// </summary>
    public const string ActivitySourceName = "CoreIdent";

    private static readonly string? Version =
        typeof(CoreIdentActivitySource).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(CoreIdentActivitySource).Assembly.GetName().Version?.ToString();

    /// <summary>
    /// The shared activity source.
    /// </summary>
    public static readonly ActivitySource ActivitySource =
        Version is null ? new(ActivitySourceName) : new(ActivitySourceName, Version);
}
