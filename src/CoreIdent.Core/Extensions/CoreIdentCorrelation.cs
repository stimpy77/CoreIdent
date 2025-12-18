using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Provides correlation ID utilities for requests.
/// </summary>
public static class CoreIdentCorrelation
{
    /// <summary>
    /// Correlation header name.
    /// </summary>
    public const string HeaderName = "X-Correlation-Id";

    private const string ItemKey = "CoreIdent.CorrelationId";

    /// <summary>
    /// Gets an existing correlation identifier or creates a new one for the request.
    /// </summary>
    /// <param name="httpContext">HTTP context.</param>
    /// <returns>The correlation identifier.</returns>
    public static string GetOrCreate(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        if (httpContext.Items.TryGetValue(ItemKey, out var existing) && existing is string s && !string.IsNullOrWhiteSpace(s))
        {
            return s;
        }

        var requestHeader = httpContext.Request.Headers[HeaderName].ToString();
        var correlationId = !string.IsNullOrWhiteSpace(requestHeader)
            ? requestHeader.Trim()
            : Activity.Current?.Id ?? httpContext.TraceIdentifier;

        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = Guid.NewGuid().ToString("N");
        }

        httpContext.Items[ItemKey] = correlationId;

        if (!httpContext.Response.Headers.ContainsKey(HeaderName))
        {
            httpContext.Response.Headers[HeaderName] = correlationId;
        }

        return correlationId;
    }

    /// <summary>
    /// Begins a logging scope containing correlation and trace identifiers.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="httpContext">HTTP context.</param>
    /// <returns>The scope disposable.</returns>
    public static IDisposable BeginScope(ILogger logger, HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(httpContext);

        var correlationId = GetOrCreate(httpContext);
        var traceId = Activity.Current?.TraceId.ToString() ?? httpContext.TraceIdentifier;

        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["correlation_id"] = correlationId,
            ["trace_id"] = traceId
        }) ?? NoopDisposable.Instance;
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new();

        public void Dispose()
        {
        }
    }
}
