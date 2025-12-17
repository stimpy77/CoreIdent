using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Core.Extensions;

public static class CoreIdentCorrelation
{
    public const string HeaderName = "X-Correlation-Id";

    private const string ItemKey = "CoreIdent.CorrelationId";

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
