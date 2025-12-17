using System.Diagnostics;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Extensions;

public static class CoreIdentProblemDetails
{
    public static IResult Create(
        HttpRequest request,
        int statusCode,
        string errorCode,
        string title,
        string detail)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);

        var httpContext = request.HttpContext;

        var correlationId = CoreIdentCorrelation.GetOrCreate(httpContext);
        var traceId = Activity.Current?.TraceId.ToString() ?? httpContext.TraceIdentifier;

        var payload = new CoreIdentProblemDetailsPayload
        {
            Type = "about:blank",
            Title = title,
            Status = statusCode,
            Detail = detail,
            Instance = request.Path.HasValue ? request.Path.Value! : string.Empty,
            Extensions = new Dictionary<string, object?>
            {
                ["error_code"] = errorCode,
                ["correlation_id"] = correlationId,
                ["trace_id"] = traceId
            }
        };

        return Results.Json(payload, statusCode: statusCode, contentType: "application/problem+json");
    }

    private sealed class CoreIdentProblemDetailsPayload
    {
        [JsonPropertyName("type")]
        public string Type { get; init; } = string.Empty;

        [JsonPropertyName("title")]
        public string Title { get; init; } = string.Empty;

        [JsonPropertyName("status")]
        public int Status { get; init; }

        [JsonPropertyName("detail")]
        public string Detail { get; init; } = string.Empty;

        [JsonPropertyName("instance")]
        public string Instance { get; init; } = string.Empty;

        [JsonExtensionData]
        public Dictionary<string, object?> Extensions { get; init; } = new(StringComparer.Ordinal);
    }
}
