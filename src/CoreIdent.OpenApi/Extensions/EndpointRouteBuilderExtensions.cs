using CoreIdent.OpenApi.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.OpenApi.Extensions;

/// <summary>
/// Endpoint mapping helpers for CoreIdent OpenAPI support.
/// </summary>
public static class EndpointRouteBuilderExtensions
{
    private const string DocumentNameParameter = "{documentName}";

    /// <summary>
    /// Maps the CoreIdent OpenAPI document endpoint.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>The same endpoint route builder for chaining.</returns>
    public static IEndpointRouteBuilder MapCoreIdentOpenApi(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetService<CoreIdentOpenApiOptions>()
            ?? new CoreIdentOpenApiOptions();

        var pattern = ResolveOpenApiPattern(options);

        endpoints.MapOpenApi(pattern);

        return endpoints;
    }

    private static string ResolveOpenApiPattern(CoreIdentOpenApiOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.OpenApiRoute))
        {
            return "/openapi/{documentName}.json";
        }

        if (options.OpenApiRoute.Contains(DocumentNameParameter, StringComparison.Ordinal))
        {
            return options.OpenApiRoute;
        }

        if (!string.IsNullOrWhiteSpace(options.DocumentVersion)
            && options.OpenApiRoute.Contains(options.DocumentVersion, StringComparison.Ordinal))
        {
            return options.OpenApiRoute.Replace(options.DocumentVersion, DocumentNameParameter, StringComparison.Ordinal);
        }

        return "/openapi/{documentName}.json";
    }
}
