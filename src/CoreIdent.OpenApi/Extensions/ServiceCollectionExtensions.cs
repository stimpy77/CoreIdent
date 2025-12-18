using CoreIdent.OpenApi.Configuration;
using CoreIdent.OpenApi.Transformers;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.OpenApi.Extensions;

/// <summary>
/// Service registration helpers for CoreIdent OpenAPI support.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds CoreIdent OpenAPI services (built on <c>Microsoft.AspNetCore.OpenApi</c>).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional OpenAPI options configuration.</param>
    /// <returns>The same service collection for chaining.</returns>
    public static IServiceCollection AddCoreIdentOpenApi(
        this IServiceCollection services,
        Action<CoreIdentOpenApiOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new CoreIdentOpenApiOptions();
        configure?.Invoke(options);

        services.AddSingleton(options);

        services.AddOpenApi("v1", openApiOptions =>
        {
            openApiOptions.AddDocumentTransformer<CoreIdentOpenApiDocumentTransformer>();
            openApiOptions.AddOperationTransformer<CoreIdentOpenApiOperationTransformer>();

            if (options.IncludeXmlComments)
            {
                openApiOptions.AddSchemaTransformer(new CoreIdentOpenApiSchemaTransformer());
            }
        });

        return services;
    }
}
