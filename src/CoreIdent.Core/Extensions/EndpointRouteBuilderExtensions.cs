using CoreIdent.Core.Configuration;
using CoreIdent.Core.Endpoints;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Extensions;

public static class EndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapCoreIdentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var services = endpoints.ServiceProvider;

        var coreOptions = services.GetRequiredService<IOptions<CoreIdentOptions>>().Value;
        var routeOptions = services.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;

        return endpoints.MapCoreIdentEndpoints(coreOptions, routeOptions);
    }

    public static IEndpointRouteBuilder MapCoreIdentEndpoints(this IEndpointRouteBuilder endpoints, Action<CoreIdentRouteOptions> configureRoutes)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(configureRoutes);

        var services = endpoints.ServiceProvider;
        var coreOptions = services.GetRequiredService<IOptions<CoreIdentOptions>>().Value;

        var routeOptions = new CoreIdentRouteOptions();
        configureRoutes(routeOptions);

        return endpoints.MapCoreIdentEndpoints(coreOptions, routeOptions);
    }

    public static IEndpointRouteBuilder MapCoreIdentEndpoints(
        this IEndpointRouteBuilder endpoints,
        CoreIdentOptions coreOptions,
        CoreIdentRouteOptions routeOptions)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(coreOptions);
        ArgumentNullException.ThrowIfNull(routeOptions);

        var jwksPath = routeOptions.GetJwksPath(coreOptions);
        endpoints.MapCoreIdentDiscoveryEndpoints(jwksPath);

        var revokePath = routeOptions.CombineWithBase("revoke");
        endpoints.MapCoreIdentTokenManagementEndpoints(revokePath);

        return endpoints;
    }
}
