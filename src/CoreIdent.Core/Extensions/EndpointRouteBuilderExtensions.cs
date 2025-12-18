using CoreIdent.Core.Configuration;
using CoreIdent.Core.Endpoints;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Endpoint mapping helpers for CoreIdent.
/// </summary>
public static class EndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps all CoreIdent endpoints using options resolved from DI.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>The endpoint route builder.</returns>
    /// <remarks>
    /// <para>
    /// This maps the current CoreIdent endpoint surface (token issuance, revocation/introspection, discovery/JWKS,
    /// authorization/consent, userinfo, resource-owner convenience endpoints, and passwordless endpoints).
    /// </para>
    /// <para>
    /// If you want a smaller surface area, avoid this helper and instead call the granular <c>MapCoreIdent*</c> methods
    /// from <c>CoreIdent.Core.Endpoints</c>.
    /// </para>
    /// </remarks>
    public static IEndpointRouteBuilder MapCoreIdentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var services = endpoints.ServiceProvider;

        var coreOptions = services.GetRequiredService<IOptions<CoreIdentOptions>>().Value;
        var routeOptions = services.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;

        return endpoints.MapCoreIdentEndpoints(coreOptions, routeOptions);
    }

    /// <summary>
    /// Maps all CoreIdent endpoints using options resolved from DI, with route options configured inline.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="configureRoutes">Route options configuration.</param>
    /// <returns>The endpoint route builder.</returns>
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

    /// <summary>
    /// Maps all CoreIdent endpoints using the provided options.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="coreOptions">CoreIdent options.</param>
    /// <param name="routeOptions">Route options.</param>
    /// <returns>The endpoint route builder.</returns>
    /// <remarks>
    /// Discovery and JWKS endpoints are derived from the <see cref="CoreIdentOptions.Issuer"/> path unless overridden.
    /// All other endpoints are mapped under <see cref="CoreIdentRouteOptions.BasePath"/>.
    /// </remarks>
    public static IEndpointRouteBuilder MapCoreIdentEndpoints(
        this IEndpointRouteBuilder endpoints,
        CoreIdentOptions coreOptions,
        CoreIdentRouteOptions routeOptions)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(coreOptions);
        ArgumentNullException.ThrowIfNull(routeOptions);

        endpoints.MapCoreIdentOpenIdConfigurationEndpoint(coreOptions, routeOptions);

        var jwksPath = routeOptions.GetJwksPath(coreOptions);
        endpoints.MapCoreIdentDiscoveryEndpoints(jwksPath);

        var authorizePath = routeOptions.CombineWithBase(routeOptions.AuthorizePath);
        endpoints.MapCoreIdentAuthorizeEndpoint(authorizePath);

        var consentPath = routeOptions.CombineWithBase(routeOptions.ConsentPath);
        endpoints.MapCoreIdentConsentEndpoints(consentPath);

        var tokenPath = routeOptions.CombineWithBase(routeOptions.TokenPath);
        endpoints.MapCoreIdentTokenEndpoint(tokenPath);

        var revokePath = routeOptions.CombineWithBase(routeOptions.RevocationPath);
        var introspectPath = routeOptions.CombineWithBase(routeOptions.IntrospectionPath);
        endpoints.MapCoreIdentTokenManagementEndpoints(revokePath, introspectPath);

        var registerPath = routeOptions.CombineWithBase(routeOptions.RegisterPath);
        var loginPath = routeOptions.CombineWithBase(routeOptions.LoginPath);
        var profilePath = routeOptions.CombineWithBase(routeOptions.ProfilePath);
        endpoints.MapCoreIdentResourceOwnerEndpoints(registerPath, loginPath, profilePath);

        var userInfoPath = routeOptions.CombineWithBase(routeOptions.UserInfoPath);
        endpoints.MapCoreIdentUserInfoEndpoint(userInfoPath);

        var passwordlessEmailStartPath = routeOptions.CombineWithBase(routeOptions.PasswordlessEmailStartPath);
        var passwordlessEmailVerifyPath = routeOptions.CombineWithBase(routeOptions.PasswordlessEmailVerifyPath);
        endpoints.MapCoreIdentPasswordlessEmailEndpoints(passwordlessEmailStartPath, passwordlessEmailVerifyPath);

        var passwordlessSmsStartPath = routeOptions.CombineWithBase(routeOptions.PasswordlessSmsStartPath);
        var passwordlessSmsVerifyPath = routeOptions.CombineWithBase(routeOptions.PasswordlessSmsVerifyPath);
        endpoints.MapCoreIdentPasswordlessSmsEndpoints(passwordlessSmsStartPath, passwordlessSmsVerifyPath);

        return endpoints;
    }
}
