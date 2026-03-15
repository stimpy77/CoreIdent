using CoreIdent.Core.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.Legacy.PasswordGrant.Extensions;

/// <summary>
/// DI extensions for registering the legacy password grant (ROPC) handler.
/// <para>
/// <strong>Deprecated in OAuth 2.1 (RFC 9725).</strong> Use authorization code flow with PKCE instead.
/// This package is provided for migration support only.
/// </para>
/// </summary>
public static class PasswordGrantExtensions
{
    /// <summary>
    /// Adds the legacy password grant (ROPC) handler to the token endpoint.
    /// <para>
    /// Clients must have <c>"password"</c> in their <c>AllowedGrantTypes</c> to use this grant.
    /// A deprecation warning is logged on every password grant request.
    /// </para>
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPasswordGrant(this IServiceCollection services)
    {
        services.AddSingleton<IGrantTypeHandler, PasswordGrantHandler>();
        return services;
    }
}
