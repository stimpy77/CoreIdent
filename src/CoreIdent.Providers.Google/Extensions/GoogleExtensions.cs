using CoreIdent.Providers.Abstractions;
using CoreIdent.Providers.Abstractions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.Providers.Google.Extensions;

/// <summary>
/// Extension methods for registering Google authentication.
/// </summary>
public static class GoogleExtensions
{
    /// <summary>
    /// Adds Google OAuth authentication to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration options for Google authentication.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddGoogleProvider(
        this IServiceCollection services,
        Action<GoogleProviderOptions> configure)
    {
        services.Configure(configure);
        services.AddScoped<GoogleAuthProvider>();
        services.AddScoped<IExternalAuthProvider, GoogleAuthProvider>();
        return services;
    }
}
