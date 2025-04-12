using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions; // For TryAddSingleton
using Microsoft.Extensions.Options;
using System;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Extension methods for setting up CoreIdent core services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class CoreIdentServiceCollectionExtensions
{
    /// <summary>
    /// Adds the CoreIdent core services to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configureOptions">An action delegate to configure the provided <see cref="CoreIdentOptions"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddCoreIdent(this IServiceCollection services, Action<CoreIdentOptions> configureOptions)
    {
        if (services == null) throw new ArgumentNullException(nameof(services));
        if (configureOptions == null) throw new ArgumentNullException(nameof(configureOptions));

        // Configure and validate options
        services.Configure(configureOptions);
        services.AddSingleton<IValidateOptions<CoreIdentOptions>, CoreIdentOptionsValidator>(); // Add validator
        // Ensure validation runs on startup
        services.AddOptions<CoreIdentOptions>().ValidateOnStart();

        // Register default core services
        // Use TryAddSingleton to allow consumers to easily override implementations if needed
        services.TryAddSingleton<IPasswordHasher, DefaultPasswordHasher>();
        services.TryAddSingleton<ITokenService, JwtTokenService>();

        // Register default store for Phase 1 (In-Memory)
        services.TryAddSingleton<IUserStore, InMemoryUserStore>();

        // Add other necessary framework services if any.
        // For now, the core services themselves don't have many external dependencies beyond options.
        // HttpContextAccessor might be needed later for endpoint logic.
        // services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        return services;
    }
}
