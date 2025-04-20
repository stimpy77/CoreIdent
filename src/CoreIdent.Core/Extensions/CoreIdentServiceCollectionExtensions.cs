using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions; // For TryAdd*
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
        // Use TryAdd to allow consumers to easily override implementations if needed
        services.TryAddSingleton<IPasswordHasher, DefaultPasswordHasher>();
        services.TryAddScoped<ITokenService, JwtTokenService>();
        // Ensure JwtTokenService is also registered for direct injection (for endpoints using [FromServices] JwtTokenService)
        services.TryAddScoped<JwtTokenService, JwtTokenService>();

        // Register default IN-MEMORY stores. Consumers can replace these by registering
        // other implementations (like EF Core stores) AFTER calling AddCoreIdent.
        services.TryAddScoped<IUserStore, InMemoryUserStore>();
        services.TryAddScoped<IRefreshTokenStore, InMemoryRefreshTokenStore>(); // Add default
        services.TryAddScoped<IClientStore, InMemoryClientStore>();         // Add default
        services.TryAddScoped<IScopeStore, InMemoryScopeStore>();           // Add default
        services.TryAddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>(); // Use Singleton for in-memory store
        services.TryAddScoped<ICustomClaimsProvider, CustomClaimsProviderDefault>(); // Register default custom claims provider
        // Register user grant store for consent mechanism
        services.TryAddSingleton<IUserGrantStore, InMemoryUserGrantStore>();

        // Add other necessary framework services if any.
        // For now, the core services themselves don't have many external dependencies beyond options.
        // HttpContextAccessor might be needed later for endpoint logic.
        services.AddHttpContextAccessor();

        return services;
    }
}
