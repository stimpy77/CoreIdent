using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Service registration helpers for authorization code stores.
/// </summary>
public static class AuthorizationCodeStoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers a custom <see cref="IAuthorizationCodeStore"/> implementation.
    /// </summary>
    /// <typeparam name="TAuthorizationCodeStore">The authorization code store implementation.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddAuthorizationCodeStore<TAuthorizationCodeStore>(this IServiceCollection services)
        where TAuthorizationCodeStore : class, IAuthorizationCodeStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IAuthorizationCodeStore, TAuthorizationCodeStore>();
        return services;
    }

    /// <summary>
    /// Registers the in-memory <see cref="IAuthorizationCodeStore"/> implementation.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddInMemoryAuthorizationCodeStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<InMemoryAuthorizationCodeStore>();
        services.TryAddSingleton<IAuthorizationCodeStore>(sp => sp.GetRequiredService<InMemoryAuthorizationCodeStore>());
        return services;
    }
}
