using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Service registration helpers for user grant (consent) stores.
/// </summary>
public static class UserGrantStoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers a custom <see cref="IUserGrantStore"/> implementation.
    /// </summary>
    /// <typeparam name="TUserGrantStore">The user grant store implementation.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddUserGrantStore<TUserGrantStore>(this IServiceCollection services)
        where TUserGrantStore : class, IUserGrantStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IUserGrantStore, TUserGrantStore>();
        return services;
    }

    /// <summary>
    /// Registers the in-memory <see cref="IUserGrantStore"/> implementation.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddInMemoryUserGrantStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<InMemoryUserGrantStore>();
        services.TryAddSingleton<IUserGrantStore>(sp => sp.GetRequiredService<InMemoryUserGrantStore>());
        return services;
    }
}
