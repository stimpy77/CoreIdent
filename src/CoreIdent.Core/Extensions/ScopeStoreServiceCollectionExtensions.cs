using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

public static class ScopeStoreServiceCollectionExtensions
{
    public static IServiceCollection AddScopeStore<TScopeStore>(this IServiceCollection services)
        where TScopeStore : class, IScopeStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IScopeStore, TScopeStore>();
        return services;
    }

    /// <summary>
    /// Adds an in-memory scope store to the service collection.
    /// </summary>
    public static IServiceCollection AddInMemoryScopeStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<InMemoryScopeStore>();
        services.TryAddSingleton<IScopeStore>(sp => sp.GetRequiredService<InMemoryScopeStore>());
        return services;
    }

    /// <summary>
    /// Adds an in-memory scope store with pre-seeded scopes.
    /// </summary>
    public static IServiceCollection AddInMemoryScopes(this IServiceCollection services, IEnumerable<CoreIdentScope> scopes)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(scopes);

        services.TryAddSingleton<InMemoryScopeStore>(sp =>
        {
            var store = new InMemoryScopeStore();
            store.SeedScopes(scopes);
            return store;
        });
        services.TryAddSingleton<IScopeStore>(sp => sp.GetRequiredService<InMemoryScopeStore>());

        return services;
    }

    /// <summary>
    /// Adds an in-memory scope store pre-seeded with standard OIDC scopes.
    /// </summary>
    public static IServiceCollection AddInMemoryStandardScopes(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<InMemoryScopeStore>(sp =>
        {
            var store = new InMemoryScopeStore();
            store.SeedStandardScopes();
            return store;
        });
        services.TryAddSingleton<IScopeStore>(sp => sp.GetRequiredService<InMemoryScopeStore>());

        return services;
    }
}
