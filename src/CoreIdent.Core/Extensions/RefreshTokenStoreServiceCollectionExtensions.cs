using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

public static class RefreshTokenStoreServiceCollectionExtensions
{
    public static IServiceCollection AddRefreshTokenStore<TRefreshTokenStore>(this IServiceCollection services)
        where TRefreshTokenStore : class, IRefreshTokenStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IRefreshTokenStore, TRefreshTokenStore>();
        return services;
    }

    /// <summary>
    /// Adds an in-memory refresh token store to the service collection.
    /// </summary>
    public static IServiceCollection AddInMemoryRefreshTokenStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<InMemoryRefreshTokenStore>();
        services.TryAddSingleton<IRefreshTokenStore>(sp => sp.GetRequiredService<InMemoryRefreshTokenStore>());
        return services;
    }
}
