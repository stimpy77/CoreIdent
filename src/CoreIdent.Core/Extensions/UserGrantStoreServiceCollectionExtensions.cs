using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

public static class UserGrantStoreServiceCollectionExtensions
{
    public static IServiceCollection AddUserGrantStore<TUserGrantStore>(this IServiceCollection services)
        where TUserGrantStore : class, IUserGrantStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IUserGrantStore, TUserGrantStore>();
        return services;
    }

    public static IServiceCollection AddInMemoryUserGrantStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<InMemoryUserGrantStore>();
        services.TryAddSingleton<IUserGrantStore>(sp => sp.GetRequiredService<InMemoryUserGrantStore>());
        return services;
    }
}
