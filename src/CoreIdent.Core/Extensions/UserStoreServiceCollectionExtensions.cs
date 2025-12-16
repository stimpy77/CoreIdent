using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

public static class UserStoreServiceCollectionExtensions
{
    public static IServiceCollection AddUserStore<TUserStore>(this IServiceCollection services)
        where TUserStore : class, IUserStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IUserStore, TUserStore>();
        return services;
    }

    public static IServiceCollection AddInMemoryUserStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<InMemoryUserStore>();
        services.TryAddSingleton<IUserStore>(sp => sp.GetRequiredService<InMemoryUserStore>());

        return services;
    }
}
