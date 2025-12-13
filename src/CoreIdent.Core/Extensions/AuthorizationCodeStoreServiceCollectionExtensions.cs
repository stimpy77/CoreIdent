using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

public static class AuthorizationCodeStoreServiceCollectionExtensions
{
    public static IServiceCollection AddAuthorizationCodeStore<TAuthorizationCodeStore>(this IServiceCollection services)
        where TAuthorizationCodeStore : class, IAuthorizationCodeStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IAuthorizationCodeStore, TAuthorizationCodeStore>();
        return services;
    }

    public static IServiceCollection AddInMemoryAuthorizationCodeStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<InMemoryAuthorizationCodeStore>();
        services.TryAddSingleton<IAuthorizationCodeStore>(sp => sp.GetRequiredService<InMemoryAuthorizationCodeStore>());
        return services;
    }
}
