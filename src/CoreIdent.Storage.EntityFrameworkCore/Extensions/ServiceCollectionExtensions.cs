using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Storage.EntityFrameworkCore.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds EF Core token revocation store.
    /// </summary>
    public static IServiceCollection AddEntityFrameworkCoreTokenRevocation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<ITokenRevocationStore, EfTokenRevocationStore>();
        return services;
    }

    /// <summary>
    /// Adds EF Core client store.
    /// </summary>
    public static IServiceCollection AddEntityFrameworkCoreClientStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
        services.TryAddScoped<IClientStore, EfClientStore>();
        return services;
    }

    /// <summary>
    /// Adds EF Core scope store.
    /// </summary>
    public static IServiceCollection AddEntityFrameworkCoreScopeStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IScopeStore, EfScopeStore>();
        return services;
    }

    /// <summary>
    /// Adds EF Core refresh token store.
    /// </summary>
    public static IServiceCollection AddEntityFrameworkCoreRefreshTokenStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IRefreshTokenStore, EfRefreshTokenStore>();
        return services;
    }

    /// <summary>
    /// Adds all EF Core stores (token revocation, client, scope, refresh token).
    /// </summary>
    public static IServiceCollection AddEntityFrameworkCoreStores(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddEntityFrameworkCoreTokenRevocation();
        services.AddEntityFrameworkCoreClientStore();
        services.AddEntityFrameworkCoreScopeStore();
        services.AddEntityFrameworkCoreRefreshTokenStore();
        return services;
    }
}
