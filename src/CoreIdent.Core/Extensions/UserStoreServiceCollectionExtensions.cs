using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Service registration helpers for user stores.
/// </summary>
public static class UserStoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers a custom <see cref="IUserStore"/> implementation.
    /// </summary>
    /// <typeparam name="TUserStore">The user store implementation.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddUserStore<TUserStore>(this IServiceCollection services)
        where TUserStore : class, IUserStore
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IUserStore, TUserStore>();
        return services;
    }

    /// <summary>
    /// Registers the in-memory <see cref="IUserStore"/> implementation.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddInMemoryUserStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<InMemoryUserStore>();
        services.TryAddSingleton<IUserStore>(sp => sp.GetRequiredService<InMemoryUserStore>());

        return services;
    }
}
