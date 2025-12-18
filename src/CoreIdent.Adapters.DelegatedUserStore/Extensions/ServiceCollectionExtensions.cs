using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore.Extensions;

/// <summary>
/// Service registration helpers for delegating CoreIdent user operations to an external system.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the delegated user store adapter.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration callback.</param>
    /// <returns>The service collection.</returns>
    /// <remarks>
    /// <para>
    /// This removes existing <see cref="IUserStore"/> and <see cref="IPasswordHasher"/> registrations and replaces them
    /// with the delegated implementations.
    /// </para>
    /// <para>
    /// The host application remains responsible for secure credential storage/verification, rate limiting, lockout, MFA,
    /// and preventing credential leakage in logs.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddCoreIdentDelegatedUserStore(
        this IServiceCollection services,
        Action<DelegatedUserStoreOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<DelegatedUserStoreOptions>().ValidateOnStart();
        services.Configure(configure);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<DelegatedUserStoreOptions>, DelegatedUserStoreOptionsValidator>());

        services.RemoveAll<IUserStore>();
        services.RemoveAll<IPasswordHasher>();

        services.AddSingleton<IUserStore, DelegatedUserStore>();
        services.AddSingleton<IPasswordHasher, DelegatedPasswordHasher>();

        return services;
    }
}
