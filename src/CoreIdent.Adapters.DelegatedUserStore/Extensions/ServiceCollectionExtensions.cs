using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore.Extensions;

public static class ServiceCollectionExtensions
{
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
