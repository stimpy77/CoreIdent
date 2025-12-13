using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

public static class TokenRevocationServiceCollectionExtensions
{
    public static IServiceCollection AddTokenRevocation(this IServiceCollection services)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.TryAddSingleton<ITokenRevocationStore, InMemoryTokenRevocationStore>();

        return services;
    }
}
