using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Service registration helpers for token revocation.
/// </summary>
public static class TokenRevocationServiceCollectionExtensions
{
    /// <summary>
    /// Adds token revocation services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
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
