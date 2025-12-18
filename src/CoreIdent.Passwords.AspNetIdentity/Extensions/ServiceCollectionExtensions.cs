using CoreIdent.Core.Services;
using CoreIdent.Passwords.AspNetIdentity.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Passwords.AspNetIdentity.Extensions;

/// <summary>
/// Extension methods for registering ASP.NET Core Identity-based password hashing services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Replaces the CoreIdent <see cref="IPasswordHasher"/> implementation with an ASP.NET Core Identity-backed password hasher.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddAspNetIdentityPasswordHasher(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher, DefaultPasswordHasher>());

        return services;
    }
}
