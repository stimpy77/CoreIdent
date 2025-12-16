using CoreIdent.Core.Services;
using CoreIdent.Passwords.AspNetIdentity.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Passwords.AspNetIdentity.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAspNetIdentityPasswordHasher(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher, DefaultPasswordHasher>());

        return services;
    }
}
