using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions; // For TryAddScoped
using System;

namespace CoreIdent.Storage.EntityFrameworkCore.Extensions;

/// <summary>
/// Extension methods for configuring CoreIdent Entity Framework Core stores.
/// </summary>
public static class CoreIdentEntityFrameworkBuilderExtensions
{
    /// <summary>
    /// Configures CoreIdent to use Entity Framework Core for its stores.
    /// </summary>
    /// <typeparam name="TContext">The type of the DbContext to use.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <remarks>
    /// This method should be called AFTER registering your DbContext (e.g., using AddDbContext) 
    /// and AFTER calling the core AddCoreIdent() method.
    /// </remarks>
    public static IServiceCollection AddCoreIdentEntityFrameworkStores<TContext>(this IServiceCollection services)
        where TContext : DbContext // Ensure TContext is a DbContext
    {
        if (services == null) throw new ArgumentNullException(nameof(services));

        // Register the EF Core implementations for each store interface.
        // Use TryAddScoped to allow users to potentially override these registrations
        // if they have custom implementations inheriting from ours, while ensuring
        // they are scoped to the request lifecycle like the DbContext.

        services.TryAddScoped<IUserStore, EfUserStore>();
        services.TryAddScoped<IRefreshTokenStore, EfRefreshTokenStore>();
        services.TryAddScoped<IClientStore, EfClientStore>();
        services.TryAddScoped<IScopeStore, EfScopeStore>();

        // We depend on the caller registering TContext itself, e.g.:
        // services.AddDbContext<TContext>(options => ...);

        return services;
    }
} 