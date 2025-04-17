using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Services;
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
        where TContext : DbContext
    {
        if (services == null) throw new ArgumentNullException(nameof(services));

        // Remove existing default registrations if they exist
        services.RemoveAll<IUserStore>();
        services.RemoveAll<IRefreshTokenStore>();
        services.RemoveAll<IClientStore>();
        services.RemoveAll<IScopeStore>();
        // Add other store removals if necessary (e.g., IAuthorizationCodeStore)

        // Register the EF Core implementations EXPLICITLY as Scoped
        services.AddScoped<IUserStore, EfUserStore>();
        services.AddScoped<IRefreshTokenStore, EfRefreshTokenStore>();
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IScopeStore, EfScopeStore>();
        // Register other EF stores here if added later

        return services;
    }

    /// <summary>
    /// Configures CoreIdent to use Entity Framework Core for its stores and adds the token cleanup background service.
    /// </summary>
    /// <typeparam name="TContext">The type of the DbContext to use.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="enableTokenCleanupService">Whether to enable the refresh token cleanup background service. Default is true.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <remarks>
    /// This method should be called AFTER registering your DbContext (e.g., using AddDbContext) 
    /// and AFTER calling the core AddCoreIdent() method.
    /// </remarks>
    public static IServiceCollection AddCoreIdentEntityFrameworkStores<TContext>(
        this IServiceCollection services, 
        bool enableTokenCleanupService = true)
        where TContext : DbContext
    {
        if (services == null) throw new ArgumentNullException(nameof(services));

        // Call the base implementation to register stores
        AddCoreIdentEntityFrameworkStores<TContext>(services);

        // Register the cleanup background service if enabled
        if (enableTokenCleanupService)
        {
            services.AddHostedService<RefreshTokenCleanupService>();
        }

        return services;
    }
} 