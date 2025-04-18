using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Services;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;

namespace CoreIdent.Storage.EntityFrameworkCore.Extensions;

public static class CoreIdentEntityFrameworkCoreExtensions
{
    /// <summary>
    /// Registers the Entity Framework Core implementations of the CoreIdent stores.
    /// It's recommended to register your DbContext before calling this method.
    /// </summary>
    /// <typeparam name="TContext">Your application's DbContext type that includes CoreIdent entities.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="enableTokenCleanup">Optional: Set to true to enable the background service that cleans up expired tokens (defaults to true).</param>
    /// <param name="enableAuthorizationCodeCleanup">Optional: Set to true to enable the background service that cleans up expired authorization codes (defaults to true).</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddCoreIdentEntityFrameworkStores<TContext>(
        this IServiceCollection services,
        bool enableTokenCleanup = true,
        bool enableAuthorizationCodeCleanup = true)
        where TContext : DbContext
    {
        if (services == null) throw new ArgumentNullException(nameof(services));

        // Check if TContext is registered, warn if not (stores will fail later)
        if (services.BuildServiceProvider().GetService<TContext>() == null)
        {
            // Consider logging a warning here instead of throwing, allowing flexibility in registration order,
            // although the recommended order is DbContext first.
            // _logger.LogWarning($"DbContext {typeof(TContext).Name} not found in services. Ensure it is registered before CoreIdent stores are resolved.");
            // For now, throw to enforce recommended pattern
            throw new InvalidOperationException($"DbContext {typeof(TContext).Name} must be registered before calling AddCoreIdentEntityFrameworkStores.");
        }

        // Register EF Core Store implementations
        // Use TryAddScoped to allow users to override specific stores after calling this method if needed
        services.TryAddScoped<IUserStore, EfUserStore>();
        services.TryAddScoped<IRefreshTokenStore, EfRefreshTokenStore>();
        services.TryAddScoped<IClientStore, EfClientStore>();
        services.TryAddScoped<IScopeStore, EfScopeStore>();
        services.TryAddScoped<IAuthorizationCodeStore, EfAuthorizationCodeStore>();

        // Register background cleanup services if enabled
        if (enableTokenCleanup)
        {
            services.AddHostedService<RefreshTokenCleanupService>();
        }

        if (enableAuthorizationCodeCleanup)
        {
            services.AddHostedService<AuthorizationCodeCleanupService>();
        }

        return services;
    }
} 