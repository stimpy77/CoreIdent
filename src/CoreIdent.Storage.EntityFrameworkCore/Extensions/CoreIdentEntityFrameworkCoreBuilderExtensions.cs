using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CoreIdent.Storage.EntityFrameworkCore.Extensions;

/// <summary>
/// Extension methods for setting up CoreIdent EF Core stores in an <see cref="IServiceCollection" />.
/// </summary>
public static class CoreIdentEntityFrameworkCoreBuilderExtensions
{
    /// <summary>
    /// Configures CoreIdent to use Entity Framework Core for its storage.
    /// Requires the DbContext to be registered elsewhere (e.g., AddDbContext or AddDbContextPool).
    /// </summary>
    /// <typeparam name="TContext">The type of the DbContext.</typeparam>
    /// <param name="builder">The CoreIdent builder.</param>
    /// <returns>The builder instance for chaining.</returns>
    public static IServiceCollection AddCoreIdentEntityFrameworkStores<TContext>(this IServiceCollection services)
        where TContext : DbContext // Could add a marker interface like ICoreIdentDbContext if desired
    {
        if (services == null) throw new ArgumentNullException(nameof(services));

        // Register the EF implementations of the stores.
        // This assumes AddCoreIdent() has already been called and potentially registered InMemory stores.
        // These registrations will replace the InMemory ones due to how DI works (last registration wins).
        services.AddScoped<IUserStore, EfUserStore>();
        services.AddScoped<IRefreshTokenStore, EfRefreshTokenStore>();
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IScopeStore, EfScopeStore>();

        // Register the DbContext itself if it hasn't been registered elsewhere.
        // However, it's generally better practice for the consuming application
        // to register the DbContext using AddDbContext<TContext>(options => ...)
        // so it controls the database provider and connection string.

        // Example of how application could register:
        // services.AddDbContext<CoreIdentDbContext>(options =>
        //     options.UseSqlite("Data Source=coreident.db"));

        // We might want to add a helper method for the application to register the DbContext
        // with a specific provider, e.g.:
        // services.AddCoreIdentDbContext<CoreIdentDbContext>(options => options.UseSqlite(...))

        return services;
    }

    // Optional: Add overloads that take DbContextOptionsBuilder actions for specific providers (Sqlite, SqlServer, etc.)
    // e.g., AddCoreIdentSqliteStores(string connectionString)
}

// Placeholder for a potential CoreIdentBuilder pattern if we introduce it later
// public interface ICoreIdentBuilder { IServiceCollection Services { get; } }
// internal class CoreIdentBuilder : ICoreIdentBuilder { public IServiceCollection Services { get; } ... } 