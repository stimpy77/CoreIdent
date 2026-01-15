using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Testing.Fixtures;
using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.Testing.Host;

/// <summary>
/// Helpers for starting a CoreIdent server for tests.
/// </summary>
public static class CoreIdentTestHost
{
    /// <summary>
    /// Creates a new <see cref="CoreIdentWebApplicationFactory"/> configured for CoreIdent tests.
    /// </summary>
    /// <param name="configureTestServices">
    /// Optional callback to configure test services (DI overrides, options, etc.).
    /// </param>
    /// <param name="seedDatabase">
    /// Optional callback to seed the EF Core database after it is created.
    /// </param>
    public static CoreIdentWebApplicationFactory CreateFactory(
        Action<IServiceCollection>? configureTestServices = null,
        Action<CoreIdentDbContext>? seedDatabase = null)
    {
        var factory = new CoreIdentWebApplicationFactory
        {
            ConfigureTestServices = configureTestServices,
            SeedDatabase = seedDatabase
        };

        return factory;
    }
}
