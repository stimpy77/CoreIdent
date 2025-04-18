using CoreIdent.Storage.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Data.Common;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Xunit;

namespace CoreIdent.TestHost.Setup;

/// <summary>
/// Shared fixture for integration tests providing a configured WebApplicationFactory
/// and database context management for CoreIdent.
/// Implements IAsyncLifetime for setup and teardown logic.
/// </summary>
public class TestSetupFixture : WebApplicationFactory<Program>, IAsyncLifetime
{
    private DbConnection? _dbConnection;
    private string? _dbConnectionString;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Remove the app's DbContext registration if it exists.
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<CoreIdentDbContext>));

            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            // Remove the DbConnection registration if it exists
             var connectionDescriptor = services.SingleOrDefault(
                 d => d.ServiceType == typeof(DbConnection));
             if (connectionDescriptor != null)
             {
                 services.Remove(connectionDescriptor);
             }

            // Use the connection string created in InitializeAsync
             if (string.IsNullOrEmpty(_dbConnectionString))
             {
                  throw new InvalidOperationException("Database connection string not initialized before ConfigureServices.");
             }
             _dbConnection = new SqliteConnection(_dbConnectionString);
             // Connection will be opened in InitializeAsync or already open

            // Add DbContext using Sqlite in-memory database
            services.AddDbContext<CoreIdentDbContext>(options =>
            {
                options.UseSqlite(_dbConnection ?? throw new InvalidOperationException("DB Connection is null in ConfigureServices"));
            }, ServiceLifetime.Scoped); // Scoped lifetime is typical

            // Register the connection itself if needed elsewhere (though usually context is used)
            // services.AddSingleton<DbConnection>(_dbConnection);

            // IMPORTANT: Register the EF Core Stores AFTER the DbContext
            // This uses the test DbContext registration above
            services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();

            // Ensure any required background services for tests are added
            // services.AddHostedService<...>();
        });

        builder.UseEnvironment("Development");
    }

    /// <summary>
    /// Creates a new DbContext instance using the shared in-memory connection.
    /// Caller is responsible for disposing the context.
    /// </summary>
    public CoreIdentDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<CoreIdentDbContext>()
            .UseSqlite(_dbConnection ?? throw new InvalidOperationException("Database connection not initialized."))
            .Options;
        return new CoreIdentDbContext(options);
    }

    /// <summary>
    /// Gets a required service from the test server's service provider.
    /// </summary>
    public T GetRequiredService<T>() where T : notnull
    {
        using var scope = Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<T>();
    }

    /// <summary>
    /// Initializes the database connection and schema asynchronously before tests run.
    /// </summary>
    public async ValueTask InitializeAsync()
    {
        // Create and open the connection here
        if (_dbConnection == null)
        {
             _dbConnectionString = $"DataSource=file:memdb-{Guid.NewGuid()}?mode=memory&cache=shared";
             _dbConnection = new SqliteConnection(_dbConnectionString);
             await _dbConnection.OpenAsync(); // Open connection here
             Console.WriteLine($"TestSetupFixture: Initialized and opened DB connection: {_dbConnectionString}");
        }
        else
        {
            Console.WriteLine("TestSetupFixture: DB connection already initialized.");
        }

        await using var dbContext = CreateDbContext();
        // Ensure the database is created and migrations are applied.
        // Using EnsureCreated for simplicity in tests, but MigrateAsync is better if migrations are used.
        await dbContext.Database.EnsureCreatedAsync();
        // await dbContext.Database.MigrateAsync();
    }

    /// <summary>
    /// Disposes resources asynchronously after tests have run.
    /// Overrides the base DisposeAsync and handles custom resource cleanup.
    /// </summary>
    public override async ValueTask DisposeAsync()
    {
        if (_dbConnection != null)
        {
            await _dbConnection.CloseAsync();
            await _dbConnection.DisposeAsync();
            _dbConnection = null;
        }
        await base.DisposeAsync();
    }
}

// Collection definition to ensure tests using this fixture don't run in parallel
[CollectionDefinition("Database test collection")]
public class DatabaseCollection : ICollectionFixture<TestSetupFixture>
{
    // This class has no code, and is never created. Its purpose is simply
    // to be the place to apply [CollectionDefinition] and all the
    // ICollectionFixture<> interfaces.
} 