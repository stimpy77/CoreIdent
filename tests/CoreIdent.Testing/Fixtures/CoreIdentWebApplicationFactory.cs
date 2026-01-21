using CoreIdent.Core.Configuration;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using CoreIdent.Testing.Seeders;
using CoreIdent.Passwords.AspNetIdentity.Extensions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Testing.Fixtures;

public sealed class CoreIdentWebApplicationFactory : WebApplicationFactory<global::Program>
{
    private SqliteConnection? _connection;
    private bool _seeded;

    public Action<IServiceCollection>? ConfigureTestServices { get; set; }

    public Action<CoreIdentDbContext>? SeedDatabase { get; set; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureLogging(logging =>
        {
            logging.AddFilter("CoreIdent.Core.Services.SymmetricSigningKeyProvider", LogLevel.Error);
        });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<CoreIdentDbContext>>();
            services.RemoveAll<CoreIdentDbContext>();

            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();

            services.AddDbContext<CoreIdentDbContext>(options => options.UseSqlite(_connection));
            services.AddEntityFrameworkCoreStores();

            services.AddAspNetIdentityPasswordHasher();

            // Disable cleanup hosted service to prevent race condition with DB creation
            services.Configure<CoreIdentAuthorizationCodeOptions>(opts => opts.EnableCleanupHostedService = false);

            ConfigureTestServices?.Invoke(services);

            // Create database tables immediately to avoid race with background hosted services.
            // This must happen during ConfigureServices so tables exist before the host starts.
            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
            db.Database.EnsureCreated();
        });
    }

    /// <summary>
    /// Ensures the database is created and seeded. Call after creating the client.
    /// </summary>
    public void EnsureSeeded()
    {
        if (_seeded) return;
        _seeded = true;

        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();

        db.Database.EnsureCreated();

        if (!db.Scopes.Any())
        {
            db.Scopes.AddRange(StandardScopes.All);
            db.SaveChanges();
        }

        SeedDatabase?.Invoke(db);
        db.SaveChanges();
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _connection?.Dispose();
        }
    }
}
