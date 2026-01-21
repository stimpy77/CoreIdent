using System.Net;
using System.Text.Json;
using CoreIdent.Core.Configuration;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using CoreIdent.Testing.Seeders;
using CoreIdent.TestHost;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Xunit;

namespace CoreIdent.Testing.Host;

/// <summary>
/// Starts <c>CoreIdent.TestHost</c> in-proc using Kestrel on an ephemeral loopback port.
/// This is required for real browser-driven E2E tests (Playwright) which cannot use TestServer.
/// </summary>
public sealed class KestrelTestHostFixture : IAsyncLifetime, IAsyncDisposable
{
    private WebApplication? _app;

    /// <summary>
    /// The test client ID used for E2E tests.
    /// </summary>
    public const string TestClientId = "e2e-test-client";

    /// <summary>
    /// The test client secret (unhashed) used for E2E tests.
    /// </summary>
    public const string TestClientSecret = "e2e-test-secret";

    public Uri BaseUri { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        // Use a per-run temp db file for isolation.
        var dbPath = Path.Combine(Path.GetTempPath(), $"coreident-e2e-{Guid.NewGuid():N}.db");

        _app = TestHostApp.Build(
            args: [],
            sqliteDbPath: dbPath,
            configureServices: services =>
            {
                // Disable cleanup hosted service to prevent race condition with DB creation
                services.Configure<CoreIdentAuthorizationCodeOptions>(opts => opts.EnableCleanupHostedService = false);
            },
            configureApp: app =>
            {
                // Bind to ephemeral port on loopback.
                app.Urls.Clear();
                app.Urls.Add("http://127.0.0.1:0");
            });

        await _app.StartAsync();

        // Seed the database with test data
        await SeedTestDataAsync();

        var addresses = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
        var address = addresses?.Addresses.FirstOrDefault();
        address.ShouldNotBeNull("Kestrel test host should expose a bound address");

        BaseUri = new Uri(address);
    }

    private async Task SeedTestDataAsync()
    {
        using var scope = _app!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();

        await db.Database.EnsureCreatedAsync();

        // Seed standard scopes if not present
        if (!await db.Scopes.AnyAsync())
        {
            db.Scopes.AddRange(StandardScopes.All);
        }

        // Seed test client for E2E tests
        var clientExists = await db.Clients.AnyAsync(c => c.ClientId == TestClientId);
        if (!clientExists)
        {
            var client = new ClientEntity
            {
                ClientId = TestClientId,
                ClientName = "E2E Test Client",
                ClientType = "Public", // Public client for password grant without client_secret
                AllowedGrantTypesJson = JsonSerializer.Serialize(new[] { "password", "refresh_token" }),
                AllowedScopesJson = JsonSerializer.Serialize(new[] { "openid", "profile", "email", "offline_access" }),
                RedirectUrisJson = JsonSerializer.Serialize(new[] { "http://localhost/callback" }),
                PostLogoutRedirectUrisJson = JsonSerializer.Serialize(Array.Empty<string>()),
                RequirePkce = false, // Password grant doesn't use PKCE
                AllowOfflineAccess = true,
                Enabled = true,
                CreatedAt = DateTime.UtcNow
            };
            db.Clients.Add(client);
            await db.SaveChangesAsync();
            
            // Verify it was saved
            var verifyClient = await db.Clients.FirstOrDefaultAsync(c => c.ClientId == TestClientId);
            if (verifyClient == null)
            {
                throw new InvalidOperationException($"Failed to seed client '{TestClientId}'");
            }
            
            // Also verify via client store
            var clientStore = scope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IClientStore>();
            var clientFromStore = await clientStore.FindByClientIdAsync(TestClientId);
            if (clientFromStore == null)
            {
                throw new InvalidOperationException($"Client store cannot find '{TestClientId}' that was just seeded!");
            }
        }
        else
        {
            await db.SaveChangesAsync();
        }
    }

    /// <summary>
    /// IAsyncLifetime.DisposeAsync implementation (returns Task).
    /// </summary>
    async Task IAsyncLifetime.DisposeAsync()
    {
        await DisposeAsyncCore();
    }

    /// <summary>
    /// IAsyncDisposable.DisposeAsync implementation (returns ValueTask).
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
    }

    private async Task DisposeAsyncCore()
    {
        if (_app != null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    public HttpClient CreateClient(bool allowAutoRedirect = false)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = allowAutoRedirect
        };

        return new HttpClient(handler)
        {
            BaseAddress = BaseUri
        };
    }
}
