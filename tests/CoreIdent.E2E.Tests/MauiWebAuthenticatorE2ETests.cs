using System.Net;
using System.Net.Sockets;
using CoreIdent.Client;
using CoreIdent.Client.Maui;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Builders;
using CoreIdent.Testing.Browser;
using SeededStandardScopes = CoreIdent.Testing.Seeders.StandardScopes;
using CoreIdent.TestHost;
using CoreIdent.Storage.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;
using Shouldly;
using Xunit;
using Xunit.Sdk;

namespace CoreIdent.E2E.Tests;

/// <summary>
/// E2E test that drives a real browser to complete the WebAuthenticator redirect roundtrip
/// while using MAUI client abstractions.
/// </summary>
/// <remarks>
/// Run with: dotnet test --filter "Category=E2E"
/// Requires: dotnet playwright install
/// Set COREIDENT_MAUI_E2E=1 to enable.
/// </remarks>
[Collection("E2E")]
[Trait("Category", "E2E")]
public sealed class MauiWebAuthenticatorE2ETests : IAsyncLifetime
{
    private readonly PlaywrightFixture _playwrightFixture = new();
    private WebApplication _app = null!;
    private HttpClient _client = null!;
    private IServiceProvider _services = null!;
    private Uri _baseUri = null!;
    private string _dbPath = string.Empty;

    public async Task InitializeAsync()
    {
        await _playwrightFixture.InitializeAsync();

        var port = GetEphemeralPort();
        _baseUri = new Uri($"http://127.0.0.1:{port}");
        _dbPath = Path.Combine(Path.GetTempPath(), $"coreident-maui-e2e-{Guid.NewGuid():N}.db");

        _app = TestHostApp.Build(
            args: [],
            sqliteDbPath: _dbPath,
            configureServices: services =>
            {
                services.Configure<CoreIdentOptions>(options =>
                {
                    var issuer = _baseUri.ToString().TrimEnd('/');
                    options.Issuer = issuer;
                    options.Audience = issuer;
                });
                services.Configure<CoreIdentAuthorizationCodeOptions>(options =>
                {
                    options.EnableCleanupHostedService = false;
                });
            },
            configureApp: app =>
            {
                app.Urls.Clear();
                app.Urls.Add(_baseUri.ToString());
                app.MapGet("/callback", () => Results.Content("Authentication Complete", "text/html"));
            });

        await _app.StartAsync();

        _services = _app.Services;
        _client = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false
        })
        {
            BaseAddress = _baseUri
        };

        await EnsureSeededAsync();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        await _playwrightFixture.DisposeAsync();

        // Leave the temp database file in place to avoid file lock issues during teardown.
    }

    [SkippableFact]
    public async Task WebAuthenticator_redirect_roundtrip_completes()
    {
        Skip.IfNot(IsEnabled(), "Set COREIDENT_MAUI_E2E=1 to enable MAUI WebAuthenticator E2E tests.");

        var user = await CreateUserAsync(builder => builder
            .WithEmail("maui-e2e-user@test.local")
            .WithPassword("Pass123!"));

        var redirectUri = new Uri(_baseUri, "/callback").ToString();

        var client = await CreateClientAsync(builder => builder
            .WithClientId("maui-e2e-client")
            .AsPublicClient()
            .WithGrantTypes(GrantTypes.AuthorizationCode)
            .WithScopes(StandardScopes.OpenId, StandardScopes.Profile)
            .WithRedirectUris(redirectUri));

        var storageAdapter = new InMemoryMauiSecureStorageAdapter();
        var tokenStorage = new MauiSecureTokenStorage(storageAdapter, "coreident.tokens");
        var authenticator = new PlaywrightWebAuthenticatorAdapter(_playwrightFixture, user.Id, user.UserName);
        var browserLauncher = new MauiBrowserLauncher(authenticator);

        var options = new CoreIdentClientOptions
        {
            Authority = _baseUri.ToString(),
            ClientId = client.ClientId,
            RedirectUri = redirectUri,
            Scopes = [StandardScopes.OpenId, StandardScopes.Profile]
        };

        using var sut = new CoreIdent.Client.CoreIdentClient(options, _client, tokenStorage, browserLauncher);

        var result = await sut.LoginAsync();

        result.IsSuccess.ShouldBeTrue($"MAUI client should complete WebAuthenticator redirect roundtrip in a real browser. Error: {result.Error} {result.ErrorDescription}");
        sut.IsAuthenticated.ShouldBeTrue("Client should be authenticated after successful login.");

        var accessToken = await sut.GetAccessTokenAsync();
        accessToken.ShouldNotBeNullOrWhiteSpace("Access token should be available after login.");

        var storedTokens = await tokenStorage.GetTokensAsync();
        storedTokens.ShouldNotBeNull("Tokens should be persisted by MauiSecureTokenStorage.");
    }

    private static bool IsEnabled()
    {
        var value = Environment.GetEnvironmentVariable("COREIDENT_MAUI_E2E");
        return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase)
               || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
    }

    private static int GetEphemeralPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private async Task EnsureSeededAsync()
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();

        await db.Database.EnsureCreatedAsync();

        if (!await db.Scopes.AnyAsync())
        {
            db.Scopes.AddRange(SeededStandardScopes.All);
            await db.SaveChangesAsync();
        }
    }

    private async Task<CoreIdentUser> CreateUserAsync(Action<UserBuilder>? configure = null, CancellationToken ct = default)
    {
        using var scope = _services.CreateScope();

        var builder = new UserBuilder();
        configure?.Invoke(builder);

        var user = builder.Build();

        if (builder.Password is not null)
        {
            var hasher = scope.ServiceProvider.GetRequiredService<CoreIdent.Core.Services.IPasswordHasher>();
            user.PasswordHash = hasher.HashPassword(user, builder.Password);
        }

        var userStore = scope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IUserStore>();
        await userStore.CreateAsync(user, ct);

        if (builder.Claims.Count > 0)
        {
            await userStore.SetClaimsAsync(user.Id, builder.Claims, ct);
        }

        return user;
    }

    private async Task<CoreIdent.Core.Models.CoreIdentClient> CreateClientAsync(Action<ClientBuilder>? configure = null, CancellationToken ct = default)
    {
        using var scope = _services.CreateScope();

        var builder = new ClientBuilder();
        configure?.Invoke(builder);

        var client = builder.Build();

        if (!string.IsNullOrWhiteSpace(builder.Secret))
        {
            var hasher = scope.ServiceProvider.GetRequiredService<CoreIdent.Core.Services.IClientSecretHasher>();
            client.ClientSecretHash = hasher.HashSecret(builder.Secret);
        }

        var clientStore = scope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IClientStore>();
        await clientStore.CreateAsync(client, ct);

        return client;
    }

    private sealed class InMemoryMauiSecureStorageAdapter : IMauiSecureStorageAdapter
    {
        private readonly Dictionary<string, string> _storage = new(StringComparer.Ordinal);

        public Task SetAsync(string key, string value, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            _storage[key] = value;
            return Task.CompletedTask;
        }

        public Task<string?> GetAsync(string key, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            _storage.TryGetValue(key, out var value);
            return Task.FromResult<string?>(value);
        }

        public bool Remove(string key)
        {
            return _storage.Remove(key);
        }
    }

    private sealed class PlaywrightWebAuthenticatorAdapter : IMauiWebAuthenticatorAdapter
    {
        private readonly PlaywrightFixture _fixture;
        private readonly string _userId;
        private readonly string? _email;

        public PlaywrightWebAuthenticatorAdapter(PlaywrightFixture fixture, string userId, string? email)
        {
            ArgumentNullException.ThrowIfNull(fixture);
            ArgumentException.ThrowIfNullOrWhiteSpace(userId);

            _fixture = fixture;
            _userId = userId;
            _email = string.IsNullOrWhiteSpace(email) ? null : email;
        }

        public async Task<AuthenticatorResponse> AuthenticateAsync(Uri url, Uri callbackUri, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(url);
            ArgumentNullException.ThrowIfNull(callbackUri);

            var context = await _fixture.CreateContextAsync("MauiWebAuthenticatorE2E");

            try
            {
                var headers = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["X-Test-User-Id"] = _userId
                };

                if (!string.IsNullOrWhiteSpace(_email))
                {
                    headers["X-Test-User-Email"] = _email;
                }

                await context.SetExtraHTTPHeadersAsync(headers);

                var page = await context.NewPageAsync();

                await page.GotoAsync(url.ToString(), new PageGotoOptions
                {
                    WaitUntil = WaitUntilState.DOMContentLoaded
                });

                await page.WaitForURLAsync($"{callbackUri}**", new PageWaitForURLOptions
                {
                    Timeout = 120_000
                });

                var redirectUrl = page.Url;
                var parameters = ParseQuery(redirectUrl);

                return new AuthenticatorResponse(parameters, AccessToken: null);
            }
            finally
            {
                await context.Tracing.StopAsync();
                await context.CloseAsync();
            }
        }
    }

    private static Dictionary<string, string> ParseQuery(string url)
    {
        var uri = new Uri(url);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var trimmed = uri.Query.TrimStart('?');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return result;
        }

        foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var kvp = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(kvp[0]);
            var value = kvp.Length == 2 ? Uri.UnescapeDataString(kvp[1]) : string.Empty;
            result[key] = value;
        }

        return result;
    }
}
