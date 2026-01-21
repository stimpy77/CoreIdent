using System.Net;
using CoreIdent.Client;
using CoreIdent.Client.Maui;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Client.Maui.Tests;

public sealed class MauiClientIntegrationTests : CoreIdentTestFixture
{
    private CoreIdentUser _user = null!;
    private CoreIdent.Core.Models.CoreIdentClient _client = null!;
    private string _redirectUri = string.Empty;

    protected override async Task SeedDataAsync()
    {
        _user = await CreateUserAsync(builder => builder
            .WithEmail("maui-user@test.local")
            .WithPassword("Pass123!"));

        var baseAddress = Client.BaseAddress ?? throw new InvalidOperationException("Test host base address was not initialized.");
        _redirectUri = new Uri(baseAddress, "/callback").ToString();

        _client = await CreateClientAsync(builder => builder
            .WithClientId("maui-client")
            .AsPublicClient()
            .WithGrantTypes(GrantTypes.AuthorizationCode)
            .WithScopes(StandardScopes.OpenId, StandardScopes.Profile)
            .WithRedirectUris(_redirectUri));
    }

    [Fact]
    public async Task Headless_login_completes_and_tokens_persist()
    {
        var storageAdapter = new InMemoryMauiSecureStorageAdapter();
        var tokenStorage = new MauiSecureTokenStorage(storageAdapter, "coreident.tokens");
        var authenticator = new TestHeaderWebAuthenticatorAdapter(Client, _user.Id, _user.UserName);
        var browserLauncher = new MauiBrowserLauncher(authenticator);

        var options = new CoreIdentClientOptions
        {
            Authority = (Client.BaseAddress ?? throw new InvalidOperationException("Test host base address was not initialized.")).ToString(),
            ClientId = _client.ClientId,
            RedirectUri = _redirectUri,
            Scopes = [StandardScopes.OpenId, StandardScopes.Profile]
        };

        using var sut = new CoreIdentClient(options, Client, tokenStorage, browserLauncher);

        var result = await sut.LoginAsync();

        result.IsSuccess.ShouldBeTrue("MAUI client should complete authorization code flow against the test host.");
        sut.IsAuthenticated.ShouldBeTrue("Client should be authenticated after successful login.");

        var accessToken = await sut.GetAccessTokenAsync();
        accessToken.ShouldNotBeNullOrWhiteSpace("Access token should be available after login.");

        var storedTokens = await tokenStorage.GetTokensAsync();
        storedTokens.ShouldNotBeNull("Tokens should be persisted by MauiSecureTokenStorage.");
        storedTokens!.AccessToken.ShouldNotBeNullOrWhiteSpace("Stored tokens should include an access token.");
    }

    [Fact]
    public async Task Logout_clears_tokens_from_MauiSecureTokenStorage()
    {
        var storageAdapter = new InMemoryMauiSecureStorageAdapter();
        var tokenStorage = new MauiSecureTokenStorage(storageAdapter, "coreident.tokens");
        var authenticator = new TestHeaderWebAuthenticatorAdapter(Client, _user.Id, _user.UserName);
        var browserLauncher = new MauiBrowserLauncher(authenticator);

        var options = new CoreIdentClientOptions
        {
            Authority = (Client.BaseAddress ?? throw new InvalidOperationException("Test host base address was not initialized.")).ToString(),
            ClientId = _client.ClientId,
            RedirectUri = _redirectUri,
            Scopes = [StandardScopes.OpenId, StandardScopes.Profile]
        };

        using var sut = new CoreIdentClient(options, Client, tokenStorage, browserLauncher);

        (await sut.LoginAsync()).IsSuccess.ShouldBeTrue("Precondition: login should succeed.");

        await sut.LogoutAsync();

        sut.IsAuthenticated.ShouldBeFalse("Client should not be authenticated after logout.");
        (await tokenStorage.GetTokensAsync()).ShouldBeNull("Logout should clear tokens from MauiSecureTokenStorage.");
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

    private sealed class TestHeaderWebAuthenticatorAdapter : IMauiWebAuthenticatorAdapter
    {
        private readonly HttpClient _http;
        private readonly string _userId;
        private readonly string? _email;

        public TestHeaderWebAuthenticatorAdapter(HttpClient http, string userId, string? email)
        {
            ArgumentNullException.ThrowIfNull(http);
            ArgumentException.ThrowIfNullOrWhiteSpace(userId);

            _http = http;
            _userId = userId;
            _email = string.IsNullOrWhiteSpace(email) ? null : email;
        }

        public async Task<AuthenticatorResponse> AuthenticateAsync(Uri url, Uri callbackUri, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(url);
            ArgumentNullException.ThrowIfNull(callbackUri);

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("X-Test-User-Id", _userId);
            if (!string.IsNullOrWhiteSpace(_email))
            {
                request.Headers.TryAddWithoutValidation("X-Test-User-Email", _email);
            }

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther)
            {
                var location = response.Headers.Location?.ToString();
                if (string.IsNullOrWhiteSpace(location))
                {
                    throw new InvalidOperationException("Authorize response did not include a Location header.");
                }

                if (!location.StartsWith(callbackUri.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Authorize response did not redirect to the expected callback URI.");
                }

                var parameters = ParseQuery(location);
                return new AuthenticatorResponse(parameters, AccessToken: null);
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Authorize request failed. Status={(int)response.StatusCode} {response.ReasonPhrase}. Body={body}");
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
