using System.Net;
using CoreIdent.Client;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Microsoft.Extensions.Time.Testing;
using Shouldly;
using Xunit;

namespace CoreIdent.Client.Tests;

public sealed class CoreIdentClientIntegrationTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Full_login_flow_works_against_test_server()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("ac-client")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId, StandardScopes.Profile)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var tokenStorage = new CapturingTokenStorage();

        var client = new CoreIdent.Client.CoreIdentClient(
            new CoreIdentClientOptions
            {
                Authority = Client.BaseAddress!.ToString().TrimEnd('/'),
                ClientId = "ac-client",
                RedirectUri = redirectUri,
                Scopes = ["openid", "profile"]
            },
            httpClient: Client,
            tokenStorage: tokenStorage,
            browserLauncher: new TestBrowserLauncher(Client));

        var result = await client.LoginAsync();
        result.IsSuccess.ShouldBeTrue($"Login should succeed. Error: {result.Error} {result.ErrorDescription}");

        client.IsAuthenticated.ShouldBeTrue("Client should be authenticated after successful login.");

        var accessToken = await client.GetAccessTokenAsync();
        accessToken.ShouldNotBeNullOrWhiteSpace("Access token should be available.");

        var userPrincipal = await client.GetUserAsync();
        userPrincipal.ShouldNotBeNull("UserInfo should return a principal.");
        userPrincipal!.FindFirst("sub")?.Value.ShouldBe(user.Id, "UserInfo sub should match the authenticated user.");

        tokenStorage.Tokens.ShouldNotBeNull("Token storage should contain tokens after login.");
    }

    [Fact]
    public async Task Logout_clears_tokens()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("logout-client")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var tokenStorage = new CapturingTokenStorage();

        var client = new CoreIdent.Client.CoreIdentClient(
            new CoreIdentClientOptions
            {
                Authority = Client.BaseAddress!.ToString().TrimEnd('/'),
                ClientId = "logout-client",
                RedirectUri = redirectUri,
                Scopes = ["openid"]
            },
            httpClient: Client,
            tokenStorage: tokenStorage,
            browserLauncher: new TestBrowserLauncher(Client));

        (await client.LoginAsync()).IsSuccess.ShouldBeTrue("Precondition: login should succeed.");

        await client.LogoutAsync();

        client.IsAuthenticated.ShouldBeFalse("Client should not be authenticated after logout.");
        (await tokenStorage.GetTokensAsync()).ShouldBeNull("Logout should clear stored tokens.");
    }

    [Fact]
    public async Task Token_refresh_works_correctly()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("refresh-client")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken)
                .AllowOfflineAccess(true)
                .WithScopes(StandardScopes.OpenId, StandardScopes.Profile, StandardScopes.OfflineAccess)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var tokenStorage = new CapturingTokenStorage();
        var time = new FakeTimeProvider();

        var client = new CoreIdent.Client.CoreIdentClient(
            new CoreIdentClientOptions
            {
                Authority = Client.BaseAddress!.ToString().TrimEnd('/'),
                ClientId = "refresh-client",
                RedirectUri = redirectUri,
                Scopes = ["openid", "profile", "offline_access"],
                TokenRefreshThreshold = TimeSpan.FromMinutes(5)
            },
            httpClient: Client,
            tokenStorage: tokenStorage,
            browserLauncher: new TestBrowserLauncher(Client),
            timeProvider: time);

        (await client.LoginAsync()).IsSuccess.ShouldBeTrue("Precondition: login should succeed.");
        tokenStorage.Tokens.ShouldNotBeNull("Precondition: token storage should contain tokens after login.");
        tokenStorage.Tokens!.RefreshToken.ShouldNotBeNullOrWhiteSpace("Precondition: offline_access should yield a refresh token.");

        var initialAccessToken = tokenStorage.Tokens.AccessToken;
        initialAccessToken.ShouldNotBeNullOrWhiteSpace("Precondition: access token should be present.");

        // Advance time enough that the access token should be considered within the refresh threshold.
        time.Advance(TimeSpan.FromDays(1));

        var refreshedAccessToken = await client.GetAccessTokenAsync();

        refreshedAccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be available after refresh.");
        refreshedAccessToken.ShouldNotBe(initialAccessToken, "Access token should change after refresh.");
        client.IsAuthenticated.ShouldBeTrue("Client should remain authenticated after successful refresh.");
    }

    private sealed class CapturingTokenStorage : ISecureTokenStorage
    {
        public TokenSet? Tokens { get; private set; }

        public Task StoreTokensAsync(TokenSet tokens, CancellationToken ct = default)
        {
            Tokens = tokens;
            return Task.CompletedTask;
        }

        public Task<TokenSet?> GetTokensAsync(CancellationToken ct = default)
        {
            return Task.FromResult(Tokens);
        }

        public Task ClearTokensAsync(CancellationToken ct = default)
        {
            Tokens = null;
            return Task.CompletedTask;
        }
    }

    private sealed class TestBrowserLauncher(HttpClient http) : IBrowserLauncher
    {
        public async Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await http.SendAsync(req, ct);

            resp.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Authorize endpoint should redirect back to client.");

            resp.Headers.Location.ShouldNotBeNull("Authorize response should include Location.");

            return BrowserResult.Success(resp.Headers.Location!.ToString());
        }
    }
}
