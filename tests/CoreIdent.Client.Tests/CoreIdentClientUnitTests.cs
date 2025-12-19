using System.Net;
using System.Security.Claims;
using System.Text.Json;
using CoreIdent.Client;
using Microsoft.Extensions.Time.Testing;
using Shouldly;
using Xunit;

namespace CoreIdent.Client.Tests;

public sealed class CoreIdentClientUnitTests
{
    [Fact]
    public async Task LoginAsync_rejects_state_mismatch()
    {
        var handler = new StubHttpMessageHandler();
        var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://authority.example")
        };

        handler.Discovery = new DiscoveryDocument
        {
            AuthorizationEndpoint = "https://authority.example/auth/authorize",
            TokenEndpoint = "https://authority.example/auth/token"
        };

        var launcher = new StubBrowserLauncher("https://client.example/cb?code=abc&state=wrong");

        var sut = new global::CoreIdent.Client.CoreIdentClient(
            new CoreIdentClientOptions
            {
                Authority = "https://authority.example",
                ClientId = "client",
                RedirectUri = "https://client.example/cb",
                Scopes = ["openid"]
            },
            httpClient: http,
            tokenStorage: new InMemoryTokenStorage(),
            browserLauncher: launcher);

        var result = await sut.LoginAsync();

        result.IsSuccess.ShouldBeFalse("Login should fail when state does not match.");
        result.Error.ShouldBe("invalid_state", "Login failure should indicate invalid_state.");
    }

    [Fact]
    public async Task GetAccessTokenAsync_refreshes_when_within_threshold()
    {
        var time = new FakeTimeProvider();
        var now = time.GetUtcNow();

        var handler = new StubHttpMessageHandler();
        var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://authority.example")
        };

        handler.Discovery = new DiscoveryDocument
        {
            TokenEndpoint = "https://authority.example/auth/token"
        };

        handler.TokenResponse = new OAuthTokenResponse
        {
            AccessToken = "new-access",
            TokenType = "Bearer",
            ExpiresIn = 3600,
            RefreshToken = "new-refresh",
            Scope = "openid"
        };

        var storage = new CapturingTokenStorage();

        await storage.StoreTokensAsync(new TokenSet
        {
            AccessToken = "old-access",
            RefreshToken = "old-refresh",
            ExpiresAtUtc = now.AddMinutes(1)
        });

        var sut = new global::CoreIdent.Client.CoreIdentClient(
            new CoreIdentClientOptions
            {
                Authority = "https://authority.example",
                ClientId = "client",
                RedirectUri = "https://client.example/cb",
                TokenRefreshThreshold = TimeSpan.FromMinutes(5)
            },
            httpClient: http,
            tokenStorage: storage,
            browserLauncher: new StubBrowserLauncher("https://client.example/cb?code=abc&state=xyz"),
            timeProvider: time);

        var token = await sut.GetAccessTokenAsync();

        token.ShouldBe("new-access", "Client should refresh when access token is within threshold.");
        handler.TokenRequests.ShouldBe(1, "Client should perform one token request (refresh).");
    }

    [Fact]
    public async Task GetAccessTokenAsync_sends_dpop_header_when_enabled()
    {
        var time = new FakeTimeProvider();
        var now = time.GetUtcNow();

        var handler = new StubHttpMessageHandler();
        var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://authority.example")
        };

        handler.Discovery = new DiscoveryDocument
        {
            TokenEndpoint = "https://authority.example/auth/token"
        };

        handler.TokenResponse = new OAuthTokenResponse
        {
            AccessToken = "new-access",
            TokenType = "Bearer",
            ExpiresIn = 3600,
            RefreshToken = "new-refresh",
            Scope = "openid"
        };

        var storage = new CapturingTokenStorage();

        await storage.StoreTokensAsync(new TokenSet
        {
            AccessToken = "old-access",
            RefreshToken = "old-refresh",
            ExpiresAtUtc = now.AddMinutes(1)
        });

        var sut = new global::CoreIdent.Client.CoreIdentClient(
            new CoreIdentClientOptions
            {
                Authority = "https://authority.example",
                ClientId = "client",
                RedirectUri = "https://client.example/cb",
                TokenRefreshThreshold = TimeSpan.FromMinutes(5),
                UseDPoP = true
            },
            httpClient: http,
            tokenStorage: storage,
            browserLauncher: new StubBrowserLauncher("https://client.example/cb?code=abc&state=xyz"),
            timeProvider: time);

        var token = await sut.GetAccessTokenAsync();

        token.ShouldBe("new-access", "Client should refresh and return the new access token.");
        handler.TokenRequests.ShouldBe(1, "Client should perform one token request (refresh).");
        handler.LastTokenRequestDpop.ShouldNotBeNull("Token request should include a DPoP header when UseDPoP=true.");
        handler.LastTokenRequestDpop!.ShouldNotBeNullOrWhiteSpace("DPoP header value should not be empty.");
        handler.LastTokenRequestDpop!.Split('.', StringSplitOptions.RemoveEmptyEntries).Length.ShouldBe(3, "DPoP proof should be a compact JWT (3 segments).");
    }

    [Fact]
    public async Task GetUserAsync_surfaces_delegated_and_role_claims_from_userinfo()
    {
        var handler = new StubHttpMessageHandler();
        var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://authority.example")
        };

        handler.Discovery = new DiscoveryDocument
        {
            UserInfoEndpoint = "https://authority.example/auth/userinfo"
        };

        handler.UserInfoResponseJson = "{" +
            "\"sub\":\"user-1\"," +
            "\"email\":\"alice@example.com\"," +
            "\"delegated_sub\":\"admin-1\"," +
            "\"roles\":[\"reader\",\"writer\"]," +
            "\"http://schemas.microsoft.com/ws/2008/06/identity/claims/role\":[\"admin\"]" +
            "}";

        var storage = new CapturingTokenStorage();
        await storage.StoreTokensAsync(new TokenSet
        {
            AccessToken = "access-token",
            RefreshToken = null,
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });

        var sut = new global::CoreIdent.Client.CoreIdentClient(
            new CoreIdentClientOptions
            {
                Authority = "https://authority.example",
                ClientId = "client",
                RedirectUri = "https://client.example/cb",
                Scopes = ["openid", "profile", "email"]
            },
            httpClient: http,
            tokenStorage: storage,
            browserLauncher: new StubBrowserLauncher("https://client.example/cb?code=abc&state=xyz"));

        var principal = await sut.GetUserAsync();

        principal.ShouldNotBeNull();
        principal!.FindFirst("delegated_sub")?.Value.ShouldBe("admin-1");
        principal.Claims.Where(c => c.Type == "roles").Select(c => c.Value).OrderBy(x => x).ToArray()
            .ShouldBe(new[] { "reader", "writer" });

        principal.IsInRole("admin").ShouldBeTrue();
        principal.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "admin").ShouldBeTrue();
    }

    private sealed class StubBrowserLauncher(string responseUrl) : IBrowserLauncher
    {
        public Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default)
        {
            return Task.FromResult(BrowserResult.Success(responseUrl));
        }
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

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        public DiscoveryDocument? Discovery { get; set; }

        public OAuthTokenResponse? TokenResponse { get; set; }

        public string? UserInfoResponseJson { get; set; }

        public int TokenRequests { get; private set; }

        public string? LastTokenRequestDpop { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri is null)
            {
                throw new InvalidOperationException("RequestUri is required.");
            }

            var path = request.RequestUri.AbsolutePath;

            if (path.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
            {
                var json = JsonSerializer.Serialize(Discovery, new JsonSerializerOptions(JsonSerializerDefaults.Web));
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                });
            }

            if (path.EndsWith("/auth/userinfo", StringComparison.Ordinal))
            {
                if (string.IsNullOrWhiteSpace(UserInfoResponseJson))
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(UserInfoResponseJson)
                });
            }

            if (path.EndsWith("/auth/token", StringComparison.Ordinal))
            {
                TokenRequests++;
                LastTokenRequestDpop = request.Headers.TryGetValues("DPoP", out var values) ? values.FirstOrDefault() : null;
                var json = JsonSerializer.Serialize(TokenResponse, new JsonSerializerOptions(JsonSerializerDefaults.Web));
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
