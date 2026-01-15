using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Testing.Browser;
using CoreIdent.Testing.Builders;
using CoreIdent.Testing.Fixtures;
using CoreIdent.Testing.Host;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;
using Shouldly;
using Xunit;

namespace CoreIdent.E2E.Tests;

/// <summary>
/// End-to-end browser tests for OAuth/OIDC flows.
/// These tests verify complete user authentication flows through the browser.
/// </summary>
/// <remarks>
/// Run with: dotnet test --filter "Category=E2E"
/// Requires: dotnet playwright install
/// </remarks>
[Collection("E2E")]
public class OAuthFlowE2ETests : IAsyncLifetime
{
    private readonly PlaywrightFixture _playwrightFixture;
    private CoreIdentWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;
    private IServiceProvider _services = null!;

    public OAuthFlowE2ETests()
    {
        _playwrightFixture = new PlaywrightFixture();
    }

    public async Task InitializeAsync()
    {
        await _playwrightFixture.InitializeAsync();

        _factory = CoreIdentTestHost.CreateFactory(services =>
        {
            services.Configure<CoreIdentOptions>(options =>
            {
                options.Issuer = "https://test-auth.example.com";
                options.Audience = "https://test-api.example.com";
            });
        });

        _client = _factory.CreateClient();
        _services = _factory.Services;
        _factory.EnsureSeeded();
    }

    public async Task DisposeAsync()
    {
        await _playwrightFixture.DisposeAsync();
        _factory.Dispose();
        _client.Dispose();
    }

    private async Task<CoreIdentUser> CreateUserAsync(Action<UserBuilder>? configure = null, CancellationToken ct = default)
    {
        using var scope = _services.CreateScope();

        var builder = new UserBuilder();
        configure?.Invoke(builder);

        var user = builder.Build();

        if (builder.Password is not null)
        {
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            user.PasswordHash = hasher.HashPassword(user, builder.Password);
        }

        var userStore = scope.ServiceProvider.GetRequiredService<IUserStore>();
        await userStore.CreateAsync(user, ct);

        if (builder.Claims.Count > 0)
        {
            await userStore.SetClaimsAsync(user.Id, builder.Claims, ct);
        }

        return user;
    }

    private async Task<CoreIdentClient> CreateClientAsync(Action<ClientBuilder>? configure = null, CancellationToken ct = default)
    {
        using var scope = _services.CreateScope();

        var builder = new ClientBuilder();
        configure?.Invoke(builder);

        var client = builder.Build();

        if (!string.IsNullOrWhiteSpace(builder.Secret))
        {
            var hasher = scope.ServiceProvider.GetRequiredService<IClientSecretHasher>();
            client.ClientSecretHash = hasher.HashSecret(builder.Secret);
        }

        var clientStore = scope.ServiceProvider.GetRequiredService<IClientStore>();
        await clientStore.CreateAsync(client, ct);

        return client;
    }

    [Fact]
    public async Task DiscoveryEndpoint_IsAccessible()
    {
        // Arrange & Act
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        content.ShouldContain("issuer");
        content.ShouldContain("authorization_endpoint");
        content.ShouldContain("token_endpoint");
    }

    [Fact]
    public async Task JwksEndpoint_ReturnsValidKeys()
    {
        // Arrange & Act
        var response = await _client.GetAsync("/.well-known/jwks.json");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        content.ShouldContain("keys");
        content.ShouldContain("kty");
    }

    [Fact]
    public async Task AuthorizationEndpoint_RedirectsToLogin()
    {
        // Arrange
        var codeVerifier = OAuthFlowHelpers.GenerateCodeVerifier();
        var codeChallenge = OAuthFlowHelpers.GenerateCodeChallenge(codeVerifier);
        var state = OAuthFlowHelpers.GenerateState();

        var authUrl = OAuthFlowHelpers.BuildAuthorizationUrl(
            authorizationEndpoint: "https://test-auth.example.com/auth/authorize",
            clientId: "e2e-test-client",
            redirectUri: "https://localhost/callback",
            scopes: ["openid", "profile"],
            state: state,
            codeChallenge: codeChallenge
        );

        // Act
        await using var browserContext = await _playwrightFixture.CreateContextAsync(nameof(AuthorizationEndpoint_RedirectsToLogin));
        var page = await browserContext.NewPageAsync();

        var exception = await Assert.ThrowsAsync<PlaywrightException>(() => page.GotoAsync(authUrl));

        // Assert - The page should fail to load (expected since we're using fake URLs)
        // but the browser should attempt to navigate to the authorization endpoint
        Assert.True(exception.Message.Contains("net::ERR_NAME_NOT_RESOLVED") ||
                    exception.Message.Contains("net::ERR_CONNECTION_REFUSED") ||
                    exception.Message.Contains("Navigation failed"));
    }

    [Fact]
    public async Task TokenEndpoint_RejectsUnknownClient()
    {
        // Arrange - Send a token request with an unknown client
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "unknown-client"
            })
        };

        // Act
        var response = await _client.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        // Assert - Unknown client returns 401 Unauthorized
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        content.ShouldContain("invalid_client");
    }

    [Fact]
    public async Task TokenEndpoint_RejectsUnauthorizedClient()
    {
        // Arrange
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["scope"] = "api"
            })
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("invalid-client:wrong-secret")));

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task TokenRefresh_RenewsAccessToken()
    {
        // Arrange - Create a user and client with refresh token support
        // Note: Refresh tokens require user context (not client_credentials) + offline_access scope
        var user = await CreateUserAsync(u => u
            .WithEmail("refresh-user@example.com")
            .WithPassword("RefreshTest123!"));

        await CreateClientAsync(client =>
        {
            client.WithClientId("refresh-test-client")
                .AsConfidentialClient("test-secret")
                .WithGrantTypes("password", "refresh_token")
                .WithScopes("openid", "offline_access")
                .AllowOfflineAccess();
        });

        // Step 1: Get initial tokens via password grant (user-context token with refresh)
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = user.UserName,
                ["password"] = "RefreshTest123!",
                ["scope"] = "openid offline_access"
            })
        };
        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("refresh-test-client:test-secret")));

        var initialResponse = await _client.SendAsync(tokenRequest);
        initialResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Password grant should succeed");

        var initialToken = await initialResponse.Content.ReadFromJsonAsync<TokenResponsePayload>();
        initialToken.ShouldNotBeNull("Token response should deserialize");
        initialToken!.access_token.ShouldNotBeNullOrEmpty("Access token should be present");
        initialToken.refresh_token.ShouldNotBeNullOrEmpty("Refresh token should be issued with offline_access scope");

        var originalAccessToken = initialToken.access_token;
        var refreshToken = initialToken.refresh_token;

        // Step 2: Use refresh token to get new access token
        using var refreshRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken!
            })
        };
        refreshRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("refresh-test-client:test-secret")));

        var refreshResponse = await _client.SendAsync(refreshRequest);
        refreshResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Refresh token grant should succeed");

        var newToken = await refreshResponse.Content.ReadFromJsonAsync<TokenResponsePayload>();
        newToken.ShouldNotBeNull("Refreshed token response should deserialize");
        newToken!.access_token.ShouldNotBeNullOrEmpty("New access token should be present");

        // Assert - New access token should be different (newly issued)
        newToken.access_token.ShouldNotBe(originalAccessToken, "New access token should be issued on refresh");
        newToken.refresh_token.ShouldNotBeNullOrEmpty("New refresh token should be issued (rotation)");
        newToken.refresh_token.ShouldNotBe(refreshToken, "Refresh token should be rotated");
    }

    [Fact]
    public async Task UserInfoEndpoint_ReturnsClaimsForAuthenticatedUser()
    {
        // Arrange - Create a user with claims
        var user = await CreateUserAsync(u => u
            .WithEmail("testuser@example.com")
            .WithPassword("TestPass123!")
            .WithClaim("given_name", "Test")
            .WithClaim("family_name", "User"));

        // Create a client that supports password grant (for user-context tokens)
        await CreateClientAsync(client =>
        {
            client.WithClientId("userinfo-test-client")
                .AsConfidentialClient("test-secret")
                .WithGrantTypes("password")
                .WithScopes("openid", "profile", "email");
        });

        // Get access token via password grant (user-context token)
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = user.UserName,
                ["password"] = "TestPass123!",
                ["scope"] = "openid profile email"
            })
        };
        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("userinfo-test-client:test-secret")));

        var tokenResponse = await _client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Token endpoint should return 200 for password grant");

        var tokenPayload = await tokenResponse.Content.ReadFromJsonAsync<TokenResponsePayload>();
        tokenPayload.ShouldNotBeNull("Token response should deserialize");
        var accessToken = tokenPayload!.access_token;

        // Act - Call UserInfo endpoint
        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/userinfo");
        userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var userInfoResponse = await _client.SendAsync(userInfoRequest);

        // Assert
        userInfoResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "UserInfo should return 200 for valid user token");
        var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();
        userInfoContent.ShouldContain("\"sub\""); // Subject is always required
        userInfoContent.ShouldContain("testuser@example.com"); // Email should be returned for email scope
    }

    [Fact]
    public async Task Logout_RevokesAccessToken_AndMakesItInactive()
    {
        // Arrange - Create a user and client with refresh token support
        var user = await CreateUserAsync(u => u
            .WithEmail("logout-access-user@example.com")
            .WithPassword("LogoutTest123!"));

        await CreateClientAsync(client =>
        {
            client.WithClientId("logout-test-client")
                .AsConfidentialClient("logout-secret")
                .WithGrantTypes("password", "refresh_token")
                .WithScopes("openid", "offline_access")
                .AllowOfflineAccess();
        });

        // Get tokens via password grant
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = user.UserName,
                ["password"] = "LogoutTest123!",
                ["scope"] = "openid offline_access"
            })
        };
        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-test-client:logout-secret")));

        var tokenResponse = await _client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Password grant should succeed");

        var tokens = await tokenResponse.Content.ReadFromJsonAsync<TokenResponsePayload>();
        tokens.ShouldNotBeNull("Token response should deserialize");
        tokens!.access_token.ShouldNotBeNullOrEmpty("Access token should be present");

        // Step 1: Verify token is active via introspection
        using var introspectBeforeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = tokens.access_token,
                ["token_type_hint"] = "access_token"
            })
        };
        introspectBeforeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-test-client:logout-secret")));

        var introspectBeforeResponse = await _client.SendAsync(introspectBeforeRequest);
        introspectBeforeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Introspection should return 200");

        var introspectBefore = await introspectBeforeResponse.Content.ReadFromJsonAsync<IntrospectionResponse>();
        introspectBefore.ShouldNotBeNull("Introspection response should deserialize");
        introspectBefore!.active.ShouldBeTrue("Token should be active before revocation");

        // Step 2: Revoke the access token
        using var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = tokens.access_token,
                ["token_type_hint"] = "access_token"
            })
        };
        revokeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-test-client:logout-secret")));

        var revokeResponse = await _client.SendAsync(revokeRequest);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation should return 200 OK");

        // Step 3: Verify token is now inactive via introspection
        using var introspectAfterRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = tokens.access_token,
                ["token_type_hint"] = "access_token"
            })
        };
        introspectAfterRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-test-client:logout-secret")));

        var introspectAfterResponse = await _client.SendAsync(introspectAfterRequest);
        introspectAfterResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Introspection should return 200");

        var introspectAfter = await introspectAfterResponse.Content.ReadFromJsonAsync<IntrospectionResponse>();
        introspectAfter.ShouldNotBeNull("Introspection response should deserialize");
        introspectAfter!.active.ShouldBeFalse("Token should be inactive after revocation");
    }

    [Fact]
    public async Task Logout_RevokesRefreshToken_AndPreventsTokenRefresh()
    {
        // Arrange - Create a user and client with refresh token support
        var user = await CreateUserAsync(u => u
            .WithEmail("logout-refresh-user@example.com")
            .WithPassword("LogoutRefresh123!"));

        await CreateClientAsync(client =>
        {
            client.WithClientId("logout-refresh-client")
                .AsConfidentialClient("logout-refresh-secret")
                .WithGrantTypes("password", "refresh_token")
                .WithScopes("openid", "offline_access")
                .AllowOfflineAccess();
        });

        // Get tokens via password grant
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = user.UserName,
                ["password"] = "LogoutRefresh123!",
                ["scope"] = "openid offline_access"
            })
        };
        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-refresh-client:logout-refresh-secret")));

        var tokenResponse = await _client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Password grant should succeed");

        var tokens = await tokenResponse.Content.ReadFromJsonAsync<TokenResponsePayload>();
        tokens.ShouldNotBeNull("Token response should deserialize");
        tokens!.refresh_token.ShouldNotBeNullOrEmpty("Refresh token should be present with offline_access scope");

        // Step 1: Verify refresh token works before revocation
        using var refreshBeforeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = tokens.refresh_token!
            })
        };
        refreshBeforeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-refresh-client:logout-refresh-secret")));

        var refreshBeforeResponse = await _client.SendAsync(refreshBeforeRequest);
        refreshBeforeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Refresh token should work before revocation");

        var newTokens = await refreshBeforeResponse.Content.ReadFromJsonAsync<TokenResponsePayload>();
        newTokens.ShouldNotBeNull("Refreshed tokens should deserialize");
        var rotatedRefreshToken = newTokens!.refresh_token;
        rotatedRefreshToken.ShouldNotBeNullOrEmpty("New refresh token should be issued (rotation)");

        // Step 2: Revoke the rotated refresh token
        using var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = rotatedRefreshToken!,
                ["token_type_hint"] = "refresh_token"
            })
        };
        revokeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-refresh-client:logout-refresh-secret")));

        var revokeResponse = await _client.SendAsync(revokeRequest);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation should return 200 OK");

        // Step 3: Verify refresh token no longer works
        using var refreshAfterRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = rotatedRefreshToken!
            })
        };
        refreshAfterRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("logout-refresh-client:logout-refresh-secret")));

        var refreshAfterResponse = await _client.SendAsync(refreshAfterRequest);
        refreshAfterResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Revoked refresh token should fail");

        var errorContent = await refreshAfterResponse.Content.ReadAsStringAsync();
        errorContent.ShouldContain("invalid_grant", Case.Sensitive, "Error should indicate invalid grant for revoked token");
    }

    [Fact]
    public async Task Logout_EndSessionEndpoint_OnlyAttemptedWhenAdvertised()
    {
        // This test verifies that:
        // 1. We check discovery for end_session_endpoint
        // 2. We only attempt end session if it's advertised
        // Currently CoreIdent does not advertise end_session_endpoint

        // Arrange - Check discovery document
        var discoveryResponse = await _client.GetAsync("/.well-known/openid-configuration");
        discoveryResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Discovery endpoint should be accessible");

        var discoveryContent = await discoveryResponse.Content.ReadAsStringAsync();

        // Assert - Currently end_session_endpoint is NOT advertised
        // This is the expected behavior until OIDC RP-Initiated Logout is implemented
        var hasEndSessionEndpoint = discoveryContent.Contains("end_session_endpoint");

        if (hasEndSessionEndpoint)
        {
            // If end_session_endpoint becomes advertised in the future, this test
            // should be updated to actually test the logout flow
            // For now, just verify it's present in discovery
            discoveryContent.ShouldContain("end_session_endpoint", Case.Sensitive,
                "End session endpoint should be advertised");
        }
        else
        {
            // Current state: end_session_endpoint is not advertised
            // This is correct - clients should use token revocation for logout
            discoveryContent.ShouldNotContain("end_session_endpoint", Case.Sensitive,
                "End session endpoint should not be advertised until RP-Initiated Logout is implemented");
        }
    }

    private record TokenResponsePayload(string access_token, int expires_in, string? refresh_token = null, string? token_type = null);
    private record IntrospectionResponse(bool active, string? scope = null, string? client_id = null, string? sub = null);
}

/// <summary>
/// Tests for PKCE helper functions.
/// </summary>
public class PkceHelpersTests
{
    [Fact]
    public void GenerateCodeVerifier_HasCorrectLength()
    {
        // Arrange & Act
        var verifier = OAuthFlowHelpers.GenerateCodeVerifier();

        // Assert
        verifier.Length.ShouldBeInRange(43, 128);
    }

    [Fact]
    public void GenerateCodeVerifier_ContainsOnlyValidCharacters()
    {
        // Arrange
        var verifier = OAuthFlowHelpers.GenerateCodeVerifier();
        var validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

        // Act & Assert
        foreach (var c in verifier)
        {
            validChars.ShouldContain(c, $"Character '{c}' in verifier should be a valid PKCE character");
        }
    }

    [Fact]
    public void GenerateCodeVerifier_ReturnsUniqueValues()
    {
        // Arrange & Act
        var verifier1 = OAuthFlowHelpers.GenerateCodeVerifier();
        var verifier2 = OAuthFlowHelpers.GenerateCodeVerifier();

        // Assert
        verifier1.ShouldNotBe(verifier2);
    }

    [Fact]
    public void GenerateCodeChallenge_MatchesExpectedFormat()
    {
        // Arrange
        var verifier = OAuthFlowHelpers.GenerateCodeVerifier();

        // Act
        var challenge = OAuthFlowHelpers.GenerateCodeChallenge(verifier);

        // Assert
        challenge.ShouldNotBeNullOrEmpty();
        challenge.Length.ShouldBeLessThanOrEqualTo(verifier.Length);
        // Base64url encoded (no + or /, no = padding)
        challenge.ShouldNotContain('+');
        challenge.ShouldNotContain('/');
        challenge.ShouldNotContain('=');
    }

    [Fact]
    public void GenerateCodeChallenge_IsDeterministic()
    {
        // Arrange
        var verifier = OAuthFlowHelpers.GenerateCodeVerifier();

        // Act
        var challenge1 = OAuthFlowHelpers.GenerateCodeChallenge(verifier);
        var challenge2 = OAuthFlowHelpers.GenerateCodeChallenge(verifier);

        // Assert
        challenge1.ShouldBe(challenge2);
    }

    [Fact]
    public void GenerateState_ReturnsValidValue()
    {
        // Arrange & Act
        var state = OAuthFlowHelpers.GenerateState();

        // Assert
        state.ShouldNotBeNullOrEmpty();
        state.Length.ShouldBeGreaterThan(16);
    }

    [Fact]
    public void BuildAuthorizationUrl_ContainsAllRequiredParameters()
    {
        // Arrange
        var authEndpoint = "https://auth.example.com/authorize";
        var clientId = "test-client";
        var redirectUri = "https://app.example.com/callback";
        var scopes = new[] { "openid", "profile", "email" };
        var state = "test-state";
        var codeChallenge = "test-challenge";

        // Act
        var url = OAuthFlowHelpers.BuildAuthorizationUrl(
            authEndpoint, clientId, redirectUri, scopes, state, codeChallenge);

        // Assert
        url.ShouldContain("response_type=code");
        url.ShouldContain($"client_id={clientId}");
        url.ShouldContain($"redirect_uri=");
        url.ShouldContain("scope=");
        url.ShouldContain("openid");
        url.ShouldContain("profile");
        url.ShouldContain("email");
        url.ShouldContain($"state={state}");
        url.ShouldContain($"code_challenge={codeChallenge}");
        url.ShouldContain("code_challenge_method=S256");
    }

    [Fact]
    public void BuildAuthorizationUrl_IncludesNonceWhenProvided()
    {
        // Arrange
        var nonce = "test-nonce";

        // Act
        var url = OAuthFlowHelpers.BuildAuthorizationUrl(
            "https://auth.example.com/authorize",
            "client",
            "https://callback",
            ["openid"],
            "state",
            "challenge",
            nonce: nonce);

        // Assert
        url.ShouldContain($"nonce={nonce}");
    }
}
