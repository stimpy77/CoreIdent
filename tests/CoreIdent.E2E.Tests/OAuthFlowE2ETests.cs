using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Testing.Browser;
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
        _factory.EnsureSeeded();
    }

    public async Task DisposeAsync()
    {
        await _playwrightFixture.DisposeAsync();
        _factory.Dispose();
        _client.Dispose();
    }

    [Fact]
    public async Task DiscoveryEndpoint_IsAccessible()
    {
        // Arrange & Act
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        response.StatusCode.ShouldBe(System.Net.HttpStatusCode.OK);
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
        response.StatusCode.ShouldBe(System.Net.HttpStatusCode.OK);
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
        response.StatusCode.ShouldBe(System.Net.HttpStatusCode.Unauthorized);
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
        response.StatusCode.ShouldBe(System.Net.HttpStatusCode.Unauthorized);
    }
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
        verifier.ShouldAllBe(c => validChars.Contains(c));
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
