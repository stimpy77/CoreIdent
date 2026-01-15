using System.Net.Http.Json;
using System.Text.Json;
using CoreIdent.Testing.ExternalProviders;
using Shouldly;
using Xunit;
using Xunit.Sdk;

namespace CoreIdent.E2E.Tests;

/// <summary>
/// Smoke tests for OAuth/OIDC flows against external providers.
/// These tests verify CoreIdent client behavior matches external provider expectations.
/// </summary>
/// <remarks>
/// <para>
/// These tests require Docker and an external provider (Keycloak) to be running.
/// Skip these tests in CI unless the provider is available.
/// </para>
/// <para>
/// To run locally:
/// <code>
/// docker run -d --name keycloak -p 8080:8080 \
///   -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
///   quay.io/keycloak/keycloak:latest start-dev
/// </code>
/// </para>
/// </remarks>
[Collection("ExternalProvider")]
[Trait("Category", "ExternalProvider")]
public class ExternalProviderSmokeTests : IAsyncLifetime
{
    private KeycloakTestFixture _keycloak = null!;
    private bool _keycloakAvailable;

    public async Task InitializeAsync()
    {
        _keycloak = new KeycloakTestFixture();
        _keycloakAvailable = await _keycloak.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _keycloak.DisposeAsync();
    }

    [SkippableFact]
    public async Task Keycloak_DiscoveryEndpoint_ReturnsValidDocument()
    {
        Skip.IfNot(_keycloakAvailable, $"Keycloak is not available: {_keycloak.LastError ?? "Unknown"}");

        // Act
        var discovery = await _keycloak.GetDiscoveryDocumentAsync();

        // Assert
        var issuer = discovery.RootElement.GetProperty("issuer").GetString();
        issuer.ShouldNotBeNull();
        issuer.ShouldContain(_keycloak.RealmName);

        discovery.RootElement.GetProperty("authorization_endpoint").GetString()
            .ShouldNotBeNullOrEmpty();

        discovery.RootElement.GetProperty("token_endpoint").GetString()
            .ShouldNotBeNullOrEmpty();

        discovery.RootElement.GetProperty("jwks_uri").GetString()
            .ShouldNotBeNullOrEmpty();

        discovery.RootElement.GetProperty("userinfo_endpoint").GetString()
            .ShouldNotBeNullOrEmpty();
    }

    [SkippableFact]
    public async Task Keycloak_ClientCredentials_ReturnsValidToken()
    {
        Skip.IfNot(_keycloakAvailable, "Keycloak is not available");

        // Arrange
        var clientId = $"test-cc-{Guid.NewGuid():N}";
        var clientSecret = Guid.NewGuid().ToString("N");

        await _keycloak.CreateClientAsync(new KeycloakClientOptions
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            AllowClientCredentialsGrant = true,
            AllowAuthorizationCodeGrant = false
        });

        // Act
        var token = await _keycloak.GetClientCredentialsTokenAsync(clientId, clientSecret);

        // Assert
        token.AccessToken.ShouldNotBeNullOrEmpty();
        token.TokenType.ShouldBe("Bearer", StringCompareShould.IgnoreCase);
        token.ExpiresIn.ShouldBeGreaterThan(0);
    }

    [SkippableFact]
    public async Task Keycloak_PasswordGrant_ReturnsValidToken()
    {
        Skip.IfNot(_keycloakAvailable, "Keycloak is not available");

        // Arrange
        var clientId = $"test-pwd-{Guid.NewGuid():N}";
        var clientSecret = Guid.NewGuid().ToString("N");
        var username = $"user-{Guid.NewGuid():N}";
        var password = "TestPassword123!";

        await _keycloak.CreateClientAsync(new KeycloakClientOptions
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            AllowPasswordGrant = true,
            IsPublic = false
        });

        await _keycloak.CreateUserAsync(new KeycloakUserOptions
        {
            Username = username,
            Password = password
        });

        // Act
        var token = await _keycloak.GetTokenAsync(clientId, clientSecret, username, password);

        // Assert
        token.AccessToken.ShouldNotBeNullOrEmpty();
        token.RefreshToken.ShouldNotBeNullOrEmpty();
        token.IdToken.ShouldNotBeNullOrEmpty();
        token.TokenType.ShouldBe("Bearer", StringCompareShould.IgnoreCase);
    }

    [SkippableFact]
    public async Task Keycloak_RefreshToken_ReturnsNewAccessToken()
    {
        Skip.IfNot(_keycloakAvailable, "Keycloak is not available");

        // Arrange
        var clientId = $"test-refresh-{Guid.NewGuid():N}";
        var clientSecret = Guid.NewGuid().ToString("N");
        var username = $"user-{Guid.NewGuid():N}";
        var password = "TestPassword123!";

        await _keycloak.CreateClientAsync(new KeycloakClientOptions
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            AllowPasswordGrant = true
        });

        await _keycloak.CreateUserAsync(new KeycloakUserOptions
        {
            Username = username,
            Password = password
        });

        var initialToken = await _keycloak.GetTokenAsync(clientId, clientSecret, username, password);

        // Act
        var refreshedToken = await _keycloak.RefreshTokenAsync(
            clientId, clientSecret, initialToken.RefreshToken!);

        // Assert
        refreshedToken.AccessToken.ShouldNotBeNullOrEmpty();
        refreshedToken.AccessToken.ShouldNotBe(initialToken.AccessToken);
    }

    [SkippableFact]
    public async Task Keycloak_TokenIntrospection_ReturnsActiveToken()
    {
        Skip.IfNot(_keycloakAvailable, "Keycloak is not available");

        // Arrange
        var clientId = $"test-introspect-{Guid.NewGuid():N}";
        var clientSecret = Guid.NewGuid().ToString("N");

        await _keycloak.CreateClientAsync(new KeycloakClientOptions
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            AllowClientCredentialsGrant = true
        });

        var token = await _keycloak.GetClientCredentialsTokenAsync(clientId, clientSecret);

        // Act
        var introspection = await _keycloak.IntrospectTokenAsync(
            clientId, clientSecret, token.AccessToken);

        // Assert
        introspection.Active.ShouldBeTrue();
        introspection.ClientId.ShouldBe(clientId);
    }

    [SkippableFact]
    public async Task Keycloak_TokenRevocation_DeactivatesToken()
    {
        Skip.IfNot(_keycloakAvailable, "Keycloak is not available");

        // Arrange
        var clientId = $"test-revoke-{Guid.NewGuid():N}";
        var clientSecret = Guid.NewGuid().ToString("N");
        var username = $"user-{Guid.NewGuid():N}";
        var password = "TestPassword123!";

        await _keycloak.CreateClientAsync(new KeycloakClientOptions
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            AllowPasswordGrant = true
        });

        await _keycloak.CreateUserAsync(new KeycloakUserOptions
        {
            Username = username,
            Password = password
        });

        var token = await _keycloak.GetTokenAsync(clientId, clientSecret, username, password);

        // Verify token is active before revocation
        var beforeRevocation = await _keycloak.IntrospectTokenAsync(
            clientId, clientSecret, token.AccessToken);
        beforeRevocation.Active.ShouldBeTrue();

        // Act
        await _keycloak.RevokeTokenAsync(clientId, clientSecret, token.RefreshToken!);

        // Assert - After revoking refresh token, future refresh attempts should fail
        // Note: Access token may still be active until expiry in Keycloak's default config
        await Should.ThrowAsync<HttpRequestException>(async () =>
        {
            await _keycloak.RefreshTokenAsync(clientId, clientSecret, token.RefreshToken!);
        });
    }
}
