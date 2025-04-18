using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Responses;
using CoreIdent.TestHost.Setup;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using CoreIdent.Core.Services;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests;

[Collection("Database test collection")]
public class ClientCredentialsFlowTests : IClassFixture<TestSetupFixture>
{
    private readonly TestSetupFixture _fixture;
    private readonly HttpClient _client;
    private const string TokenEndpointPath = "/auth/token"; // Assuming default path

    public ClientCredentialsFlowTests(TestSetupFixture fixture)
    {
        _fixture = fixture;
        _client = _fixture.CreateClient();
    }

    private async Task SetupTestClient(string clientId, string clientSecret, string? scope = null, bool enabled = true, List<string>? allowedGrantTypes = null)
    {
        await using var dbContext = _fixture.CreateDbContext();

        var client = await dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client != null)
        {
            dbContext.Clients.Remove(client); // Remove existing to ensure clean state
            await dbContext.SaveChangesAsync();
        }

        var hasher = _fixture.GetRequiredService<IPasswordHasher>();
        var hashedSecret = hasher.HashPassword(null, clientSecret);

        client = new CoreIdentClient
        {
            ClientId = clientId,
            ClientName = $"{clientId}-name",
            Enabled = enabled,
            AllowedGrantTypes = allowedGrantTypes ?? new List<string> { "client_credentials" },
            AllowedScopes = scope != null ? new List<string> { scope } : new List<string>(),
            ClientSecrets = new List<CoreIdentClientSecret> { new CoreIdentClientSecret { Value = hashedSecret } },
            AccessTokenLifetime = 3600,
            RequirePkce = false,
            AllowOfflineAccess = false // Typically false for client credentials
        };

        dbContext.Clients.Add(client);
        await dbContext.SaveChangesAsync();
    }

    private async Task SetupTestScope(string scopeName)
    {
        await using var dbContext = _fixture.CreateDbContext();
        var scope = await dbContext.Scopes.FirstOrDefaultAsync(s => s.Name == scopeName);
        if (scope == null)
        {
            dbContext.Scopes.Add(new CoreIdentScope { Name = scopeName, DisplayName = scopeName, Enabled = true });
            await dbContext.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task ClientCredentials_WithValidClientAndSecret_UsingBasicAuth_ReturnsToken()
    {
        // Arrange
        var clientId = "cc-client-1";
        var clientSecret = "cc-secret-1";
        await SetupTestClient(clientId, clientSecret);
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var responseString = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        tokenResponse.ShouldNotBeNull();
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace();
        tokenResponse.TokenType.ShouldBe("Bearer");
        tokenResponse.ExpiresIn.ShouldBeGreaterThan(0);
        tokenResponse.RefreshToken.ShouldBeNull(); // No refresh token for client credentials
        tokenResponse.IdToken.ShouldBeNull();
        tokenResponse.Scope.ShouldBeNullOrEmpty(); // No scope requested
    }

    [Fact]
    public async Task ClientCredentials_WithValidClientAndSecret_UsingRequestBody_ReturnsToken()
    {
        // Arrange
        var clientId = "cc-client-2";
        var clientSecret = "cc-secret-2";
        await SetupTestClient(clientId, clientSecret);
        _client.DefaultRequestHeaders.Authorization = null; // Ensure Basic auth is not used

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", clientId },
            { "client_secret", clientSecret }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var responseString = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        tokenResponse.ShouldNotBeNull();
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task ClientCredentials_WithValidClientAndSecret_AndValidScope_ReturnsTokenWithScope()
    {
        // Arrange
        var clientId = "cc-client-3";
        var clientSecret = "cc-secret-3";
        var scope = "api.read";
        await SetupTestScope(scope);
        await SetupTestClient(clientId, clientSecret, scope: scope);

        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "scope", scope }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var responseString = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        tokenResponse.ShouldNotBeNull();
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace();
        tokenResponse.Scope.ShouldBe(scope);
    }

    [Fact]
    public async Task ClientCredentials_WithInvalidSecret_ReturnsInvalidClient()
    {
        // Arrange
        var clientId = "cc-client-4";
        var clientSecret = "cc-secret-4";
        await SetupTestClient(clientId, clientSecret);
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:wrong-secret"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe("invalid_client");
    }

    [Fact]
    public async Task ClientCredentials_WithUnknownClient_ReturnsInvalidClient()
    {
        // Arrange
        var clientId = "unknown-cc-client";
        var clientSecret = "cc-secret-5";
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe("invalid_client");
    }

    [Fact]
    public async Task ClientCredentials_WithDisabledClient_ReturnsInvalidClient()
    {
        // Arrange
        var clientId = "disabled-cc-client";
        var clientSecret = "cc-secret-6";
        await SetupTestClient(clientId, clientSecret, enabled: false);
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe("invalid_client");
    }

    [Fact]
    public async Task ClientCredentials_WithoutGrantType_ReturnsInvalidRequest()
    {
         // Arrange
        var clientId = "cc-client-7";
        var clientSecret = "cc-secret-7";
        await SetupTestClient(clientId, clientSecret);
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            // Missing grant_type
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe("invalid_request");
    }

    [Fact]
    public async Task ClientCredentials_WithIncorrectGrantType_ReturnsUnsupportedGrantType()
    {
        // Arrange
        var clientId = "cc-client-8";
        var clientSecret = "cc-secret-8";
        await SetupTestClient(clientId, clientSecret);
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "password" } // Incorrect grant type
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe("unsupported_grant_type");
    }

     [Fact]
    public async Task ClientCredentials_WithScopeNotAllowedForClient_ReturnsInvalidScope()
    {
        // Arrange
        var clientId = "cc-client-9";
        var clientSecret = "cc-secret-9";
        var allowedScope = "api.allowed";
        var requestedScope = "api.forbidden";
        await SetupTestScope(allowedScope);
        await SetupTestScope(requestedScope);
        await SetupTestClient(clientId, clientSecret, scope: allowedScope); // Only allow 'api.allowed'

        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "scope", requestedScope }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe("invalid_scope");
    }

    [Fact]
    public async Task ClientCredentials_WithClientNotAllowedGrantType_ReturnsUnauthorizedClient()
    {
        // Arrange
        var clientId = "cc-client-10";
        var clientSecret = "cc-secret-10";
        // Setup client but explicitly disallow 'client_credentials'
        await SetupTestClient(clientId, clientSecret, allowedGrantTypes: new List<string> { "authorization_code" });

        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" }
        });

        // Act
        var response = await _client.PostAsync(TokenEndpointPath, content);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe("unauthorized_client");
    }

    // Helper class for deserializing error responses
    private class ErrorResponse
    {
        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }
    }
} 