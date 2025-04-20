using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Shouldly;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Xunit;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Collections.Generic;
using CoreIdent.TestHost;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;

namespace CoreIdent.Integration.Tests;

// Custom factory for Refresh Token tests
public class RefreshTokenTestWebApplicationFactory : WebApplicationFactory<Program>, IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly string _connectionString = $"DataSource=file:RefreshTests_{Guid.NewGuid()}?mode=memory&cache=shared";

    public RefreshTokenTestWebApplicationFactory()
    {
        _connection = new SqliteConnection(_connectionString);
        _connection.Open();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Remove default/conflicting DbContext registrations
            services.RemoveAll<DbContextOptions<CoreIdentDbContext>>();
            services.RemoveAll<CoreIdentDbContext>();

            // Register DbContext with our connection
            services.AddDbContext<CoreIdentDbContext>(options => options.UseSqlite(_connection), ServiceLifetime.Scoped);
            
            // Register EF Core stores
            services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();

            // Run migrations 
            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
            var logger = scope.ServiceProvider.GetRequiredService<ILogger<RefreshTokenTestWebApplicationFactory>>();
            try { db.Database.Migrate(); } catch (Exception ex) { logger.LogError(ex, "Migration failed"); throw; }
            
            // *** Add seeding logic here ***
            SeedRequiredClients(db, logger); 
        });
        builder.UseEnvironment("Development");
    }

    // *** Add the seeding method ***
    private void SeedRequiredClients(CoreIdentDbContext context, ILogger logger)
    {
        logger.LogInformation("Seeding required clients for RefreshToken tests...");
        const string passwordClient = "__password_flow__";

        if (!context.Clients.Any(c => c.ClientId == passwordClient))
        {
            logger.LogInformation("Client '{ClientId}' not found, adding.", passwordClient);
            context.Clients.Add(new CoreIdentClient
            {
                ClientId = passwordClient,
                ClientName = "Password Flow Client (Integration Tests)",
                Enabled = true,
                AllowedGrantTypes = new List<string> { "password" },
                AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access" },
                AllowOfflineAccess = true,
                AccessTokenLifetime = 3600,
                RefreshTokenUsage = TokenUsage.OneTimeOnly,
                RefreshTokenExpiration = TokenExpiration.Sliding,
                SlidingRefreshTokenLifetime = 2592000
            });

            try
            {
                context.SaveChanges();
                logger.LogInformation("Client '{ClientId}' seeded successfully.", passwordClient);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to seed client '{ClientId}'.", passwordClient);
                // Re-throw or handle as appropriate for test setup failure
                throw; 
            }
        }
        else
        {
             logger.LogInformation("Client '{ClientId}' already exists.", passwordClient);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _connection.Close(); _connection.Dispose(); }
        base.Dispose(disposing);
    }
}

/// <summary>
/// Integration tests for the /token/refresh endpoint.
/// </summary>
// Use the new custom factory
public class RefreshTokenEndpointTests : IClassFixture<RefreshTokenTestWebApplicationFactory>
{
    private readonly RefreshTokenTestWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public RefreshTokenEndpointTests(RefreshTokenTestWebApplicationFactory factory)
    {
        _factory = factory;
        _client = _factory.CreateClient(); 
    }

    private async Task<(string AccessToken, string RefreshToken)> RegisterAndLoginUser(string email, string password)
    {
        // Register user directly via service provider 
        // (assuming AddDbContext and AddCoreIdentEntityFrameworkStores are called in factory setup)
        using (var scope = _factory.Services.CreateScope())
        {
            var userStore = scope.ServiceProvider.GetRequiredService<IUserStore>();
            var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            var logger = scope.ServiceProvider.GetRequiredService<ILogger<RefreshTokenEndpointTests>>();
            
            var existingUser = await userStore.FindUserByUsernameAsync(email.ToUpperInvariant(), default);
            if (existingUser == null)
            {
                var user = new CoreIdentUser
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = email,
                    NormalizedUserName = email.ToUpperInvariant(),
                    PasswordHash = passwordHasher.HashPassword(null, password)
                };
                var result = await userStore.CreateUserAsync(user, default);
                if (result != StoreResult.Success)
                {
                    logger.LogError("Failed to create user {Email} in helper. Result: {Result}", email, result);
                    throw new InvalidOperationException($"Test setup failed: Could not create user {email}. Result: {result}");
                }
                logger.LogDebug("User {Email} created in helper.", email);
            }
            else
            {
                 logger.LogDebug("User {Email} already existed in helper.", email);
            }
        }

        // Login user
        var loginResponse = await _client.PostAsJsonAsync("/auth/login", new LoginRequest { Email = email, Password = password });
        loginResponse.EnsureSuccessStatusCode();

        // Explicitly qualify the type used for deserialization
        var tokenResponse = await loginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.Responses.TokenResponse>(); 
        tokenResponse.ShouldNotBeNull();
        tokenResponse.RefreshToken.ShouldNotBeNullOrEmpty();
        tokenResponse.AccessToken.ShouldNotBeNullOrEmpty();

        return (tokenResponse.AccessToken, tokenResponse.RefreshToken);
    }

    [Fact]
    public async Task RefreshToken_WithValidToken_ReturnsNewTokensAndInvalidatesOld()
    {
        // Arrange: Register and Login to get initial tokens
        var userEmail = $"refresh_user_{Guid.NewGuid()}@test.com";
        var userPassword = "ValidPassword123!";
        var (_, initialRefreshToken) = await RegisterAndLoginUser(userEmail, userPassword);

        var refreshRequest = new RefreshTokenRequest { RefreshToken = initialRefreshToken };

        // Act: Refresh the token (First time)
        var refreshPayload = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", initialRefreshToken! },
            { "client_id", "__password_flow__" } // Client ID is required for token endpoint
        };
        var refreshResponse1 = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(refreshPayload));

        // *** Log Raw JSON Response ***
        var rawJson = await refreshResponse1.Content.ReadAsStringAsync();
        _factory.Services.GetRequiredService<ILogger<RefreshTokenEndpointTests>>().LogInformation("Raw JSON response from /token/refresh: {RawJson}", rawJson);

        // Assert: First refresh is successful
        refreshResponse1.StatusCode.ShouldBe(HttpStatusCode.OK);
        var refreshedTokens1 = JsonSerializer.Deserialize<CoreIdent.Core.Models.Responses.TokenResponse>(rawJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); // Deserialize manually
        refreshedTokens1.ShouldNotBeNull();
        refreshedTokens1.RefreshToken.ShouldNotBeNullOrEmpty();
        refreshedTokens1.AccessToken.ShouldNotBeNullOrEmpty();
        refreshedTokens1.RefreshToken.ShouldNotBe(initialRefreshToken, "A new refresh token should be issued.");

        // Act: Try to use the FIRST token again (Should fail due to consumption)
        var reuseAttemptResponse = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", initialRefreshToken },
            { "client_id", "__password_flow__" }
        }));
        reuseAttemptResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest); // Changed from Unauthorized to BadRequest (invalid_grant)
        var errorResponseJson = await reuseAttemptResponse.Content.ReadAsStringAsync();
        using var errorDoc = JsonDocument.Parse(errorResponseJson);
        errorDoc.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
        errorElement.GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
        if (errorDoc.RootElement.TryGetProperty("error_description", out var errorDescElem))
        {
            Console.WriteLine($"[DEBUG] error_description: {errorDescElem.GetString()}");
        }

        // Act: Try to use the SECOND, newly issued token 
        var refreshRequest2Payload = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", refreshedTokens1.RefreshToken! },
            { "client_id", "__password_flow__" }
        };
        var refreshResponse2 = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(refreshRequest2Payload));

        // Assert: Second refresh SHOULD NOW FAIL if RevokeFamily is enabled (default)
        // Because the reuse attempt above triggered family revocation.
        // If theft detection was Silent, this would be OK.
        refreshResponse2.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Using the second token after the first was reused should fail due to family revocation.");
        var errorJson2 = await refreshResponse2.Content.ReadAsStringAsync();
        using var errorDoc2 = JsonDocument.Parse(errorJson2);
        errorDoc2.RootElement.TryGetProperty("error", out var errorElement2).ShouldBeTrue();
        errorElement2.GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
        if (errorDoc2.RootElement.TryGetProperty("error_description", out var errorDescElem2))
        {
            Console.WriteLine($"[DEBUG] error_description: {errorDescElem2.GetString()}");
        }

        // We cannot proceed to test a third refresh as the family is already revoked.
        // // Assert: Third refresh (using token from refreshResponse2) is also successful
        // var refreshedTokens2 = JsonSerializer.Deserialize<CoreIdent.Core.Models.Responses.TokenResponse>(await refreshResponse2.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); 
        // var refreshRequest3Payload = new Dictionary<string, string> { { "grant_type", "refresh_token" }, { "refresh_token", refreshedTokens2.RefreshToken! }, { "client_id", "__password_flow__" } };
        // var refreshResponse3 = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(refreshRequest3Payload));
        // refreshResponse3.StatusCode.ShouldBe(HttpStatusCode.OK, "The newly issued refresh token should be valid.");
    }

    [Fact]
    public async Task RefreshToken_WithExpiredToken_ReturnsUnauthorized()
    {
        // Arrange: Register and Login
        var userEmail = $"expired_user_{Guid.NewGuid()}@test.com";
        var userPassword = "ValidPassword123!";
        var (_, initialRefreshToken) = await RegisterAndLoginUser(userEmail, userPassword);

        // Arrange: Make the token expired in the database (requires access to the store)
        using (var scope = _factory.Services.CreateScope())
        {
            var refreshTokenStore = scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>();
            var tokenEntity = await refreshTokenStore.GetRefreshTokenAsync(initialRefreshToken, default);
            tokenEntity.ShouldNotBeNull("The refresh token should exist in the database after login."); // Fails if token not found
            tokenEntity.ExpirationTime = DateTime.UtcNow.AddSeconds(-1); // Set expiration to the past
            // Need to update the stored token - IRefreshTokenStore lacks an Update method!
            // We might need to Remove and re-Store, or add an Update method.
            // For now, let's assume the store implementation (e.g., EF) tracks changes or we add Update.
            // If using EF store directly:
            var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
            dbContext.Update(tokenEntity); 
            await dbContext.SaveChangesAsync();
        }

        var refreshPayload = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", initialRefreshToken },
            { "client_id", "__password_flow__" }
        };

        // Act
        var response = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(refreshPayload));

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest); // Changed from Unauthorized to BadRequest (invalid_grant)
        var errorJson = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(errorJson);
        doc.RootElement.TryGetProperty("error", out var error).ShouldBeTrue();
        error.GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
        if (doc.RootElement.TryGetProperty("error_description", out var errorDescElem))
        {
            Console.WriteLine($"[DEBUG] error_description: {errorDescElem.GetString()}");
        }
    }

    [Fact]
    public async Task RefreshToken_WithInvalidOrNonExistentToken_ReturnsUnauthorized()
    {
        // Arrange
        var invalidTokenPayload = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "invalid-or-non-existent-token" },
            { "client_id", "__password_flow__" }
        };

        // Act
        var response = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(invalidTokenPayload));

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest); // Changed from Unauthorized to BadRequest (invalid_grant)
        var errorJson = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(errorJson);
        doc.RootElement.TryGetProperty("error", out var error).ShouldBeTrue();
        error.GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
        if (doc.RootElement.TryGetProperty("error_description", out var errorDescElem))
        {
            Console.WriteLine($"[DEBUG] error_description: {errorDescElem.GetString()}");
        }
    }

     [Fact]
    public async Task RefreshToken_WithMissingToken_ReturnsBadRequest()
    {
        // Arrange
        var missingTokenPayload = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            // Missing refresh_token
            { "client_id", "__password_flow__" }
        };

        // Act
        var response = await _client.PostAsync("/auth/token", new FormUrlEncodedContent(missingTokenPayload));

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    // TODO: Add test for expired refresh token (Might require manipulating time or DB state)

} 