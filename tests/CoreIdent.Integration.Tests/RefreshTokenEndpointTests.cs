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
        // Register
        var registerRequest = new RegisterRequest { Email = email, Password = password };
        var registerResponse = await _client.PostAsJsonAsync("/auth/register", registerRequest);
        registerResponse.StatusCode.ShouldBeOneOf(HttpStatusCode.Created, HttpStatusCode.Conflict); // Allow conflict if user exists from previous run within same factory
        if (registerResponse.StatusCode == HttpStatusCode.Conflict)
        {
             // If conflict, just try logging in directly
            // (Could happen if test runner reuses factory instance unexpectedly)
        } else {
             registerResponse.EnsureSuccessStatusCode(); // Ensure 201 Created otherwise
        }
        

        // Login
        var loginRequest = new LoginRequest { Email = email, Password = password };
        var loginResponse = await _client.PostAsJsonAsync("/auth/login", loginRequest);
        
        // *** Add detailed logging if login fails ***
        if (!loginResponse.IsSuccessStatusCode)
        {
            var errorContent = await loginResponse.Content.ReadAsStringAsync();
            _factory.Services.GetRequiredService<ILogger<RefreshTokenEndpointTests>>().LogError(
                "Login failed in RegisterAndLoginUser. Status: {StatusCode}, Reason: {ReasonPhrase}, Content: {ErrorContent}",
                loginResponse.StatusCode, loginResponse.ReasonPhrase, errorContent);
        }
        loginResponse.EnsureSuccessStatusCode(); // Let this throw if login fails

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

        // Act: Refresh the token
        var refreshResponse1 = await _client.PostAsJsonAsync("/auth/token/refresh", refreshRequest);

        // *** Log Raw JSON Response ***
        var rawJson = await refreshResponse1.Content.ReadAsStringAsync();
        _factory.Services.GetRequiredService<ILogger<RefreshTokenEndpointTests>>().LogInformation("Raw JSON response from /token/refresh: {RawJson}", rawJson);

        // Assert: First refresh is successful
        refreshResponse1.StatusCode.ShouldBe(HttpStatusCode.OK);
        var refreshedTokens = JsonSerializer.Deserialize<CoreIdent.Core.Models.Responses.TokenResponse>(rawJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); // Deserialize manually
        refreshedTokens.ShouldNotBeNull();
        refreshedTokens.RefreshToken.ShouldNotBeNullOrEmpty();
        refreshedTokens.AccessToken.ShouldNotBeNullOrEmpty();
        refreshedTokens.RefreshToken.ShouldNotBe(initialRefreshToken, "A new refresh token should be issued.");

        // Act: Attempt to use the *original* refresh token again
        var refreshResponse2 = await _client.PostAsJsonAsync("/auth/token/refresh", refreshRequest); // Use initial token again

        // Assert: Second refresh attempt with the original token fails
        refreshResponse2.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "The original refresh token should be invalidated after use.");

        // Act: Attempt to use the *new* refresh token
        var newRefreshRequest = new RefreshTokenRequest { RefreshToken = refreshedTokens.RefreshToken };
        var refreshResponse3 = await _client.PostAsJsonAsync("/auth/token/refresh", newRefreshRequest); // Use the token from the first refresh

         // Assert: Refresh with the new token succeeds
        refreshResponse3.StatusCode.ShouldBe(HttpStatusCode.OK, "The newly issued refresh token should be valid.");
        var finalTokens = await refreshResponse3.Content.ReadFromJsonAsync<TokenResponse>();
        finalTokens.ShouldNotBeNull();
        finalTokens.RefreshToken.ShouldNotBe(refreshedTokens.RefreshToken);
    }

    [Fact]
    public async Task RefreshToken_WithExpiredToken_ReturnsUnauthorized()
    {
        // Arrange: Register and Login to get initial tokens
        var userEmail = $"expired_user_{Guid.NewGuid()}@test.com";
        var userPassword = "ValidPassword123!";
        var (_, initialRefreshToken) = await RegisterAndLoginUser(userEmail, userPassword);

        // Arrange: Directly manipulate the database to expire the token
        using (var scope = _factory.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
            var tokenEntity = await dbContext.RefreshTokens
                                             .FirstOrDefaultAsync(rt => rt.Handle == initialRefreshToken);
            
            tokenEntity.ShouldNotBeNull("The refresh token should exist in the database after login.");

            tokenEntity.ExpirationTime = DateTime.UtcNow.AddMinutes(-5); // Set expiration to the past
            await dbContext.SaveChangesAsync();
        }

        var refreshRequest = new RefreshTokenRequest { RefreshToken = initialRefreshToken };

        // Act: Attempt to refresh with the now-expired token
        var response = await _client.PostAsJsonAsync("/auth/token/refresh", refreshRequest);

        // Assert: Request fails with Unauthorized
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Expired refresh tokens should be rejected.");
    }

    // TODO: Add test for expired refresh token
    // TODO: Add test for invalid/non-existent refresh token handle

    [Fact]
    public async Task RefreshToken_WithInvalidOrNonExistentToken_ReturnsUnauthorized()
    {
        // Arrange
        var invalidTokenRequest = new RefreshTokenRequest { RefreshToken = "invalid-or-non-existent-token" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/token/refresh", invalidTokenRequest);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

     [Fact]
    public async Task RefreshToken_WithMissingToken_ReturnsBadRequest()
    {
        // Arrange
        var missingTokenRequest = new RefreshTokenRequest { RefreshToken = null }; // Or string.Empty

        // Act
        var response = await _client.PostAsJsonAsync("/auth/token/refresh", missingTokenRequest);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    // TODO: Add test for expired refresh token (Might require manipulating time or DB state)

} 