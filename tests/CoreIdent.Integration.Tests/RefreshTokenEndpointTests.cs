using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Storage.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc.Testing; // Added for WebApplicationFactory
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Shouldly;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json; // For PostAsJsonAsync
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Integration.Tests;

/// <summary>
/// Integration tests for the /token/refresh endpoint.
/// These tests require the database to be set up via migrations.
/// </summary>
// Use the standard WebApplicationFactory with the Program entry point from CoreIdent.TestHost
public class RefreshTokenEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public RefreshTokenEndpointTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        // Use a client configured for the TestServer
        _client = _factory.CreateClient(); 
    }

    private async Task<(string AccessToken, string RefreshToken)> RegisterAndLoginUser(string email, string password)
    {
        // Register
        var registerRequest = new RegisterRequest { Email = email, Password = password };
        var registerResponse = await _client.PostAsJsonAsync("/auth/register", registerRequest);
        registerResponse.EnsureSuccessStatusCode(); // Throws if not 2xx

        // Login
        var loginRequest = new LoginRequest { Email = email, Password = password };
        var loginResponse = await _client.PostAsJsonAsync("/auth/login", loginRequest);
        loginResponse.EnsureSuccessStatusCode();
        var tokenResponse = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>();
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

        // Assert: First refresh is successful
        refreshResponse1.StatusCode.ShouldBe(HttpStatusCode.OK);
        var refreshedTokens = await refreshResponse1.Content.ReadFromJsonAsync<TokenResponse>();
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