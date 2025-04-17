using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.TestHost;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Integration.Tests;

public class TokenTheftDetectionTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;
    private readonly CoreIdentUser _testUser;
    private readonly string _testPassword = "Password123!";
    private readonly string _testClient = "test-client";

    public TokenTheftDetectionTests(WebApplicationFactory<Program> factory)
    {
        // Configure the factory to use specific options for this test
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Override the options to enable token security features
                services.Configure<CoreIdentOptions>(options =>
                {
                    options.TokenSecurity = new TokenSecurityOptions
                    {
                        TokenTheftDetectionMode = TokenTheftDetectionMode.RevokeFamily,
                        EnableTokenFamilyTracking = true
                    };
                });
            });
        });

        _client = _factory.CreateClient();

        // Set up our test user, register if needed
        _testUser = new CoreIdentUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = $"test-user-{Guid.NewGuid().ToString("N").Substring(0, 8)}@example.com"
        };

        // Register the user using the service provider
        using (var scope = _factory.Services.CreateScope())
        {
            var userStore = scope.ServiceProvider.GetRequiredService<IUserStore>();
            var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            var user = new CoreIdentUser
            {
                Id = _testUser.Id,
                UserName = _testUser.UserName
            };
            
            userStore.CreateUserAsync(user, passwordHasher.HashPassword(_testPassword), default).GetAwaiter().GetResult();
        }
    }

    [Fact]
    public async Task TokenTheft_Detection_Should_RevokeFamilyTokens()
    {
        // Arrange - first, login to get a token
        var loginResponse = await _client.PostAsJsonAsync("/login", new LoginRequest
        {
            Username = _testUser.UserName,
            Password = _testPassword
        });

        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
        
        var loginTokens = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>();
        loginTokens.ShouldNotBeNull();
        loginTokens.RefreshToken.ShouldNotBeNullOrEmpty();
        
        var originalRefreshToken = loginTokens.RefreshToken;

        // Act 1 - Use the refresh token to get a new token (legitimate refresh)
        var firstRefreshResponse = await _client.PostAsJsonAsync("/token/refresh", new RefreshTokenRequest 
        { 
            RefreshToken = originalRefreshToken 
        });

        firstRefreshResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
        
        var firstRefreshedTokens = await firstRefreshResponse.Content.ReadFromJsonAsync<TokenResponse>();
        firstRefreshedTokens.ShouldNotBeNull();
        firstRefreshedTokens.RefreshToken.ShouldNotBeNullOrEmpty();
        firstRefreshedTokens.RefreshToken.ShouldNotBe(originalRefreshToken); // Token rotation worked

        // Let's store the second refresh token
        var secondRefreshToken = firstRefreshedTokens.RefreshToken;

        // Act 2 - Try to use the original refresh token again (simulating theft)
        var theftAttemptResponse = await _client.PostAsJsonAsync("/token/refresh", new RefreshTokenRequest 
        { 
            RefreshToken = originalRefreshToken 
        });

        // Assert - First, the theft attempt should fail
        theftAttemptResponse.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // Act 3 - Now try to use the second (legitimate) token - it should be revoked 
        // due to family-wide revocation
        var postTheftLegitimateRefreshResponse = await _client.PostAsJsonAsync("/token/refresh", new RefreshTokenRequest 
        { 
            RefreshToken = secondRefreshToken 
        });

        // Assert - The legitimate token should also be rejected because the whole family is revoked
        postTheftLegitimateRefreshResponse.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // Verify in the database that the family is revoked
        using (var scope = _factory.Services.CreateScope())
        {
            var refreshTokenStore = scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>();
            
            // Get both tokens and verify they're marked as consumed
            var originalToken = await refreshTokenStore.GetRefreshTokenAsync(originalRefreshToken, default);
            var secondToken = await refreshTokenStore.GetRefreshTokenAsync(secondRefreshToken, default);

            originalToken.ShouldNotBeNull();
            secondToken.ShouldNotBeNull();
            
            originalToken!.ConsumedTime.ShouldNotBeNull();
            secondToken!.ConsumedTime.ShouldNotBeNull();
            
            // Verify they're in the same family
            originalToken.FamilyId.ShouldBe(secondToken.FamilyId);
            secondToken.PreviousTokenId.ShouldBe(originalToken.Handle);
        }
    }
} 