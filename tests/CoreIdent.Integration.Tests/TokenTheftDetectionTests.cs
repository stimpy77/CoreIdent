using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
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
using CoreIdent.TestHost;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Integration.Tests;

// Restore IDisposable
public class TokenTheftDetectionTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;
    // Restore initialization inside ConfigureServices
    private CoreIdentUser _testUser = default!;
    private readonly string _testPassword = "Password123!";
    // Restore keepAliveConnection
    private SqliteConnection? _keepAliveConnection; 

    public TokenTheftDetectionTests(WebApplicationFactory<Program> factory)
    {
        // Restore WithWebHostBuilder customization
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Restore DB setup logic from previous successful attempt
                
                // 1. Remove existing DbContext registration if any (important!)
                var dbContextDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<CoreIdentDbContext>));
                if (dbContextDescriptor != null)
                {
                    services.Remove(dbContextDescriptor);
                }
                var dbConnectionDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(System.Data.Common.DbConnection));
                 if (dbConnectionDescriptor != null)
                {
                    services.Remove(dbConnectionDescriptor);
                }

                // 2. Configure unique In-Memory SQLite DB for this test run
                 var connectionString = $"DataSource=file:memdb-tokentheft-{Guid.NewGuid()}?mode=memory&cache=shared";
                _keepAliveConnection = new SqliteConnection(connectionString);
                _keepAliveConnection.Open(); // Keep the connection open

                 services.AddDbContext<CoreIdentDbContext>(options =>
                {
                    options.UseSqlite(_keepAliveConnection);
                });

                // 3. Register EF Core stores AFTER DbContext registration
                services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();

                // 4. Override CoreIdent options for token security
                services.Configure<CoreIdentOptions>(options =>
                {
                    options.TokenSecurity = new TokenSecurityOptions
                    {
                        TokenTheftDetectionMode = TokenTheftDetectionMode.RevokeFamily,
                        EnableTokenFamilyTracking = true
                    };
                });

                // 5. Build SP once to perform setup tasks (Migration, Seed, User Creation)
                var sp = services.BuildServiceProvider();
                using (var scope = sp.CreateScope())
                {
                    var scopedServices = scope.ServiceProvider;
                    var db = scopedServices.GetRequiredService<CoreIdentDbContext>();
                    var logger = scopedServices.GetRequiredService<ILogger<TokenTheftDetectionTests>>(); 
                    var userStore = scopedServices.GetRequiredService<IUserStore>();
                    var passwordHasher = scopedServices.GetRequiredService<IPasswordHasher>();
                    var clientStore = scopedServices.GetRequiredService<IClientStore>();

                    try
                    {
                        // Migrate DB
                         db.Database.Migrate(); 
                         logger.LogInformation("Migrations applied successfully for TokenTheftDetectionTests.");

                         // Seed Client
                         var passwordClient = clientStore.FindClientByIdAsync("__password_flow__", CancellationToken.None).GetAwaiter().GetResult(); 
                         if (passwordClient == null)
                         {
                            logger.LogInformation("Seeding __password_flow__ client for TokenTheftDetectionTests..."); 
                            db.Clients.Add(new CoreIdentClient
                            { /* ... client config ... */ 
                                ClientId = "__password_flow__", 
                                ClientName = "Password Flow Client (Test)",
                                AllowedGrantTypes = new List<string> { "password" }, 
                                AllowOfflineAccess = true, 
                                AccessTokenLifetime = 3600,
                                AbsoluteRefreshTokenLifetime = 2592000,
                                SlidingRefreshTokenLifetime = 1296000,
                                RefreshTokenUsage = (int)TokenUsage.ReUse,
                                RefreshTokenExpiration = (int)TokenExpiration.Absolute,
                                Enabled = true,
                                AllowedScopes = { "openid", "profile", "email", "offline_access" } 
                            });
                             db.SaveChanges();
                            logger.LogInformation("__password_flow__ client seeded successfully.");
                         }
                         else
                         {
                            logger.LogInformation("__password_flow__ client already exists."); 
                         }

                        // Create and Assign Test User Directly
                         var testUserName = $"test-user-{Guid.NewGuid().ToString("N").Substring(0, 8)}@example.com";
                         _testUser = new CoreIdentUser 
                         {
                             Id = Guid.NewGuid().ToString(),
                             UserName = testUserName,
                             NormalizedUserName = testUserName.ToUpperInvariant(),
                             PasswordHash = passwordHasher.HashPassword(null, _testPassword)
                         };
                         logger.LogInformation("Creating test user: {UserName} ({UserId})", _testUser.UserName, _testUser.Id);
                         var createUserResult = userStore.CreateUserAsync(_testUser, default).GetAwaiter().GetResult();
                         if (createUserResult != StoreResult.Success)
                         {
                             logger.LogError("Failed to create test user {UserName} ({UserId}). StoreResult: {Result}", 
                                             _testUser.UserName, _testUser.Id, createUserResult);
                             throw new InvalidOperationException($"Failed to create test user in ConfigureServices. Result: {createUserResult}");
                         }
                         logger.LogInformation("Test user created successfully.");

                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Setup (Migration/Seed/User Creation) failed for TokenTheftDetectionTests");
                        throw;
                    }
                }
            });
        });

        _client = _factory.CreateClient();
        // Remove user creation from here again
    }

    // Restore Dispose method
    public void Dispose()
    {
        _keepAliveConnection?.Close();
        _keepAliveConnection?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task TokenTheft_Detection_Should_RevokeFamilyTokens()
    {
        // Arrange - first, login to get a token
        var loginResponse = await _client.PostAsJsonAsync("/auth/login", new LoginRequest
        {
            Email = _testUser.UserName,
            Password = _testPassword
        });

        // Assertion should fail here if refresh token is null
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);        
        var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true }; 
        var loginTokens = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>(jsonOptions);
        loginTokens.ShouldNotBeNull();
        loginTokens.RefreshToken.ShouldNotBeNullOrEmpty(); // This was failing
        
        var originalRefreshToken = loginTokens.RefreshToken;

        // Act 1 - Use the refresh token to get a new token (legitimate refresh)
        var firstRefreshResponse = await _client.PostAsJsonAsync("/auth/token/refresh", new RefreshTokenRequest 
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
        var theftAttemptResponse = await _client.PostAsJsonAsync("/auth/token/refresh", new RefreshTokenRequest 
        { 
            RefreshToken = originalRefreshToken 
        });

        // Assert - First, the theft attempt should fail
        theftAttemptResponse.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // Act 3 - Now try to use the second (legitimate) token - it should be revoked 
        // due to family-wide revocation
        var postTheftLegitimateRefreshResponse = await _client.PostAsJsonAsync("/auth/token/refresh", new RefreshTokenRequest 
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