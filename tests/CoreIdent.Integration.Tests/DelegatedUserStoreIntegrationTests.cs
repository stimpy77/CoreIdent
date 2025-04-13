using CoreIdent.Adapters.DelegatedUserStore.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Integration.Tests.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using CoreIdent.Core.Stores;
using CoreIdent.Adapters.DelegatedUserStore;
using CoreIdent.Core.Services;

namespace CoreIdent.Integration.Tests;

public class DelegatedUserStoreIntegrationTests : IClassFixture<DelegatedUserStoreWebApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly DelegatedUserStoreWebApplicationFactory _factory;

    public DelegatedUserStoreIntegrationTests(DelegatedUserStoreWebApplicationFactory factory)
    {
        _factory = factory;
        _client = _factory.CreateClient();

        // Reset flags before each test
        _factory.ResetDelegateFlags();
    }

    [Fact]
    public async Task Login_WithValidCredentials_CallsDelegatesAndReturnsTokens()
    {
        // Arrange
        var loginRequest = new { Email = DelegatedUserStoreWebApplicationFactory.TestUser.UserName, Password = "password" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/login", loginRequest);

        // Assert
        response.EnsureSuccessStatusCode();
        var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokens.ShouldNotBeNull();
        tokens.AccessToken.ShouldNotBeNullOrWhiteSpace();
        tokens.RefreshToken.ShouldNotBeNullOrWhiteSpace();

        // Verify delegates were called
        _factory.FindUserByUsernameCalled.ShouldBeTrue();
        _factory.GetClaimsCalled.ShouldBeTrue(); // Called during token generation
    }

    [Fact]
    public async Task Login_WithInvalidCredentials_CallsDelegatesAndReturnsUnauthorized()
    {
        // Arrange
        var loginRequest = new { Email = DelegatedUserStoreWebApplicationFactory.TestUser.UserName, Password = "wrongpassword" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/login", loginRequest);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // Verify delegates were called (FindUser should still be called)
        _factory.FindUserByUsernameCalled.ShouldBeTrue();
        _factory.GetClaimsCalled.ShouldBeFalse(); // Not called if validation fails
    }

    [Fact]
    public async Task RefreshToken_WithValidToken_CallsFindUserByIdDelegate()
    {
        // Arrange: First, log in to get a refresh token
        var loginRequest = new { Email = DelegatedUserStoreWebApplicationFactory.TestUser.UserName, Password = "password" };
        var loginResponse = await _client.PostAsJsonAsync("/auth/login", loginRequest);
        loginResponse.EnsureSuccessStatusCode();
        var initialTokens = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>();
        initialTokens.ShouldNotBeNull();

        // Reset flags after login setup
        _factory.ResetDelegateFlags();

        var refreshRequest = new { RefreshToken = initialTokens.RefreshToken };

        // Act: Use the refresh token
        var refreshResponse = await _client.PostAsJsonAsync("/auth/token/refresh", refreshRequest);

        // Assert
        refreshResponse.EnsureSuccessStatusCode();
        var newTokens = await refreshResponse.Content.ReadFromJsonAsync<TokenResponse>();
        newTokens.ShouldNotBeNull();
        newTokens.AccessToken.ShouldNotBeNullOrWhiteSpace();
        newTokens.RefreshToken.ShouldNotBeNullOrWhiteSpace();
        newTokens.RefreshToken.ShouldNotBe(initialTokens.RefreshToken); // Ensure rotation

        // Verify FindUserByIdAsync was called (to validate refresh token subject)
        // And GetClaims for the new token
        _factory.FindUserByIdCalled.ShouldBeTrue();
        _factory.GetClaimsCalled.ShouldBeTrue();

        // Other delegates should not be called for refresh
        _factory.FindUserByUsernameCalled.ShouldBeFalse();
    }
}

// Custom WebApplicationFactory to configure DelegatedUserStore with mocks
public class DelegatedUserStoreWebApplicationFactory : WebApplicationFactory<Program>
{
    public bool FindUserByIdCalled { get; private set; }
    public bool FindUserByUsernameCalled { get; private set; }
    public bool GetClaimsCalled { get; private set; }

    // Store the hasher to create the test user's hash
    private IPasswordHasher? _passwordHasher;

    // Pre-hashed password for "password"
    private string? _testUserPasswordHash;

    public static readonly CoreIdentUser TestUser = new() { Id = Guid.NewGuid().ToString(), UserName = "delegate-tester@test.com" };

    public void ResetDelegateFlags()
    {
        FindUserByIdCalled = false;
        FindUserByUsernameCalled = false;
        GetClaimsCalled = false;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Resolve the password hasher to pre-hash the test user password
            var sp = services.BuildServiceProvider(); // Temporary SP
            _passwordHasher = sp.GetRequiredService<IPasswordHasher>();
            _testUserPasswordHash = _passwordHasher.HashPassword(TestUser, "password");

            // Remove existing stores if they were registered (e.g., EF Core stores)
            var userStoreDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IUserStore));
            if (userStoreDescriptor != null) services.Remove(userStoreDescriptor);
            var refreshTokenStoreDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IRefreshTokenStore));
            if (refreshTokenStoreDescriptor != null) services.Remove(refreshTokenStoreDescriptor);
            // Add other store removals if necessary (IClientStore, IScopeStore)

            // Add DelegatedUserStore with mock delegates
            services.AddCoreIdentDelegatedUserStore(options =>
            {
                options.FindUserByIdAsync = (id, ct) =>
                {
                    FindUserByIdCalled = true;
                    // Create new user instance instead of using 'with' expression
                    CoreIdentUser? user = null;
                    if (id == TestUser.Id)
                    {
                        user = new CoreIdentUser 
                        {
                            Id = TestUser.Id,
                            UserName = TestUser.UserName,
                            NormalizedUserName = TestUser.NormalizedUserName, // Copy other relevant props
                            PasswordHash = _testUserPasswordHash 
                        };
                    }
                    return Task.FromResult(user);
                };
                options.FindUserByUsernameAsync = (username, ct) =>
                {
                    FindUserByUsernameCalled = true;
                    // Create new user instance instead of using 'with' expression
                    CoreIdentUser? user = null;
                    if (string.Equals(username, TestUser.UserName, StringComparison.OrdinalIgnoreCase))
                    {
                         user = new CoreIdentUser 
                        {
                            Id = TestUser.Id,
                            UserName = TestUser.UserName,
                            NormalizedUserName = TestUser.NormalizedUserName, // Copy other relevant props
                            PasswordHash = _testUserPasswordHash 
                        };
                    }
                    return Task.FromResult(user);
                };
                options.ValidateCredentialsAsync = (username, password, ct) => Task.FromResult(false);
                options.GetClaimsAsync = (user, ct) =>
                {
                    GetClaimsCalled = true;
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id!),
                        new Claim(ClaimTypes.Name, user.UserName!),
                        new Claim("custom_delegate_claim", "delegate_value")
                    };
                    return Task.FromResult<IList<Claim>>(claims);
                };
            });

            // Register a simple in-memory store for refresh tokens for these tests
            // Use the specific test version to avoid ambiguity
            services.AddSingleton<IRefreshTokenStore, CoreIdent.Integration.Tests.Setup.InMemoryRefreshTokenStore>();

        });

        builder.UseEnvironment("Development");
    }
}

// Simple DTO for deserializing token responses
public class TokenResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public int ExpiresIn { get; set; }
} 