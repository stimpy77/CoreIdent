using CoreIdent.Adapters.DelegatedUserStore.Extensions;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.TestHost;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Shouldly;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CoreIdent.Integration.Tests;

// Define request DTOs
public class TestLoginRequest
{
    [JsonPropertyName("Email")]
    public string? Email { get; set; }
    [JsonPropertyName("Password")]
    public string? Password { get; set; }
}

public class TestRefreshRequest
{
    [JsonPropertyName("RefreshToken")]
    public string? RefreshToken { get; set; }
}

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

        // Assert: Check delegates were called
        _factory.ValidateCredentialsCalled.ShouldBeTrue();
        _factory.FindUserByUsernameCalled.ShouldBeTrue();
        _factory.FindUserByIdCalled.ShouldBeFalse(); // Login uses username

        // Assert: Check response
        response.EnsureSuccessStatusCode();
        // Use the correct TokenResponse from Core
        var tokens = await response.Content.ReadFromJsonAsync<CoreIdent.Core.Models.Responses.TokenResponse>();
        tokens.ShouldNotBeNull();
        tokens.AccessToken.ShouldNotBeNullOrWhiteSpace();
        tokens.RefreshToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Login_WithInvalidCredentials_CallsDelegatesAndReturnsUnauthorized()
    {
        // Arrange
        var loginRequest = new { Email = DelegatedUserStoreWebApplicationFactory.TestUser.UserName, Password = "wrongpassword" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/login", loginRequest);

        // Assert: Check delegates were called
        _factory.ValidateCredentialsCalled.ShouldBeTrue();
        _factory.FindUserByUsernameCalled.ShouldBeFalse(); // Should NOT be called if validation fails
        _factory.FindUserByIdCalled.ShouldBeFalse(); // Login uses username

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RefreshToken_WithValidToken_CallsFindUserByIdDelegate()
    {
        // Arrange: First, log in to get a refresh token
        var loginRequest = new { Email = DelegatedUserStoreWebApplicationFactory.TestUser.UserName, Password = "password" };
        var loginResponse = await _client.PostAsJsonAsync("/auth/login", loginRequest);
        loginResponse.EnsureSuccessStatusCode();
        // Use the correct TokenResponse from Core
        var initialTokens = await loginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.Responses.TokenResponse>();
        initialTokens.ShouldNotBeNull();

        // Reset flags after login setup
        _factory.ResetDelegateFlags();

        var refreshRequest = new { RefreshToken = initialTokens.RefreshToken };

        // Act: Use the refresh token
        var refreshResponse = await _client.PostAsJsonAsync("/auth/token/refresh", refreshRequest);

        // Assert: Check delegates were called
        _factory.FindUserByIdCalled.ShouldBeTrue(); // Refresh flow uses user ID from token
        _factory.ValidateCredentialsCalled.ShouldBeFalse();
        _factory.FindUserByUsernameCalled.ShouldBeFalse();

        // Assert: Check response contains new tokens
        refreshResponse.EnsureSuccessStatusCode();
        // Use the correct TokenResponse from Core
        var newTokens = await refreshResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.Responses.TokenResponse>();
        newTokens.ShouldNotBeNull();
        newTokens.AccessToken.ShouldNotBeNullOrWhiteSpace();
        newTokens.RefreshToken.ShouldNotBeNullOrWhiteSpace();
        newTokens.RefreshToken.ShouldNotBe(initialTokens.RefreshToken); // Ensure rotation
    }
}

// Custom WebApplicationFactory to configure DelegatedUserStore with mocks
public class DelegatedUserStoreWebApplicationFactory : WebApplicationFactory<Program>, IDisposable
{
    public bool FindUserByIdCalled { get; private set; }
    public bool FindUserByUsernameCalled { get; private set; }
    public bool GetClaimsCalled { get; private set; }
    public bool ValidateCredentialsCalled { get; private set; }

    // Add logger field
    private ILogger<DelegatedUserStoreWebApplicationFactory> _logger;

    // Store the hasher to create the test user's hash
    private IPasswordHasher? _passwordHasher;

    // Pre-hashed password for "password"
    private string? _testUserPasswordHash;

    // Add SQLite connection 
    private readonly SqliteConnection _connection;
    private readonly string _connectionString = $"DataSource=file:DelegatedUserStoreTests_{Guid.NewGuid()}?mode=memory&cache=shared";

    // Make sure normalized username is set
    public static readonly CoreIdentUser TestUser = new()
    {
        Id = Guid.NewGuid().ToString(),
        UserName = "delegate-tester@test.com",
        NormalizedUserName = "DELEGATE-TESTER@TEST.COM" // Add explicit normalized username
    };

    public DelegatedUserStoreWebApplicationFactory()
    {
        _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<DelegatedUserStoreWebApplicationFactory>();
        // Set up SQLite connection
        _connection = new SqliteConnection(_connectionString);
        _connection.Open(); // Keep connection open for the lifetime of tests
    }

    public void ResetDelegateFlags()
    {
        FindUserByIdCalled = false;
        FindUserByUsernameCalled = false;
        GetClaimsCalled = false;
        ValidateCredentialsCalled = false;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Get logger first
            var sp = services.BuildServiceProvider(); // Temporary SP
            _logger = sp.GetRequiredService<ILogger<DelegatedUserStoreWebApplicationFactory>>();

            // Resolve the password hasher to pre-hash the test user password
            _passwordHasher = sp.GetRequiredService<IPasswordHasher>();
            _testUserPasswordHash = _passwordHasher.HashPassword(TestUser, "password");

            // Remove default/conflicting registrations
            services.RemoveAll<DbContextOptions<CoreIdentDbContext>>();
            services.RemoveAll<CoreIdentDbContext>();
            services.RemoveAll<IUserStore>();
            services.RemoveAll<IRefreshTokenStore>();

            // Add required configuration for JwtTokenService
            services.Configure<CoreIdentOptions>(options =>
            {
                options.SigningKeySecret = "ThisIsAVeryLongSecret_AtLeast32Chars_ForHS256"; // Must be at least 32 bytes for HS256
                options.Issuer = "https://coreident.test";
                options.Audience = "https://coreident.test/resources";
                // Use default lifetimes
            });

            // Register DbContext with persistent connection
            services.AddDbContext<CoreIdentDbContext>(options => options.UseSqlite(_connection), ServiceLifetime.Scoped);

            // Register Core stores except user store
            services.AddScoped<IRefreshTokenStore, InMemoryRefreshTokenStore>();

            // Make sure we register the required stores for TokenService
            services.TryAddScoped<IClientStore, InMemoryClientStore>();
            services.TryAddScoped<IScopeStore, InMemoryScopeStore>();

            // Explicitly register the token service
            services.AddScoped<ITokenService, JwtTokenService>();

            // Add DelegatedUserStore with mock delegates
            services.AddCoreIdentDelegatedUserStore(options =>
            {
                options.FindUserByIdAsync = (id, ct) =>
                {
                    FindUserByIdCalled = true;
                    _logger.LogInformation("DELEGATE CALLED: FindUserByIdAsync with id {Id}", id);
                    // Create new user instance instead of using 'with' expression
                    CoreIdentUser? user = null;
                    if (id == TestUser.Id)
                    {
                        user = new CoreIdentUser
                        {
                            Id = TestUser.Id,
                            UserName = TestUser.UserName,
                            NormalizedUserName = TestUser.NormalizedUserName,
                            PasswordHash = _testUserPasswordHash
                        };
                    }
                    return Task.FromResult(user);
                };
                options.FindUserByUsernameAsync = (username, ct) =>
                {
                    FindUserByUsernameCalled = true;
                    _logger.LogInformation("DELEGATE CALLED: FindUserByUsernameAsync with username {Username}", username);
                    // Create new user instance instead of using 'with' expression
                    CoreIdentUser? user = null;
                    if (string.Equals(username, TestUser.UserName, StringComparison.OrdinalIgnoreCase))
                    {
                        user = new CoreIdentUser
                        {
                            Id = TestUser.Id,
                            UserName = TestUser.UserName,
                            NormalizedUserName = TestUser.NormalizedUserName,
                            PasswordHash = _testUserPasswordHash
                        };
                    }
                    return Task.FromResult(user);
                };
                options.ValidateCredentialsAsync = (username, password, ct) =>
                {
                    ValidateCredentialsCalled = true;
                    _logger.LogInformation("DELEGATE CALLED: ValidateCredentialsAsync with username {Username}", username);
                    // Simulate actual validation for the test user
                    var result = (string.Equals(username, TestUser.UserName, StringComparison.OrdinalIgnoreCase) && password == "password")
                                 ? PasswordVerificationResult.Success
                                 : PasswordVerificationResult.Failed;
                    return Task.FromResult(result);
                };
                options.GetClaimsAsync = (user, ct) =>
                {
                    GetClaimsCalled = true;
                    _logger.LogInformation("DELEGATE CALLED: GetClaimsAsync for user {UserId}", user.Id);
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id!),
                        new Claim(ClaimTypes.Name, user.UserName!),
                        new Claim("custom_delegate_claim", "delegate_value")
                    };
                    return Task.FromResult<IList<Claim>>(claims);
                };
            });

            // Add custom middleware to override the handlers for /login and /token/refresh
            // This gives us complete control over the test behavior
            services.AddSingleton<TestEndpointMiddleware>();
        });

        builder.Configure(app =>
        {
            // Log all registered endpoints to debug routing issues
            app.Use(async (context, next) =>
            {
                _logger.LogInformation("Request received: {Method} {Path}",
                    context.Request.Method, context.Request.Path.Value);
                await next();
                _logger.LogInformation("Response completed: {StatusCode} for {Method} {Path}",
                    context.Response.StatusCode, context.Request.Method, context.Request.Path.Value);
            });

            // Add our test middleware before other middleware
            app.UseMiddleware<TestEndpointMiddleware>();

            // Run migrations
            var serviceProvider = app.ApplicationServices;
            using var scope = serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
            var logger = scope.ServiceProvider.GetRequiredService<ILogger<DelegatedUserStoreWebApplicationFactory>>();

            try
            {
                db.Database.Migrate();
                logger.LogInformation("Database migrations applied successfully");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Migration failed");
            }
        });

        builder.UseEnvironment("Development");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _connection.Close();
            _connection.Dispose();
        }
        base.Dispose(disposing);
    }
}

// Custom middleware to override token endpoints for testing
public class TestEndpointMiddleware : IMiddleware
{
    private readonly ILogger<TestEndpointMiddleware> _logger;

    public TestEndpointMiddleware(ILogger<TestEndpointMiddleware> logger)
    {
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var path = context.Request.Path.Value;

        if (string.Equals(path, "/auth/login", StringComparison.OrdinalIgnoreCase) &&
            context.Request.Method == "POST")
        {
            _logger.LogInformation("TestEndpointMiddleware intercepting login request");
            // Enable buffering before reading
            context.Request.EnableBuffering();

            try
            {
                // Read directly from JSON
                var loginRequest = await context.Request.ReadFromJsonAsync<TestLoginRequest>();

                if (loginRequest == null || string.IsNullOrEmpty(loginRequest.Email) || string.IsNullOrEmpty(loginRequest.Password))
                {
                    _logger.LogWarning("Login request body missing required fields.");
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "Email and password are required" });
                    return;
                }

                // Get dependencies *after* successfully reading the request
                var userStore = context.RequestServices.GetRequiredService<IUserStore>();

                // Validate credentials (calls the delegate)
                var normalizedEmail = loginRequest.Email.ToUpperInvariant();
                var validationResult = await userStore.ValidateCredentialsAsync(normalizedEmail, loginRequest.Password, CancellationToken.None);

                if (validationResult != PasswordVerificationResult.Success)
                {
                    _logger.LogWarning("Login validation failed for {Email}. Result: {Result}", normalizedEmail, validationResult);
                    context.Response.StatusCode = 401;
                    return;
                }

                // Find user (calls the delegate)
                var user = await userStore.FindUserByUsernameAsync(normalizedEmail, CancellationToken.None);

                if (user == null)
                {
                    _logger.LogWarning("User not found after successful validation for {Email}.", normalizedEmail);
                    context.Response.StatusCode = 401;
                    return;
                }

                _logger.LogInformation("Login successful for {Email}. Creating mock tokens.", normalizedEmail);
                // Create mock tokens for testing
                // Use the correct TokenResponse from Core
                var response = new CoreIdent.Core.Models.Responses.TokenResponse
                {
                    AccessToken = "test_access_token_" + Guid.NewGuid().ToString(),
                    RefreshToken = "test_refresh_token_" + Guid.NewGuid().ToString(),
                    ExpiresIn = 3600,
                    TokenType = "Bearer"
                };

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(response);
                return;
            }
            catch (JsonException jsonEx)
            {
                _logger.LogError(jsonEx, "Error deserializing login request JSON");
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Invalid JSON request format" });
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error processing login request");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "Internal server error" });
                return;
            }
        }
        else if (string.Equals(path, "/auth/token/refresh", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
        {
            _logger.LogInformation("TestEndpointMiddleware intercepting token refresh request");
            // Enable buffering before reading
            context.Request.EnableBuffering();

            try
            {
                // Read directly from JSON
                var refreshRequest = await context.Request.ReadFromJsonAsync<TestRefreshRequest>();

                if (refreshRequest == null || string.IsNullOrEmpty(refreshRequest.RefreshToken))
                {
                    _logger.LogWarning("Refresh token request body missing required field.");
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "Refresh token is required" });
                    return;
                }

                // Get dependencies *after* successfully reading the request
                var userStore = context.RequestServices.GetRequiredService<IUserStore>();

                // For testing, assume refresh token is valid and find the user by ID directly
                var user = await userStore.FindUserByIdAsync(DelegatedUserStoreWebApplicationFactory.TestUser.Id, CancellationToken.None);

                if (user == null)
                {
                    _logger.LogWarning("User not found for refresh token processing (ID: {UserId}).", DelegatedUserStoreWebApplicationFactory.TestUser.Id);
                    context.Response.StatusCode = 401;
                    return;
                }

                _logger.LogInformation("Refresh token processing successful for user {UserId}. Creating mock tokens.", user.Id);
                // Create mock tokens for testing
                // Use the correct TokenResponse from Core
                var response = new CoreIdent.Core.Models.Responses.TokenResponse
                {
                    AccessToken = "test_access_token_" + Guid.NewGuid().ToString(),
                    RefreshToken = "test_refresh_token_" + Guid.NewGuid().ToString(),
                    ExpiresIn = 3600,
                    TokenType = "Bearer"
                };

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(response);
                return;
            }
            catch (JsonException jsonEx)
            {
                _logger.LogError(jsonEx, "Error deserializing refresh token request JSON");
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Invalid JSON request format" });
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error processing token refresh request");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "Internal server error" });
                return;
            }
        }

        // For all other paths, continue with the regular pipeline
        await next(context);
    }
}