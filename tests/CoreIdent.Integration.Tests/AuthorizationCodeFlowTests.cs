using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Security.Cryptography;
using CoreIdent.Core.Models;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Shouldly;
using Xunit;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore.Infrastructure;
using CoreIdent.Core.Configuration;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace CoreIdent.Integration.Tests
{
    public class AuthCodeTestWebApplicationFactory : WebApplicationFactory<Program>, IDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _connectionString;
        public string TestUserId { get; private set; } = string.Empty;
        public string TestUserEmail { get; private set; } = "authcode-tester@example.com";

        public AuthCodeTestWebApplicationFactory()
        {
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();
            _connectionString = _connection.ConnectionString;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                // Remove potentially conflicting DbContext registrations
                services.RemoveAll<DbContextOptions<CoreIdentDbContext>>();
                services.RemoveAll<CoreIdentDbContext>();

                // Register DbContext with our kept-alive connection
                services.AddDbContext<CoreIdentDbContext>(options => options.UseSqlite(_connection), ServiceLifetime.Scoped);
                
                // Ensure CoreIdent EF stores are registered
                services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();
                
                // Add CoreIdent Core services (like IPasswordHasher, ITokenService)
                // If Program.cs doesn't add these, they are needed here.
                // Provide dummy options if necessary.
                services.AddCoreIdent(options => { // Use dummy AddCoreIdent setup if needed
                     options.SigningKeySecret = "TestSecretKeyNeedsToBe_AtLeast32CharsLongForHS256";
                     options.Issuer = "https://test.issuer.com";
                     options.Audience = "https://test.audience.com";
                 });

                // Add Authentication and Authorization services
                services.AddAuthentication(); // Add authentication services
                services.AddAuthorization(); // Add authorization services (REQUIRED by UseAuthorization)

                // Build a temporary service provider to perform seeding
                var sp = services.BuildServiceProvider(); 
                using var scope = sp.CreateScope();
                var scopedProvider = scope.ServiceProvider;
                var db = scopedProvider.GetRequiredService<CoreIdentDbContext>();
                var logger = scopedProvider.GetRequiredService<ILogger<AuthCodeTestWebApplicationFactory>>();
                var passwordHasher = scopedProvider.GetRequiredService<IPasswordHasher>(); // Get hasher

                try
                {
                    db.Database.Migrate();
                    // Seed client, scopes, AND the specific test user
                    SeedDataViaDbContext(db, passwordHasher); 
                    logger.LogInformation("Database migrated and seeded successfully...");
                }
                catch (Exception ex)
                {
                     logger.LogError(ex, "An error occurred migrating/seeding the database...");
                    throw;
                }
            });

            // Configure the application pipeline
            builder.Configure(app =>
            {
                // 1. Middleware to simulate authentication using the PRE-SEEDED TestUserId
                app.Use(async (context, next) =>
                {
                    if (context.Request.Path.StartsWithSegments("/auth/authorize"))
                    {
                        if (!string.IsNullOrEmpty(TestUserId))
                        {
                            var claims = new List<Claim>
                            {
                                new Claim(ClaimTypes.NameIdentifier, TestUserId), 
                                new Claim(ClaimTypes.Name, TestUserEmail) 
                            };
                            var identity = new ClaimsIdentity(claims, "TestAuth");
                            context.User = new ClaimsPrincipal(identity);
                             var logger = context.RequestServices.GetRequiredService<ILogger<AuthCodeTestWebApplicationFactory>>();
                             logger.LogInformation("Simulated authentication for user {UserId} ({UserName}) on path {Path}", TestUserId, TestUserEmail, context.Request.Path);
                        }
                        else
                        {
                             var logger = context.RequestServices.GetRequiredService<ILogger<AuthCodeTestWebApplicationFactory>>();
                             logger.LogWarning("TestUserId was not set during seeding. Cannot simulate authentication for path {Path}", context.Request.Path);
                             // Depending on test needs, could return 401 here or let auth middleware handle it
                        }
                    }
                    await next.Invoke();
                });

                // 2. Standard middleware 
                app.UseRouting(); 
                
                // Add Authentication middleware (needed for HttpContext.User to be properly processed by endpoints)
                app.UseAuthentication(); 
                app.UseAuthorization(); // Add Authorization as well, it's usually needed

                // 3. Map CoreIdent Endpoints
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapCoreIdentEndpoints("/auth");
                });

                // 4. Add request logging middleware for debugging
                app.Use(async (context, next) =>
                {
                    // Simple logging middleware to see requests in test output
                    Console.WriteLine($">>> Test Request: {context.Request.Method} {context.Request.Path}{context.Request.QueryString}");
                    await next.Invoke();
                });
            });
            
            builder.UseEnvironment("Development");
        }

        // Modified seeding logic to accept DbContext and Hasher
        private void SeedDataViaDbContext(CoreIdentDbContext dbContext, IPasswordHasher passwordHasher)
        {
            // Seed Client
            var client = dbContext.Clients.FirstOrDefault(c => c.ClientId == "test-authcode-client");
            if (client == null)
            {
                 client = new CoreIdentClient
                {
                    ClientId = "test-authcode-client",
                    ClientName = "Test Auth Code Client",
                    RequirePkce = true,
                    AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
                    RedirectUris = new List<string> { "http://localhost:12345/callback" },
                    AllowedScopes = new List<string> { "openid", "profile", "api1", "offline_access" },
                    AllowOfflineAccess = true, // Important for refresh tokens
                    Enabled = true
                };
                dbContext.Clients.Add(client);
            }

             // Seed User specifically for these tests
            var user = dbContext.Users.FirstOrDefault(u => u.UserName == TestUserEmail);
            if (user == null)
            {
                user = new CoreIdentUser
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = TestUserEmail,
                    NormalizedUserName = TestUserEmail.ToUpperInvariant(),
                     // Make sure user has a password hash if login/validation logic needs it later
                    PasswordHash = passwordHasher.HashPassword(null, "password") // Hash a dummy password
                };
                dbContext.Users.Add(user);
                TestUserId = user.Id; // Store the generated ID
            }
            else
            {
                 TestUserId = user.Id; // Store the existing ID
                 // Ensure user has a password hash if test logic depends on it
                 if (string.IsNullOrEmpty(user.PasswordHash)) {
                     user.PasswordHash = passwordHasher.HashPassword(user, "password");
                 }
            }


            // Seed Scopes
            EnsureScopeExistsViaDbContext(dbContext, "openid", "OpenID Connect");
            EnsureScopeExistsViaDbContext(dbContext, "profile", "User Profile");
            EnsureScopeExistsViaDbContext(dbContext, "api1", "Test API Scope");
             EnsureScopeExistsViaDbContext(dbContext, "offline_access", "Offline Access"); // Ensure this exists

            try
            {
                dbContext.SaveChanges(); // Commit seeded data
            }
            catch (DbUpdateException ex)
            {
                 var logger = dbContext.GetService<ILogger<AuthCodeTestWebApplicationFactory>>(); // Get logger from DbContext
                 logger.LogError(ex, "Error saving seeded data to DbContext.");
                 throw;
            }
        }

        private void EnsureScopeExistsViaDbContext(CoreIdentDbContext dbContext, string name, string displayName)
        {
            var scope = dbContext.Scopes.FirstOrDefault(s => s.Name == name);
            if (scope == null)
            {
                dbContext.Scopes.Add(new CoreIdentScope { Name = name, DisplayName = displayName, Enabled = true });
            }
            else if (!scope.Enabled) 
            { 
                scope.Enabled = true; 
            } 
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _connection?.Close();
                _connection?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    public class AuthorizationCodeFlowTests : IClassFixture<AuthCodeTestWebApplicationFactory>
    {
        private readonly AuthCodeTestWebApplicationFactory _factory;
        private readonly HttpClient _client;

        public AuthorizationCodeFlowTests(AuthCodeTestWebApplicationFactory factory)
        {
            _factory = factory;
            _client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false // Important for OAuth flows to handle redirects manually
            });
        }

        // Helper method to generate PKCE code challenge and verifier
        private (string codeVerifier, string codeChallenge) GeneratePkceValues()
        {
            // Generate random code verifier (between 43-128 chars)
            var randomBytes = new byte[32]; // 32 bytes = 43 chars in base64url
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            string codeVerifier = Base64UrlEncoder.Encode(randomBytes);
            
            // Generate code challenge (S256 method)
            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            string codeChallenge = Base64UrlEncoder.Encode(challengeBytes);
            
            return (codeVerifier, codeChallenge);
        }

        [Fact]
        public async Task Authorize_WithValidRequest_ReturnsRedirectWithCode()
        {
            // Arrange
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            // Construct authorize request with appropriate parameters
            var requestUri = new Uri($"/auth/authorize?client_id=test-authcode-client" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20api1" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=abc123", UriKind.Relative);
            
            // Act
            var response = await _client.GetAsync(requestUri);
            
            // Assert
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            
            var location = response.Headers.Location;
            location.ShouldNotBeNull();
            location.ToString().ShouldStartWith("http://localhost:12345/callback");
            
            // Extract code from redirect URI
            var query = QueryHelpers.ParseQuery(location.Query);
            query.ContainsKey("code").ShouldBeTrue("Response should contain authorization code");
            query["state"].ToString().ShouldBe("abc123");
        }

        [Fact]
        public async Task Token_WithValidAuthorizationCode_ReturnsTokens()
        {
            // Arrange - First get an authorization code
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id=test-authcode-client" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20api1%20offline_access" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-state", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var location = authorizeResponse.Headers.Location;
            var query = QueryHelpers.ParseQuery(location.Query);
            query.ContainsKey("code").ShouldBeTrue();
            var code = query["code"];
            
            // Act - Exchange code for tokens
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "test-authcode-client",
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            // Assert
            tokenResponse.EnsureSuccessStatusCode();
            var content = await tokenResponse.Content.ReadAsStringAsync();
            
            // DEBUG: Print the raw response content to the console
            Console.WriteLine($"DEBUG - Raw token response: {content}");
            
            // Try with JSONDocument direct access 
            using JsonDocument document = JsonDocument.Parse(content);
            JsonElement root = document.RootElement;
            
            string accessToken = root.GetProperty("access_token").GetString() ?? string.Empty;
            string tokenType = root.GetProperty("token_type").GetString() ?? string.Empty;
            string refreshToken = root.GetProperty("refresh_token").GetString() ?? string.Empty;
            int expiresIn = root.GetProperty("expires_in").GetInt32();
            
            Console.WriteLine($"DEBUG - Manually parsed AccessToken: {accessToken}");
            Console.WriteLine($"DEBUG - Manually parsed RefreshToken: {refreshToken}");
            Console.WriteLine($"DEBUG - Manually parsed TokenType: {tokenType}");
            
            // Validate through assertions
            accessToken.ShouldNotBeNullOrWhiteSpace();
            refreshToken.ShouldNotBeNullOrWhiteSpace();
            tokenType.ShouldBe("Bearer");
            expiresIn.ShouldBeGreaterThan(0);
        }
    }
}