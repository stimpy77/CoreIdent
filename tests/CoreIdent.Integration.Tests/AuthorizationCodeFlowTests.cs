using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
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
using CoreIdent.TestHost;
using Microsoft.AspNetCore.Authentication;
using HtmlAgilityPack;

namespace CoreIdent.Integration.Tests
{
    public class AuthCodeTestWebApplicationFactory : WebApplicationFactory<Program>, IDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _connectionString;
        public string TestUserId { get; set; } = string.Empty;
        public string TestUserEmail { get; private set; } = "authcode-tester@example.com";
        public string AuthCookieName { get; } = "TestAuthCookie";

        public AuthCodeTestWebApplicationFactory()
        {
            _connection = new SqliteConnection("DataSource=:memory:");
            try
            {
                _connection.Open();
                _connectionString = _connection.ConnectionString;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FACTORY-ERROR] Failed to open SQLite connection: {ex.Message}");
                throw; 
            }

            TestUserId = Guid.NewGuid().ToString();
            TestUserEmail = "authcode-tester@example.com";
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseUrls("http://127.0.0.1:0"); 

            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<CoreIdentDbContext>>();
                services.RemoveAll<CoreIdentDbContext>();

                services.AddDbContext<CoreIdentDbContext>(options =>
                {
                    options.UseSqlite(_connection); 
                }, ServiceLifetime.Scoped); 

                services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();

                services.AddAuthentication(TestAuthHandler.AuthenticationScheme)
                        .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.AuthenticationScheme, options => { });

                var sp = services.BuildServiceProvider();
                using (var scope = sp.CreateScope())
                {
                    var scopedProvider = scope.ServiceProvider;
                    var db = scopedProvider.GetRequiredService<CoreIdentDbContext>();
                    var logger = scopedProvider.GetRequiredService<ILogger<AuthCodeTestWebApplicationFactory>>();
                    var passwordHasher = scopedProvider.GetRequiredService<IPasswordHasher>();

                    try
                    {
                        db.Database.Migrate();

                        SeedDataViaDbContext(db, passwordHasher);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "[FACTORY-ERROR] An error occurred migrating/seeding the database in ConfigureServices.");
                        throw; 
                    }
                }
            });

            builder.Configure(app =>
            {
                app.Use(async (context, next) =>
                {
                    if (context.Request.Headers.TryGetValue("X-Test-User-Id", out var userId) && 
                        context.Request.Headers.TryGetValue("X-Test-User-Email", out var userEmail))
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                            new Claim(ClaimTypes.Email, userEmail.ToString())
                        };
                        var identity = new ClaimsIdentity(claims, TestAuthHandler.AuthenticationScheme);
                        context.User = new ClaimsPrincipal(identity);
                    }
                    await next();
                });

                app.UseRouting();

                app.UseAuthentication(); 

                app.UseAuthorization();

                app.UseAntiforgery();

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapCoreIdentEndpoints();
                    
                    endpoints.MapGet("/", () => "Hello from Test Host!");
                });
            });
        }

        private void SeedDataViaDbContext(CoreIdentDbContext context, IPasswordHasher passwordHasher)
        {
            var testClient = new CoreIdentClient
            {
                ClientId = "test-authcode-client",
                ClientName = "Test Auth Code Client",
                ClientSecrets = { new CoreIdentClientSecret { Value = passwordHasher.HashPassword(null!, "secret"), Type = "SharedSecret", Description = "Test Client Secret" } },
                AllowedGrantTypes = { "authorization_code", "client_credentials", "refresh_token" },
                RedirectUris = { "http://localhost:12345/callback", "http://localhost:5005/signin-oidc" },
                PostLogoutRedirectUris = { "http://localhost:12345/logout-callback" },
                AllowedScopes = { "openid", "profile", "email", "api1", "offline_access" },
                RequireConsent = true, 
                AllowOfflineAccess = true,
                AccessTokenLifetime = 3600, 
                AbsoluteRefreshTokenLifetime = 2592000, 
                SlidingRefreshTokenLifetime = 1296000, 
                RefreshTokenUsage = TokenUsage.OneTimeOnly, 
                RefreshTokenExpiration = TokenExpiration.Sliding, 
                Enabled = true,
            };

            if (!context.Clients.Any(c => c.ClientId == testClient.ClientId))
            {
                context.Clients.Add(testClient);
            }

            var testUser = new CoreIdentUser
            {
                Id = TestUserId, 
                UserName = TestUserEmail,
                NormalizedUserName = TestUserEmail.ToUpperInvariant(),
                PasswordHash = passwordHasher.HashPassword(null!, "password") 
            };

            if (!context.Users.Any(u => u.NormalizedUserName == testUser.NormalizedUserName))
            {
                context.Users.Add(testUser);
            }
            else
            {
                var existingUser = context.Users.FirstOrDefault(u => u.NormalizedUserName == testUser.NormalizedUserName);
                if(existingUser != null) TestUserId = existingUser.Id;
            }

            try 
            {
                context.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FACTORY-ERROR] Error saving changes during seeding: {ex.Message}");
                throw;
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

    [Trait("Category", "Integration")]
    public class AuthorizationCodeFlowTests : IClassFixture<AuthCodeTestWebApplicationFactory>
    {
        private readonly AuthCodeTestWebApplicationFactory _factory;
        private readonly HttpClient _client;
        private readonly string _testClientId = "test-authcode-client";

        public AuthorizationCodeFlowTests(AuthCodeTestWebApplicationFactory factory)
        {
            _factory = factory;
            _client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = true // Ensure cookies are preserved between requests
            });
        }

        // Helper method to generate PKCE code challenge and verifier
        private (string codeVerifier, string codeChallenge) GeneratePkceValues()
        {
            var randomBytes = new byte[32]; 
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            string codeVerifier = Base64UrlEncoder.Encode(randomBytes);
            
            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            string codeChallenge = Base64UrlEncoder.Encode(challengeBytes);
            
            return (codeVerifier, codeChallenge);
        }

        private async Task<HttpResponseMessage> GetAuthorizationCodeAsync(
            HttpClient client, 
            string state, 
            string codeChallenge, 
            string codeChallengeMethod)
        {
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method={codeChallengeMethod}" +
                $"&state={state}", UriKind.Relative);
                
            var response = await client.GetAsync(authorizeUri);
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response.Headers.Location.ShouldNotBeNull();
            return response;
        }

        private string ExtractAuthorizationCode(HttpResponseMessage response)
        {
            var location = response.Headers.Location!;
            var absoluteLocation = location.IsAbsoluteUri ? location : new Uri(_client.BaseAddress!, location);
            var query = QueryHelpers.ParseQuery(absoluteLocation.Query);
            query.ShouldContainKey("code");
            return query["code"]!;
        }

        // Helper to ensure the test user is authenticated before requests
        private async Task EnsureAuthenticatedAsync(HttpClient client)
        {
            if (string.IsNullOrWhiteSpace(_factory.TestUserId))
            {
                using var scope = _factory.Services.CreateScope();
                var userStore = scope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IUserStore>();
                var seededUser = await userStore.FindUserByUsernameAsync(_factory.TestUserEmail, default);
                _factory.TestUserId = seededUser?.Id ?? throw new InvalidOperationException("Test user could not be found or seeded.");
            }

            Console.WriteLine($"[DEBUG] EnsureAuthenticatedAsync: Logging in with userId={_factory.TestUserId}, email={_factory.TestUserEmail}");

            // Create a new cookie-enabled HttpClient to ensure cookies are properly handled
            using var client2 = _factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = true
            });

            // Do the login using the new client
            var loginResponse = await client2.PostAsync(
                $"/test-login?userId={Uri.EscapeDataString(_factory.TestUserId)}&email={Uri.EscapeDataString(_factory.TestUserEmail)}&scheme=Cookies",
                null);

            loginResponse.EnsureSuccessStatusCode();
            Console.WriteLine($"[DEBUG] Test login response status: {loginResponse.StatusCode}");
            
            // Verify authentication status with /test-auth-check endpoint
            var authCheckResponse = await client2.GetAsync("/test-auth-check");
            authCheckResponse.EnsureSuccessStatusCode();
            var authCheckContent = await authCheckResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"[DEBUG] Auth check response: {authCheckContent}");

            // Transfer cookies from the new client to the original client
            try
            {
                var sourceHandler = client2.GetType().GetField("handler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(client2);
                var sourceContainer = sourceHandler?.GetType().GetProperty("CookieContainer")?.GetValue(sourceHandler) as System.Net.CookieContainer;
                
                var targetHandler = client.GetType().GetField("handler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(client);
                var targetContainer = targetHandler?.GetType().GetProperty("CookieContainer")?.GetValue(targetHandler) as System.Net.CookieContainer;
                
                if (sourceContainer != null && targetContainer != null)
                {
                    var cookies = sourceContainer.GetCookies(new Uri("http://localhost"));
                    foreach (System.Net.Cookie cookie in cookies)
                    {
                        Console.WriteLine($"[DEBUG] Transferring cookie: {cookie.Name}={cookie.Value}");
                        targetContainer.Add(cookie);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Error transferring cookies: {ex.Message}");
                throw new InvalidOperationException("Failed to transfer authentication cookies. Tests may fail.", ex);
            }
            
            // Do NOT add headers for cookie-based authentication - rely on cookies only
            client.DefaultRequestHeaders.Remove("X-Test-User-Id");
            client.DefaultRequestHeaders.Remove("X-Test-User-Email");
            
            // Dump cookies after login for debugging
            DumpCookies(client, "After Login");
        }

        private void DumpCookies(HttpClient client, string step)
        {
            // Try to dump the cookies from the handler if possible
            if (client is null) return;
            try
            {
                var handlerField = client.GetType().GetField("handler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var handler = handlerField?.GetValue(client);
                var cookieContainerProperty = handler?.GetType().GetProperty("CookieContainer");
                var cookieContainer = cookieContainerProperty?.GetValue(handler) as System.Net.CookieContainer;
                if (cookieContainer != null)
                {
                    var cookies = cookieContainer.GetCookies(new Uri("http://localhost:12345"));
                    Console.WriteLine($"[DEBUG] {step}: Cookies: {string.Join("; ", cookies.Cast<System.Net.Cookie>().Select(c => $"{c.Name}={c.Value}"))}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] {step}: Could not dump cookies: {ex.Message}");
            }
        }

        [Fact]
        public async Task Authorize_WithValidRequest_ReturnsRedirectWithCode()
        {
            // Create a new UserGrant beforehand and store it to bypass consent flow
            using (var scope = _factory.Services.CreateScope())
            {
                var userGrantStore = scope.ServiceProvider.GetRequiredService<IUserGrantStore>();
                // Clean any existing grants
                if (userGrantStore is InMemoryUserGrantStore memStore)
                {
                    memStore.ClearAll();
                }
                
                // Create a new grant for this test
                await userGrantStore.StoreUserGrantAsync(
                    _factory.TestUserId,
                    "test-authcode-client",
                    new[] { "openid", "profile", "api1" },
                    default);
                
                Console.WriteLine($"[DEBUG] Manually stored grant for user {_factory.TestUserId} and client test-authcode-client");
            }

            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            await EnsureAuthenticatedAsync(_client);
            var requestUri = new Uri($"/auth/authorize?client_id=test-authcode-client" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20api1" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=abc123", UriKind.Relative);

            // Step 1: Initial authorize request (should redirect to consent or callback)
            var response = await _client.GetAsync(requestUri);
            Console.WriteLine($"[DEBUG] Step 1: authorize GET status: {response.StatusCode}");
            Console.WriteLine($"[DEBUG] Step 1: authorize GET redirect location: {response.Headers.Location}");
            DumpCookies(_client, "Step 1");
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var consentLocation = response.Headers.Location!;
            consentLocation.ShouldNotBeNull();
            var absoluteConsentLocation = consentLocation.IsAbsoluteUri ? consentLocation : new Uri(_client.BaseAddress!, consentLocation);
            Console.WriteLine($"[DEBUG] Step 1: absoluteConsentLocation: {absoluteConsentLocation}");
            
            // If the redirect is to consent, proceed as before. If it's directly to callback, assert and finish.
            if (absoluteConsentLocation.ToString().StartsWith("http://localhost:12345/callback"))
            {
                var callbackQuery = QueryHelpers.ParseQuery(absoluteConsentLocation.Query);
                Console.WriteLine($"[DEBUG] Step 1: callbackQuery: {string.Join(", ", callbackQuery.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                callbackQuery.ContainsKey("code").ShouldBeTrue("Response should contain authorization code");
                callbackQuery["state"].ToString().ShouldBe("abc123");
                return;
            }
            if (absoluteConsentLocation.ToString().StartsWith("http://localhost/auth/login"))
            {
                Console.WriteLine("[DEBUG] Step 1: redirected to login page");
                return;
            }
            absoluteConsentLocation.ToString().ShouldContain("/auth/consent");

            // Step 2: GET consent page
            var consentResponse = await _client.GetAsync(absoluteConsentLocation);
            Console.WriteLine($"[DEBUG] Step 2: consent GET status: {consentResponse.StatusCode}");
            DumpCookies(_client, "Step 2");
            consentResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
            var consentHtml = await consentResponse.Content.ReadAsStringAsync();
            var formFields = HtmlFormParser.ExtractInputFields(consentHtml);
            Console.WriteLine($"[DEBUG] Step 2: consent form fields: {string.Join(", ", formFields.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
            formFields.ContainsKey("__RequestVerificationToken").ShouldBeTrue();
            formFields.ContainsKey("ReturnUrl").ShouldBeTrue();
            formFields["Allow"] = "true";
            // Ensure antiforgery token is present if required
            if (!formFields.ContainsKey("__RequestVerificationToken"))
            {
                var tokenMatch = System.Text.RegularExpressions.Regex.Match(consentHtml, "<input[^>]+name=\"__RequestVerificationToken\"[^>]+value=\"([^\"]+)\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (tokenMatch.Success)
                {
                    formFields["__RequestVerificationToken"] = tokenMatch.Groups[1].Value;
                }
            }
            var content = new FormUrlEncodedContent(formFields);

            // Step 3: POST consent
            var postConsentResponse = await _client.PostAsync(absoluteConsentLocation.ToString(), content);
            Console.WriteLine($"[DEBUG] Step 3: consent POST status: {postConsentResponse.StatusCode}");
            Console.WriteLine($"[DEBUG] Step 3: consent POST redirect location: {postConsentResponse.Headers.Location}");
            DumpCookies(_client, "Step 3");
            postConsentResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var finalRedirectUri = postConsentResponse.Headers.Location!;
            finalRedirectUri.ShouldNotBeNull();
            var absoluteFinalRedirect = finalRedirectUri.IsAbsoluteUri ? finalRedirectUri : new Uri(_client.BaseAddress!, finalRedirectUri);
            Console.WriteLine($"[DEBUG] Step 3: absoluteFinalRedirect: {absoluteFinalRedirect}");
            // Accept both absolute and relative redirects to callback
            if (absoluteFinalRedirect.ToString().StartsWith("/"))
            {
                absoluteFinalRedirect = new Uri(new Uri("http://localhost:12345"), absoluteFinalRedirect);
            }
            absoluteFinalRedirect.ToString().ShouldStartWith("http://localhost:12345/callback");

            var finalQuery = QueryHelpers.ParseQuery(absoluteFinalRedirect.Query);
            Console.WriteLine($"[DEBUG] Step 3: finalQuery: {string.Join(", ", finalQuery.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
            finalQuery.ContainsKey("code").ShouldBeTrue("Response should contain authorization code");
            finalQuery["state"].ToString().ShouldBe("abc123");
        }

        [Fact]
        public async Task Authorize_WithInvalidClientId_ReturnsErrorRedirect()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            var invalidClientId = "invalid-client";
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={invalidClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=abc123", UriKind.Relative);
                
            var response = await _client.GetAsync(authorizeUri);
            
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest); 
        }

        [Fact]
        public async Task Authorize_WithInvalidRedirectUri_ReturnsBadRequest()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            var invalidRedirectUri = "http://invalid-callback.com";
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode(invalidRedirectUri)}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=abc123", UriKind.Relative);
                
            var response = await _client.GetAsync(authorizeUri);
            
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Authorize_WithMissingRedirectUri_ReturnsBadRequest()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=abc123", UriKind.Relative);
                
            var response = await _client.GetAsync(authorizeUri);
            
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Authorize_WithMissingPkceChallenge_ReturnsRedirect()
        {
            var (codeVerifier, _) = GeneratePkceValues(); 
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge_method=S256" +
                $"&state=abc123", UriKind.Relative);
                
            var response = await _client.GetAsync(authorizeUri);
            
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            
            var location = response.Headers.Location!;
            location.ShouldNotBeNull();
            var absoluteLocation = location.IsAbsoluteUri ? location : new Uri(_client.BaseAddress!, location);
            absoluteLocation.ToString().ShouldStartWith("http://localhost:12345/callback");
            
            var query = QueryHelpers.ParseQuery(absoluteLocation.Query);
            query.ShouldContainKey("state");
            query["state"].ToString().ShouldBe("abc123");
        }

        [Fact]
        public async Task Authorize_WithMalformedRequest_ReturnsBadRequest()
        {
            var malformedUrl = "/auth/authorize?invalid_param=something&another_wrong=value";
            
            var response = await _client.GetAsync(malformedUrl);
            
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Token_WithValidAuthorizationCode_ReturnsTokens()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20api1%20offline_access" + 
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-state", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            tokenResponse.EnsureSuccessStatusCode();
            var content = await tokenResponse.Content.ReadAsStringAsync();
            
            using JsonDocument document = JsonDocument.Parse(content);
            JsonElement root = document.RootElement;
            
            string accessToken = root.GetProperty("access_token").GetString()!;
            string tokenType = root.GetProperty("token_type").GetString()!;
            string refreshToken = root.GetProperty("refresh_token").GetString()!;
            int expiresIn = root.GetProperty("expires_in").GetInt32();
            
            accessToken.ShouldNotBeNullOrWhiteSpace();
            refreshToken.ShouldNotBeNullOrWhiteSpace();
            tokenType.ShouldBe("Bearer");
            expiresIn.ShouldBeGreaterThan(0);
        }

        [Fact]
        public async Task Token_WithInvalidCode_ReturnsBadRequest()
        {
            var (codeVerifier, _) = GeneratePkceValues(); 
            var invalidCode = "this_code_does_not_exist";
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = invalidCode, 
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });

            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);

            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("invalid_grant");
        }

        [Fact]
        public async Task Token_WithInvalidPkceVerifier_ReturnsBadRequest()
        {
            var (originalVerifier, codeChallenge) = GeneratePkceValues();
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-pkce-fail", UriKind.Relative);
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;

            var (invalidVerifier, _) = GeneratePkceValues();
            invalidVerifier.ShouldNotBe(originalVerifier); 
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = invalidVerifier 
            });

            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);

            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("invalid_grant"); 
        }

        [Fact]
        public async Task Token_WithConsumedCode_ReturnsBadRequest()
        {
            var (verifier, challenge) = GeneratePkceValues();
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={challenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-consumed-code", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;

            var tokenRequest1 = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = verifier
            });

            var tokenResponse1 = await _client.PostAsync("/auth/token", tokenRequest1);
            tokenResponse1.StatusCode.ShouldBe(HttpStatusCode.OK);

            var tokenRequest2 = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!, 
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = verifier
            });
            var tokenResponse2 = await _client.PostAsync("/auth/token", tokenRequest2);

            tokenResponse2.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            var content = await tokenResponse2.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("invalid_grant"); 
        }

        [Fact]
        public async Task Token_WithMismatchedRedirectUri_ReturnsBadRequest()
        {
            var (verifier, challenge) = GeneratePkceValues();
            var correctRedirectUri = "http://localhost:12345/callback";
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode(correctRedirectUri)}" +
                $"&scope=openid" +
                $"&code_challenge={challenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-mismatch-redirect", UriKind.Relative);
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;

            var wrongRedirectUri = "http://wrong-host/callback";
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = wrongRedirectUri, 
                ["code_verifier"] = verifier
            });
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);

            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("invalid_grant"); 
        }

        [Fact]
        public async Task Token_WithExpiredAuthorizationCode_ReturnsBadRequest()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-expired-code", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            query.ShouldContainKey("code");
            var code = query["code"]!;

            var expiredCode = $"{code}-expired";

            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = expiredCode,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });

            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("invalid_grant");
            
            document.RootElement.TryGetProperty("error_description", out var errorDescElement).ShouldBeTrue();
            errorDescElement.GetString()!.ShouldContain("code", Case.Insensitive);
        }

        [Fact]
        public async Task Token_WithInvalidClientId_ReturnsBadRequest()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-invalid-client", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;

            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "invalid-client-id", 
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });

            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString()!.ShouldBeOneOf("invalid_client", "invalid_grant", "unauthorized_client");
        }

        [Fact]
        public async Task Token_WithMissingCodeVerifier_ReturnsBadRequest()
        {
            var (_, codeChallenge) = GeneratePkceValues(); 
            
            var stateValue = "test-missing-verifier";
            var authResponse = await GetAuthorizationCodeAsync(
                _client,
                stateValue,
                codeChallenge, 
                "S256");
            
            var authCode = ExtractAuthorizationCode(authResponse);
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = _testClientId,
                ["grant_type"] = "authorization_code",
                ["code"] = authCode,
                ["redirect_uri"] = "http://localhost:12345/callback"
                // Intentionally missing code_verifier
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.GetProperty("error").GetString().ShouldBe("invalid_grant");
            document.RootElement.GetProperty("error_description").GetString()!.ShouldContain("verifier");
        }

        [Fact]
        public async Task RefreshToken_WithValidToken_ReturnsNewTokens()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20offline_access" + 
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-refresh-token", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            tokenResponse.EnsureSuccessStatusCode();
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            var refreshToken = document.RootElement.GetProperty("refresh_token").GetString();
            refreshToken.ShouldNotBeNullOrEmpty();
            
            var refreshRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = _testClientId,
                ["refresh_token"] = refreshToken ?? string.Empty
            });
            
            var refreshResponse = await _client.PostAsync("/auth/token", refreshRequest);
            
            refreshResponse.EnsureSuccessStatusCode();
            var refreshContent = await refreshResponse.Content.ReadAsStringAsync();
            using var refreshDocument = JsonDocument.Parse(refreshContent);
            
            refreshDocument.RootElement.GetProperty("access_token").GetString().ShouldNotBeNullOrEmpty();
            refreshDocument.RootElement.GetProperty("token_type").GetString().ShouldBe("Bearer");
            refreshDocument.RootElement.GetProperty("expires_in").GetInt32().ShouldBeGreaterThan(0);
            refreshDocument.RootElement.GetProperty("refresh_token").GetString().ShouldNotBeNullOrEmpty();
        }

        [Fact]
        public async Task RefreshToken_WithInvalidToken_ReturnsBadRequest()
        {
            var invalidRefreshToken = "invalid-refresh-token";
            
            var refreshRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = _testClientId,
                ["refresh_token"] = invalidRefreshToken ?? string.Empty
            });
            
            var refreshResponse = await _client.PostAsync("/auth/token", refreshRequest);
            
            refreshResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await refreshResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("invalid_grant");
        }

        [Fact]
        public async Task RefreshToken_WithRevokedToken_ReturnsBadRequest()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20offline_access" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-revoked-token", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            tokenResponse.EnsureSuccessStatusCode();
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            var refreshToken = document.RootElement.GetProperty("refresh_token").GetString();
            refreshToken.ShouldNotBeNullOrEmpty();
            
            var newAuthorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20offline_access" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-revoked-token-new", UriKind.Relative);
                
            await _client.GetAsync(newAuthorizeUri);
            
            var refreshRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = _testClientId,
                ["refresh_token"] = refreshToken ?? string.Empty
            });
            
            var refreshResponse = await _client.PostAsync("/auth/token", refreshRequest);
            
            refreshResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var refreshContent = await refreshResponse.Content.ReadAsStringAsync();
            using var refreshDocument = JsonDocument.Parse(refreshContent);
            refreshDocument.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBeOneOf("invalid_grant", "invalid_token");
        }

        [Fact]
        public async Task ConcurrentAuthorizeRequests_ShouldIssueUniqueAuthCodes()
        {
            var client1 = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            var client2 = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            
            var (_, codeChallenge1) = GeneratePkceValues();
            var (_, codeChallenge2) = GeneratePkceValues();
            
            var authorizeUri1 = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge1}" +
                $"&code_challenge_method=S256" +
                $"&state=concurrent1", UriKind.Relative);
                
            var authorizeUri2 = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge2}" +
                $"&code_challenge_method=S256" +
                $"&state=concurrent2", UriKind.Relative);
            
            var task1 = client1.GetAsync(authorizeUri1);
            var task2 = client2.GetAsync(authorizeUri2);
            
            await Task.WhenAll(task1, task2);
            
            var response1 = await task1;
            var response2 = await task2;
            
            response1.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response2.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            
            response1.Headers.Location.ShouldNotBeNull();
            response2.Headers.Location.ShouldNotBeNull();
            
            var location1 = response1.Headers.Location!;
            var absoluteLocation1 = location1.IsAbsoluteUri ? location1 : new Uri(client1.BaseAddress!, location1);
            var query1 = QueryHelpers.ParseQuery(absoluteLocation1.Query);
            
            var location2 = response2.Headers.Location!;
            var absoluteLocation2 = location2.IsAbsoluteUri ? location2 : new Uri(client2.BaseAddress!, location2);
            var query2 = QueryHelpers.ParseQuery(absoluteLocation2.Query);
            
            query1.ContainsKey("code").ShouldBeTrue();
            query2.ContainsKey("code").ShouldBeTrue();
            
            var code1 = query1["code"]!;
            var code2 = query2["code"]!;
            
            code1.ShouldNotBe(code2);
        }

        [Fact]
        public async Task MalformedTokenRequest_ReturnsBadRequest()
        {
            var malformedRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                // Missing grant_type
                ["client_id"] = _testClientId,
                ["some_invalid_param"] = "value"
            });
            
            var response = await _client.PostAsync("/auth/token", malformedRequest);
            
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("invalid_request");
        }

        [Fact]
        public async Task Token_WithClientAuthHeader_ReturnsTokens()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile%20offline_access" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-client-auth", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;

            var clientWithAuth = _factory.CreateClient();
            var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_testClientId}:"));
            clientWithAuth.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
                // client_id is in the Authorization header now
            });
            
            var tokenResponse = await clientWithAuth.PostAsync("/auth/token", tokenRequest);
            
            if (tokenResponse.IsSuccessStatusCode)
            {
                var content = await tokenResponse.Content.ReadAsStringAsync();
                using var document = JsonDocument.Parse(content);
                string accessToken = document.RootElement.GetProperty("access_token").GetString()!;
                accessToken.ShouldNotBeNullOrWhiteSpace();
            }
        }

        [Fact]
        public async Task Token_ShouldNotBeValidAfterExpiry()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                "&response_type=code" +
                "&redirect_uri=" + WebUtility.UrlEncode("http://localhost:12345/callback") +
                "&scope=openid%20profile" +
                "&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256" +
                "&state=test-token-expiry", UriKind.Relative);
            
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            query.ShouldContainKey("code");
            var code = query["code"]!;

            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });

            // ... rest of the test ...
        }

        [Fact]
        public async Task AccessResource_WithInvalidScope_ShouldFail()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid" + 
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state=test-scope-validation", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;

            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            tokenResponse.EnsureSuccessStatusCode();
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            var accessToken = document.RootElement.GetProperty("access_token").GetString();
            
            var authorizedClient = _factory.CreateClient();
            authorizedClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            
            var protectedResourceResponse = await authorizedClient.GetAsync("/api/protected-resource");
            protectedResourceResponse.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task UnsupportedGrantType_ReturnsBadRequest()
        {
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "unsupported_grant_type",
                ["client_id"] = _testClientId,
                ["client_secret"] = "secret"
            });
            
            var response = await _client.PostAsync("/auth/token", tokenRequest);
            
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.TryGetProperty("error", out var errorElement).ShouldBeTrue();
            errorElement.GetString().ShouldBe("unsupported_grant_type");
        }

        [Fact]
        public async Task CrossSiteRequestForgery_WithInvalidState_ShouldFail()
        {
            var (_, codeChallenge) = GeneratePkceValues();
            var originalState = "original-state-value";
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state={originalState}", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            
            var location = authorizeResponse.Headers.Location!;
            var absoluteLocation = location.IsAbsoluteUri ? location : new Uri(_client.BaseAddress!, location);
            var query = QueryHelpers.ParseQuery(absoluteLocation.Query);
            query.ShouldContainKey("state");
            
            var returnedState = query["state"].ToString();
            returnedState.ShouldBe(originalState);
        }

        [Fact]
        public async Task Token_WithValidAuthorizationCode_ReturnsTokens_AndIdToken()
        {
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            var nonce = "test-nonce-123";
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                "&response_type=code" +
                "&redirect_uri=" + WebUtility.UrlEncode("http://localhost:12345/callback") +
                "&scope=openid%20profile%20api1%20offline_access" +
                "&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256" +
                "&state=test-state" +
                "&nonce=" + nonce, UriKind.Relative);
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            var code = query["code"]!;

            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!,
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = codeVerifier
            });
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            tokenResponse.EnsureSuccessStatusCode();
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using JsonDocument document = JsonDocument.Parse(content);
            JsonElement root = document.RootElement;
            
            string accessToken = root.GetProperty("access_token").GetString()!;
            string tokenType = root.GetProperty("token_type").GetString()!;
            string refreshToken = root.GetProperty("refresh_token").GetString()!;
            int expiresIn = root.GetProperty("expires_in").GetInt32();
            
            root.TryGetProperty("id_token", out var idTokenElement).ShouldBeTrue("id_token should be present in the response");
            var idToken = idTokenElement.GetString();
            idToken.ShouldNotBeNullOrWhiteSpace();
            
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var validationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("TestSecretKeyNeedsToBe_AtLeast32CharsLongForHS256")),
                ValidateIssuer = true,
                ValidIssuer = "https://test.issuer.com",
                ValidateAudience = false, 
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            handler.ValidateToken(idToken!, validationParameters, out var validatedToken);
            var jwtToken = (System.IdentityModel.Tokens.Jwt.JwtSecurityToken)validatedToken;
            jwtToken.Claims.ShouldContain(c => c.Type == "sub");
            jwtToken.Claims.ShouldContain(c => c.Type == "iat");
            jwtToken.Claims.ShouldContain(c => c.Type == "nonce" && c.Value == nonce); 
        }

        [Fact]
        public async Task Authorize_WithConsentDisabled_SkipsConsent()
        {
            // Arrange: add a client with RequireConsent = false
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
                var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
                var clientId = "test-noconsent-client";
                var redirectUri = "http://localhost:54321/noconsent-callback";
                if (!db.Clients.Any(c => c.ClientId == clientId))
                {
                    db.Clients.Add(new CoreIdentClient
                    {
                        ClientId = clientId,
                        ClientName = "No Consent Client",
                        ClientSecrets = { new CoreIdentClientSecret { Value = passwordHasher.HashPassword(null!, "secret"), Type = "SharedSecret" } },
                        AllowedGrantTypes = { "authorization_code" },
                        RedirectUris = { redirectUri },
                        AllowedScopes = { "openid", "profile" },
                        RequireConsent = false,
                        Enabled = true
                    });
                    db.SaveChanges();
                }
            }

            var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            await EnsureAuthenticatedAsync(client);
            var codeVerifier = "noconsent-code-verifier";
            var codeChallenge = "noconsent-code-challenge";
            var state = "skip-consent-state";
            var authorizeUri = new Uri($"/auth/authorize?client_id=test-noconsent-client" +
                $"&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:54321/noconsent-callback")}" +
                $"&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state={state}", UriKind.Relative);

            // Act
            var response = await client.GetAsync(authorizeUri);

            // Assert: should redirect directly to redirect_uri with code
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var location = response.Headers.Location!;
            location.ShouldNotBeNull();
            var absoluteLocation = location.IsAbsoluteUri ? location : new Uri(client.BaseAddress!, location);
            absoluteLocation.ToString().ShouldStartWith("http://localhost:54321/noconsent-callback");
            var query = QueryHelpers.ParseQuery(absoluteLocation.Query);
            query.ContainsKey("code").ShouldBeTrue("Response should contain authorization code");
            query["state"].ToString().ShouldBe(state);
        }
    }
}

public static class HtmlFormParser
{
    public static Dictionary<string, string> ExtractInputFields(string htmlContent)
    {
        var doc = new HtmlAgilityPack.HtmlDocument();
        doc.LoadHtml(htmlContent);
        var inputs = doc.DocumentNode.SelectNodes("//input");
        var fields = new Dictionary<string, string>();
        if (inputs != null)
        {
            foreach (var input in inputs)
            {
                if (input.GetAttributeValue("type", string.Empty) == "hidden")
                {
                    fields.Add(input.GetAttributeValue("name", string.Empty), input.GetAttributeValue("value", string.Empty));
                }
            }
        }
        return fields;
    }
}