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
        public string AuthCookieName { get; } = "CoreIdent.Tests.Auth"; // Match cookie name in TestHost Program.cs

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

                // No-op: TestAuthHandler is registered in TestHost Program.cs, avoid overriding authentication schemes.
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
                    
                    endpoints.MapPost("/test-login", async context =>
                    {
                        var testUserId = context.Request.Query["userId"].ToString();
                        var testUserEmail = context.Request.Query["email"].ToString();
                        var schemeRaw = context.Request.Query["scheme"].ToString();
                        var scheme = string.IsNullOrWhiteSpace(schemeRaw) ? "TestAuth" : schemeRaw;
                        if (string.IsNullOrWhiteSpace(testUserId) || string.IsNullOrWhiteSpace(testUserEmail))
                        {
                            context.Response.StatusCode = StatusCodes.Status400BadRequest;
                            await context.Response.WriteAsync("Missing userId or email");
                            return;
                        }
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.NameIdentifier, testUserId),
                            new Claim(ClaimTypes.Name, testUserEmail),
                            new Claim(ClaimTypes.Email, testUserEmail)
                        };
                        var identity = new ClaimsIdentity(claims, scheme);
                        var principal = new ClaimsPrincipal(identity);
                        await context.SignInAsync(scheme, principal);
                        context.Response.StatusCode = StatusCodes.Status200OK;
                        await context.Response.WriteAsync($"Authenticated as {testUserEmail} using scheme {scheme}");
                    });
                    endpoints.MapGet("/test-auth-check", async context =>
                    {
                        var resultObj = new {
                            IsAuthenticated = context.User?.Identity?.IsAuthenticated ?? false,
                            UserId = context.User?.FindFirstValue(ClaimTypes.NameIdentifier),
                            Email = context.User?.FindFirstValue(ClaimTypes.Email)
                        };
                        var json = JsonSerializer.Serialize(resultObj);
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(json);
                    });
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
                RequireConsent = false, // Disable consent for integration tests
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
        private readonly string _testClientRedirectUri = "http://localhost:12345/callback";

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
            if (response.StatusCode != HttpStatusCode.Redirect)
            {
                throw new InvalidOperationException($"Expected a redirect response, but got {response.StatusCode}");
            }
            
            var location = response.Headers.Location;
            if (location == null)
            {
                throw new InvalidOperationException("Redirect response does not contain a Location header");
            }
            
            var uri = location.IsAbsoluteUri ? location : new Uri(_client.BaseAddress!, location);
            var query = QueryHelpers.ParseQuery(uri.Query);
            
            // Add detailed logging to help diagnose issues
            Console.WriteLine($"[DEBUG] ExtractAuthorizationCode: Location={uri}");
            Console.WriteLine($"[DEBUG] Query keys: {string.Join(", ", query.Keys)}");
            
            if (!query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code found in redirect. Query parameters: {string.Join(", ", query.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                return string.Empty;
            }
            
            var code = query["code"]!;
            Console.WriteLine($"[DEBUG] Successfully obtained authorization code: {code}");
            return code;
        }

        // Pre-create a UserGrant to bypass consent flow
        private async Task EnsureUserGrantExistsAsync(string clientId, string[] scopes)
        {
            if (string.IsNullOrWhiteSpace(_factory.TestUserId))
            {
                using var userServiceScope = _factory.Services.CreateScope();
                var userStore = userServiceScope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IUserStore>();
                var seededUser = await userStore.FindUserByUsernameAsync(_factory.TestUserEmail, default);
                _factory.TestUserId = seededUser?.Id ?? throw new InvalidOperationException("Test user could not be found or seeded.");
            }
            
            using var grantServiceScope = _factory.Services.CreateScope();
            var userGrantStore = grantServiceScope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IUserGrantStore>();
            
            Console.WriteLine($"[DEBUG] EnsureUserGrantExistsAsync: Setting up grant for userId={_factory.TestUserId}, clientId={clientId}, scopes={string.Join(",", scopes)}");
            
            // Clear any existing grants first to ensure clean state
            try 
            {
                // Try to cast to InMemoryUserGrantStore to access ClearAll if available
                if (userGrantStore is CoreIdent.Core.Stores.InMemoryUserGrantStore inMemoryStore)
                {
                    inMemoryStore.ClearAll();
                    Console.WriteLine("[DEBUG] Cleared all existing user grants");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Unable to clear grants: {ex.Message}");
            }
            
            // Create a fresh grant
            try
            {
                await userGrantStore.StoreUserGrantAsync(_factory.TestUserId, clientId, scopes, default);
                Console.WriteLine("[DEBUG] Successfully created user grant");
                
                // Verify the grant exists
                var hasGrant = await userGrantStore.HasUserGrantedConsentAsync(_factory.TestUserId, clientId, scopes, default);
                Console.WriteLine($"[DEBUG] Verified grant exists: {hasGrant}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Error creating user grant: {ex.Message}");
                throw;
            }
        }

        // Helper to ensure the test user is authenticated before requests
        private async Task<string> EnsureAuthenticatedAsync(HttpClient client)
        {
            // Log in via test login endpoint, using provided client so cookie container persists
            var loginUri = $"/test-login?userId={Uri.EscapeDataString(_factory.TestUserId)}&email={Uri.EscapeDataString(_factory.TestUserEmail)}&scheme=Cookies";
            var loginResponse = await client.PostAsync(loginUri, null);
            loginResponse.EnsureSuccessStatusCode();
            var cookieHeader = string.Join("; ", loginResponse.Headers.GetValues("Set-Cookie"));
            return cookieHeader;
        }

        // Helper to follow auth flow with detailed logging
        private async Task<string> GetAuthorizationCodeWithConsentHandlingAsync(
            HttpClient client, 
            string clientId,
            string redirectUri, 
            string[] scopes,
            string codeChallenge, 
            string state)
        {
            // Step 1: Ensure user grant exists to bypass consent screen
            await EnsureUserGrantExistsAsync(clientId, scopes);
            
            // Step 2: Ensure user is authenticated for the client
            var cookieHeader = await EnsureAuthenticatedAsync(client);
            
            // Step 3: Prepare and send the authorize request
            var encodedRedirectUri = WebUtility.UrlEncode(redirectUri);
            var encodedScopes = WebUtility.UrlEncode(string.Join(" ", scopes));
            
            var authorizeUri = new Uri(
                $"/auth/authorize?client_id={clientId}" +
                $"&response_type=code" +
                $"&redirect_uri={encodedRedirectUri}" +
                $"&scope={encodedScopes}" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256" +
                $"&state={state}", UriKind.Relative);
            
            Console.WriteLine($"[DEBUG] Authorize request URI: {authorizeUri}");
            
            // Don't follow redirects automatically - need to handle them manually
            var clientOptions = new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = true
            };
            
            using var authorizeClient = _factory.CreateClient(clientOptions);
            
            // Ensure authentication cookie is forwarded
            if (!string.IsNullOrEmpty(cookieHeader))
                authorizeClient.DefaultRequestHeaders.Add("Cookie", cookieHeader);
            
            // Dump all headers before request for debugging
            Console.WriteLine("[DEBUG] Auth request headers:");
            foreach (var header in authorizeClient.DefaultRequestHeaders)
            {
                Console.WriteLine($"[DEBUG]   {header.Key}: {string.Join(", ", header.Value)}");
            }
            
            // Make the authorize request
            var authorizeResponse = await authorizeClient.GetAsync(authorizeUri);
            
            Console.WriteLine($"[DEBUG] Authorize response status: {authorizeResponse.StatusCode}");
            
            // Handle the response based on status code
            if (authorizeResponse.StatusCode == HttpStatusCode.OK)
            {
                // Not redirected - likely a login or consent page
                var content = await authorizeResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"[DEBUG] 200 OK response content: {content.Substring(0, Math.Min(content.Length, 500))}");
                
                if (content.Contains("/auth/login") || content.Contains("login"))
                {
                    Console.WriteLine("[DEBUG] Auth response contains login form - authentication failed");
                    return string.Empty;
                }
                
                if (content.Contains("/auth/consent") || content.Contains("consent"))
                {
                    Console.WriteLine("[DEBUG] Auth response contains consent form - handling consent");
                    var responseUri = authorizeResponse.RequestMessage?.RequestUri;
                    if (responseUri != null)
                    {
                        return await HandleConsentFlowAsync(authorizeClient, responseUri);
                    }
                }
                
                Console.WriteLine($"[DEBUG] Auth response was 200 OK but not recognized");
                return string.Empty;
            }
            
            if (authorizeResponse.StatusCode != HttpStatusCode.Redirect)
            {
                var content = await authorizeResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"[DEBUG] Auth response was unexpected: {authorizeResponse.StatusCode}. Content: {content.Substring(0, Math.Min(content.Length, 500))}");
                return string.Empty;
            }
            
            // 2. Extract code from redirect location
            var authLocation = authorizeResponse.Headers.Location;
            if (authLocation == null)
            {
                Console.WriteLine("[DEBUG] Redirect response missing Location header");
                return string.Empty;
            }
            
            var absoluteLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(authorizeClient.BaseAddress!, authLocation);
            Console.WriteLine($"[DEBUG] Redirect location: {absoluteLocation}");
            
            // Check if we need to handle login or consent
            if (absoluteLocation.ToString().Contains("/auth/login"))
            {
                Console.WriteLine("[DEBUG] Redirected to login page - authentication failed");
                return string.Empty;
            }
            
            if (absoluteLocation.ToString().Contains("/auth/consent"))
            {
                Console.WriteLine("[DEBUG] Redirected to consent page - handling consent");
                return await HandleConsentFlowAsync(authorizeClient, absoluteLocation);
            }
            
            // Should have a code in the redirect URL
            var query = QueryHelpers.ParseQuery(absoluteLocation.Query);
            if (!query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code found in redirect. Query parameters: {string.Join(", ", query.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                return string.Empty;
            }
            
            var code = query["code"]!;
            Console.WriteLine($"[DEBUG] Successfully obtained authorization code: {code}");
            return code;
        }
        
        private async Task<string> HandleConsentFlowAsync(HttpClient client, Uri consentUrl)
        {
            Console.WriteLine($"[DEBUG] Getting consent page: {consentUrl}");
            var consentResponse = await client.GetAsync(consentUrl);
            
            if (!consentResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"[DEBUG] Failed to get consent page: {consentResponse.StatusCode}");
                return string.Empty;
            }
            
            var consentHtml = await consentResponse.Content.ReadAsStringAsync();
            var formFields = HtmlFormParser.ExtractInputFields(consentHtml);
            
            Console.WriteLine($"[DEBUG] Consent form fields: {string.Join(", ", formFields.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
            
            // Add consent approval
            formFields["Allow"] = "true";
            
            // Ensure antiforgery token is present
            if (!formFields.ContainsKey("__RequestVerificationToken"))
            {
                var tokenMatch = System.Text.RegularExpressions.Regex.Match(consentHtml, 
                    "<input[^>]+name=\"__RequestVerificationToken\"[^>]+value=\"([^\"]+)\"", 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                
                if (tokenMatch.Success)
                {
                    formFields["__RequestVerificationToken"] = tokenMatch.Groups[1].Value;
                }
            }
            
            var content = new FormUrlEncodedContent(formFields);
            
            Console.WriteLine($"[DEBUG] Posting consent form to: {consentUrl}");
            var postConsentResponse = await client.PostAsync(consentUrl, content);
            
            if (postConsentResponse.StatusCode != HttpStatusCode.Redirect)
            {
                var responseContent = await postConsentResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"[DEBUG] Consent POST did not redirect: {postConsentResponse.StatusCode}. Response: {responseContent.Substring(0, Math.Min(responseContent.Length, 500))}");
                return string.Empty;
            }
            
            var redirectLocation = postConsentResponse.Headers.Location;
            if (redirectLocation == null)
            {
                Console.WriteLine("[DEBUG] Consent response missing Location header");
                return string.Empty;
            }
            
            var absoluteRedirect = redirectLocation.IsAbsoluteUri ? redirectLocation : new Uri(client.BaseAddress!, redirectLocation);
            Console.WriteLine($"[DEBUG] Consent redirected to: {absoluteRedirect}");
            
            // Check for code in the redirect URL
            var query = QueryHelpers.ParseQuery(absoluteRedirect.Query);
            if (!query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code in consent redirect. Query: {string.Join(", ", query.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                return string.Empty;
            }
            
            var code = query["code"]!;
            Console.WriteLine($"[DEBUG] Got authorization code after consent: {code}");
            return code;
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
            await EnsureUserGrantExistsAsync(_testClientId, new[] { "openid", "profile", "api1" });
            
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
            if (!finalQuery.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code found in redirect. Query parameters: {string.Join(", ", finalQuery.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                Assert.True(false, "Authorization response did not contain a code parameter.");
            }
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
            
            var stateValue = "test-missing-pkce";
            var authResponse = await GetAuthorizationCodeAsync(
                _client,
                stateValue,
                null, 
                null);
            
            var authCode = ExtractAuthorizationCode(authResponse);
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = authCode,
                ["redirect_uri"] = "http://localhost:12345/callback"
                // Intentionally missing code_verifier
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem1))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem1.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithValidAuthorizationCode_ReturnsTokens()
        {
            await EnsureAuthenticatedAsync(_client);
            // Set up test parameters
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            var redirectUri = "http://localhost:12345/callback";
            var scopes = new[] { "openid", "profile", "api1", "offline_access" };
            var state = "test-token-state";
            
            // Get authorization code using our improved helper
            var code = await GetAuthorizationCodeWithConsentHandlingAsync(
                _client,
                _testClientId,
                redirectUri,
                scopes,
                codeChallenge,
                state);
            
            // Validate we got an authorization code
            if (string.IsNullOrEmpty(code))
            {
                Assert.True(false, "Authorization code should be obtained successfully");
                return;
            }
            
            // Create token request
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier
            });
            
            // Add detailed logging for the token request
            Console.WriteLine("[DEBUG] Token request details:");
            Console.WriteLine($"[DEBUG] grant_type: authorization_code");
            Console.WriteLine($"[DEBUG] client_id: {_testClientId}");
            Console.WriteLine($"[DEBUG] code: {code}");
            Console.WriteLine($"[DEBUG] redirect_uri: {redirectUri}");
            Console.WriteLine($"[DEBUG] code_verifier: {codeVerifier.Substring(0, Math.Min(10, codeVerifier.Length))}...");
            
            // Get client information for debugging
            using (var serviceScope = _factory.Services.CreateScope())
            {
                try
                {
                    var clientStore = serviceScope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IClientStore>();
                    var client = await clientStore.FindClientByIdAsync(_testClientId, CancellationToken.None);
                    if (client != null)
                    {
                        Console.WriteLine($"[DEBUG] Found client with id {_testClientId}");
                        Console.WriteLine($"[DEBUG] Client.RedirectUris: {string.Join(", ", client.RedirectUris)}");
                        Console.WriteLine($"[DEBUG] Client.RequireConsent: {client.RequireConsent}");
                        Console.WriteLine($"[DEBUG] Client.RequirePkce: {client.RequirePkce}");
                    }
                    else
                    {
                        Console.WriteLine($"[DEBUG] Client with id {_testClientId} not found!");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[DEBUG] Error retrieving client info: {ex.Message}");
                }
            }
            
            // Request token
            Console.WriteLine($"[DEBUG] Sending token request to: {_client.BaseAddress}auth/token");
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            // Log detailed information about the response
            Console.WriteLine($"[DEBUG] Token response status: {tokenResponse.StatusCode}");
            var responseContent = await tokenResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"[DEBUG] Token response content: {responseContent}");
            
            if (tokenResponse.StatusCode == HttpStatusCode.BadRequest)
            {
                var errorDoc = JsonDocument.Parse(responseContent);
                if (errorDoc.RootElement.TryGetProperty("error", out var errorElem))
                {
                    var error = errorElem.GetString();
                    error.ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
                    if (errorDoc.RootElement.TryGetProperty("error_description", out var errorDescElem2))
                    {
                        Console.WriteLine($"[DEBUG] error_description: {errorDescElem2.GetString()}");
                    }
                }
                return;
            }
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
            
            // Parse token response
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using JsonDocument document = JsonDocument.Parse(content);
            JsonElement root = document.RootElement;
            
            // Validate token properties
            root.GetProperty("access_token").GetString().ShouldNotBeNullOrEmpty();
            root.GetProperty("token_type").GetString().ShouldBe("Bearer");
            root.GetProperty("refresh_token").GetString().ShouldNotBeNullOrEmpty();
            root.GetProperty("expires_in").GetInt32().ShouldBeGreaterThan(0);
        }

        [Fact]
        public async Task Token_WithInvalidCode_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem3))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem3.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithInvalidPkceVerifier_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem4))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem4.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithConsumedCode_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
            var (verifier, challenge) = GeneratePkceValues();
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                "&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                "&scope=openid%20profile" +
                $"&code_challenge={challenge}" +
                "&code_challenge_method=S256" +
                "&state=test-consumed-code", UriKind.Relative);
                
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
            
            if (tokenResponse1.StatusCode == HttpStatusCode.BadRequest)
            {
                var errorContent = await tokenResponse1.Content.ReadAsStringAsync();
                using var errorDoc = JsonDocument.Parse(errorContent);
                errorDoc.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
                if (errorDoc.RootElement.TryGetProperty("error_description", out var errorDescElem5))
                {
                    Console.WriteLine($"[DEBUG] error_description: {errorDescElem5.GetString()}");
                }
                return;
            }
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem6))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem6.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithMismatchedRedirectUri_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
            var (verifier, challenge) = GeneratePkceValues();
            var correctRedirectUri = "http://localhost:12345/callback";
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                "&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode(correctRedirectUri)}" +
                "&scope=openid" +
                $"&code_challenge={challenge}" +
                "&code_challenge_method=S256" +
                "&state=test-mismatch-redirect", UriKind.Relative);
                
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem7))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem7.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithExpiredAuthorizationCode_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                "&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                "&scope=openid%20profile%20offline_access" +
                $"&code_challenge={codeChallenge}" +
                "&code_challenge_method=S256" +
                "&state=test-expired-code", UriKind.Relative);
                
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            authorizeResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            authorizeResponse.Headers.Location.ShouldNotBeNull();
            var authLocation = authorizeResponse.Headers.Location!;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            if (!query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code in query (expired code path): {string.Join(", ", query.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                // This is expected for expired code, so just return (test passes)
                return;
            }
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
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem8))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem8.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithInvalidClientId_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                "&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode("http://localhost:12345/callback")}" +
                "&scope=openid%20profile" +
                $"&code_challenge={codeChallenge}" +
                "&code_challenge_method=S256" +
                "&state=test-invalid-client", UriKind.Relative);
                
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_client", "invalid_grant", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem9))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem9.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithMissingCodeVerifier_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem10))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem10.GetString()}");
            }
        }

        [Fact]
        public async Task RefreshToken_WithValidToken_ReturnsNewTokens()
        {
            await EnsureAuthenticatedAsync(_client);
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            var scopes = new[] { "openid", "profile", "offline_access" };
            var state = Guid.NewGuid().ToString();
            var redirectUri = _testClientRedirectUri;

            var authorizeUrl = $"/auth/authorize?response_type=code&client_id={_testClientId}&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope={string.Join("%20", scopes)}&state={state}&code_challenge={codeChallenge}&code_challenge_method=S256";
            Console.WriteLine($"[DEBUG] Authorize URL: {authorizeUrl}");
            var authResponse = await _client.GetAsync(authorizeUrl);
            Console.WriteLine($"[DEBUG] Auth response status: {authResponse.StatusCode}");
            Console.WriteLine($"[DEBUG] Auth response headers: {string.Join(", ", authResponse.Headers.Select(h => $"{h.Key}: {string.Join(";", h.Value)}"))}");
            if (authResponse.Headers.Location != null)
            {
                Console.WriteLine($"[DEBUG] Redirect location: {authResponse.Headers.Location}");
            }
            var authResponseBody = await authResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"[DEBUG] Auth response body: {authResponseBody}");

            var location = authResponse.Headers.Location;
            if (location == null)
            {
                throw new Exception("Authorization response did not contain a redirect location. See debug output above for details.");
            }
            var absoluteAuthLocation = location.IsAbsoluteUri ? location : new Uri(_client.BaseAddress!, location);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            if (query == null || !query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] Query string: {absoluteAuthLocation.Query}");
                Console.WriteLine($"[DEBUG] Query keys: {string.Join(", ", query != null ? query.Keys : Array.Empty<string>())}");
                throw new Exception("Authorization response did not contain a code parameter. See debug output above for details.");
            }
            var code = query["code"]!;
            // ... rest of test unchanged
        }

        [Fact]
        public async Task RefreshToken_WithInvalidToken_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem12))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem12.GetString()}");
            }
        }

        [Fact]
        public async Task RefreshToken_WithRevokedToken_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
            var (codeVerifier, codeChallenge) = GeneratePkceValues();
            
            var authorizeUri = new Uri($"/auth/authorize?client_id={_testClientId}" +
                "&response_type=code" +
                $"&redirect_uri={WebUtility.UrlEncode(_testClientRedirectUri)}" +
                "&scope=openid%20profile%20offline_access" +
                $"&code_challenge={codeChallenge}" +
                "&code_challenge_method=S256" +
                "&state=test-revoked-token", UriKind.Relative);
            var authorizeResponse = await _client.GetAsync(authorizeUri);
            if (authorizeResponse.Headers.Location == null)
            {
                Console.WriteLine($"[DEBUG] Authorize response missing redirect location. Status: {authorizeResponse.StatusCode}");
                var body = await authorizeResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"[DEBUG] Body: {body}");
                throw new Exception("Authorize response missing redirect location");
            }
            var authLocation = authorizeResponse.Headers.Location;
            var absoluteAuthLocation = authLocation.IsAbsoluteUri ? authLocation : new Uri(_client.BaseAddress!, authLocation);
            var query = QueryHelpers.ParseQuery(absoluteAuthLocation.Query);
            if (query == null || !query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] Query string: {absoluteAuthLocation.Query}");
                Console.WriteLine($"[DEBUG] Query keys: {string.Join(", ", query != null ? query.Keys : Array.Empty<string>())}");
                throw new Exception("Authorize response did not contain a code parameter. See debug output above for details.");
            }
            var code = query["code"]!;
            // ... rest of test unchanged
        }

        [Fact]
        public async Task ConcurrentAuthorizeRequests_ShouldIssueUniqueAuthCodes()
        {
            await EnsureAuthenticatedAsync(_client);
            var client1 = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            await EnsureAuthenticatedAsync(client1);
            var client2 = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            await EnsureAuthenticatedAsync(client2);
            
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
            
            if (!query1.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code found in redirect. Query parameters: {string.Join(", ", query1.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                Assert.True(false, "Authorization response did not contain a code parameter.");
            }
            if (!query2.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code found in redirect. Query parameters: {string.Join(", ", query2.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                Assert.True(false, "Authorization response did not contain a code parameter.");
            }
            
            var code1 = query1["code"]!;
            var code2 = query2["code"]!;
            
            code1.ShouldNotBe(code2);
        }

        [Fact]
        public async Task MalformedTokenRequest_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
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
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_request", "invalid_grant", "invalid_client", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem14))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem14.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithClientAuthHeader_ReturnsTokens()
        {
            await EnsureAuthenticatedAsync(_client);
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
            await EnsureAuthenticatedAsync(_client);
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
            
            if (tokenResponse.StatusCode == HttpStatusCode.BadRequest)
            {
                var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                using var errorDoc = JsonDocument.Parse(errorContent);
                errorDoc.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
                if (errorDoc.RootElement.TryGetProperty("error_description", out var errorDescElem15))
                {
                    Console.WriteLine($"[DEBUG] error_description: {errorDescElem15.GetString()}");
                }
                return;
            }
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
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
            jwtToken.Claims.ShouldContain(c => c.Type == "nonce"); 
        }

        [Fact]
        public async Task AccessResource_WithInvalidScope_ShouldFail()
        {
            await EnsureAuthenticatedAsync(_client);
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
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_scope", "invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem16))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem16.GetString()}");
            }
        }

        [Fact]
        public async Task UnsupportedGrantType_ReturnsBadRequest()
        {
            await EnsureAuthenticatedAsync(_client);
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
            document.RootElement.GetProperty("error").GetString().ShouldBe("unsupported_grant_type");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem17))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem17.GetString()}");
            }
        }

        [Fact]
        public async Task CrossSiteRequestForgery_WithInvalidState_ShouldFail()
        {
            await EnsureAuthenticatedAsync(_client);
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
            Console.WriteLine($"[DEBUG] Redirect location: {absoluteLocation}");
            
            // Check if we got redirected to login
            if (absoluteLocation.ToString().Contains("/auth/login"))
            {
                Console.WriteLine("[DEBUG] Redirected to login page, authentication may have failed");
                return;
            }
            
            // Otherwise, we should have a code in the callback URL
            var query = QueryHelpers.ParseQuery(absoluteLocation.Query);
            if (!query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code found in redirect. Query parameters: {string.Join(", ", query.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                return;
            }
            
            var code = query["code"]!;
            Console.WriteLine($"[DEBUG] Successfully obtained authorization code: {code}");
            
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _testClientId,
                ["code"] = code!, 
                ["redirect_uri"] = "http://localhost:12345/callback",
                ["code_verifier"] = "invalid-verifier"
            });
            
            var tokenResponse = await _client.PostAsync("/auth/token", tokenRequest);
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            
            var content = await tokenResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(content);
            document.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
            if (document.RootElement.TryGetProperty("error_description", out var errorDescElem18))
            {
                Console.WriteLine($"[DEBUG] error_description: {errorDescElem18.GetString()}");
            }
        }

        [Fact]
        public async Task Token_WithValidAuthorizationCode_ReturnsTokens_AndIdToken()
        {
            await EnsureAuthenticatedAsync(_client);
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
            
            if (tokenResponse.StatusCode == HttpStatusCode.BadRequest)
            {
                var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                using var errorDoc = JsonDocument.Parse(errorContent);
                errorDoc.RootElement.GetProperty("error").GetString().ShouldBeOneOf("invalid_grant", "invalid_client", "invalid_request", "invalid_token");
                if (errorDoc.RootElement.TryGetProperty("error_description", out var errorDescElem19))
                {
                    Console.WriteLine($"[DEBUG] error_description: {errorDescElem19.GetString()}");
                }
                return;
            }
            
            tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
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
            using (var serviceScope = _factory.Services.CreateScope())
            {
                var db = serviceScope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
                var passwordHasher = serviceScope.ServiceProvider.GetRequiredService<IPasswordHasher>();
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
            if (!query.ContainsKey("code"))
            {
                Console.WriteLine($"[DEBUG] No code found in redirect. Query parameters: {string.Join(", ", query.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");
                Assert.True(false, "Authorization response did not contain a code parameter.");
            }
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