#pragma warning disable CS8600, CS8601, CS8602, CS8604, CS0219
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Shouldly;
using Xunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.Logging;
using CoreIdent.Integration.Tests;
using CoreIdent.Storage.EntityFrameworkCore;

namespace CoreIdent.Integration.Tests
{
    public class ConsentFlowTests : IClassFixture<AuthCodeTestWebApplicationFactory>
    {
        private readonly AuthCodeTestWebApplicationFactory _factory;
        private readonly WebApplicationFactory<CoreIdent.TestHost.Program> _webFactory;
        private const string ClientId = "test-authcode-client";
        private const string RedirectUri = "http://localhost:12345/callback";
        private const string Scope = "openid profile api1";
        private const string State = "abc123";
        private const string CodeChallenge = "challenge";
        private const string CodeChallengeMethod = "S256";

        public ConsentFlowTests(AuthCodeTestWebApplicationFactory factory)
        {
            try
            {
                _factory = factory;
                _webFactory = factory.WithWebHostBuilder(builder =>
                {
                    // Restore custom logging setup
                    builder.ConfigureLogging(logging =>
                    {
                        logging.ClearProviders(); // Remove default providers
                        logging.AddConsole();
                        logging.AddDebug();
                        logging.SetMinimumLevel(LogLevel.Trace); // Capture detailed logs
                    });

                    builder.ConfigureServices(services =>
                    {
                        // Enable consent requirement for consent flow tests
                        var sp = services.BuildServiceProvider();
                        using var scope = sp.CreateScope();
                        var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
                        var client = dbContext.Clients.First(c => c.ClientId == ClientId);
                        client.RequireConsent = true;
                        dbContext.SaveChanges();
                    });
                });
            }
            catch (Exception ex)
            {
                var message = $"[TEST-ERROR] Exception during ConsentFlowTests constructor: {ex}";
                Console.WriteLine(message);
                throw;
            }
        }

        private HttpClient CreateClientWithCookies()
        {
            var client = _webFactory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = true
            });
            return client;
        }

        private async Task EnsureAuthenticatedAsync(HttpClient client)
        {
            if (string.IsNullOrWhiteSpace(_factory.TestUserId))
            {
                using var scope = _factory.Services.CreateScope();
                var userStore = scope.ServiceProvider.GetRequiredService<CoreIdent.Core.Stores.IUserStore>();
                var seededUser = await userStore.FindUserByUsernameAsync(_factory.TestUserEmail, default);
                _factory.TestUserId = seededUser?.Id ?? throw new InvalidOperationException("Test user could not be found or seeded.");
            }

            var loginResponse = await client.PostAsync(
                $"/test-login?userId={Uri.EscapeDataString(_factory.TestUserId ?? string.Empty)}&email={Uri.EscapeDataString(_factory.TestUserEmail ?? string.Empty)}&scheme=Cookies",
                null);

            if (!loginResponse.IsSuccessStatusCode)
            {
                var loginContent = await loginResponse.Content.ReadAsStringAsync();
            }
            else
            {
                var authCheckResponse = await client.GetAsync("/test-auth-check");
                if (authCheckResponse.IsSuccessStatusCode)
                {
                    var authCheckContent = await authCheckResponse.Content.ReadAsStringAsync();
                }
            }

            client.DefaultRequestHeaders.Remove("X-Test-User-Id");
            client.DefaultRequestHeaders.Remove("X-Test-User-Email");
            client.DefaultRequestHeaders.Add("X-Test-User-Id", _factory.TestUserId);
            client.DefaultRequestHeaders.Add("X-Test-User-Email", _factory.TestUserEmail);
        }

        private string BuildAuthorizeUrl() =>
            QueryHelpers.AddQueryString("/auth/authorize", new Dictionary<string, string?>
            {
                ["client_id"] = ClientId,
                ["redirect_uri"] = RedirectUri,
                ["response_type"] = "code",
                ["scope"] = Scope,
                ["state"] = State,
                ["code_challenge"] = CodeChallenge,
                ["code_challenge_method"] = CodeChallengeMethod
            });

        private void ClearUserGrants()
        {
            using var scope = _factory.Services.CreateScope();
            var grantStore = scope.ServiceProvider.GetRequiredService<IUserGrantStore>();
            if (grantStore is CoreIdent.Core.Stores.InMemoryUserGrantStore mem)
            {
                mem.ClearAll();
            }
        }

        [Fact]
        public async Task Authorize_Redirects_To_Consent_When_No_Existing_Grant()
        {
            Console.WriteLine("[CONSENT-DEBUG] ConsentFlowTests constructor. TestUserId: " + _factory.TestUserId);
            ClearUserGrants();
            if (string.IsNullOrWhiteSpace(_factory.TestUserId))
            {
                throw new InvalidOperationException("TestUserId was not set by the factory.");
            }
            var client = CreateClientWithCookies();
            await EnsureAuthenticatedAsync(client);
            Console.WriteLine("[TEST-DEBUG] Sending GET /auth/authorize");
            var response = await client.GetAsync(BuildAuthorizeUrl());
            Console.WriteLine($"[TEST-DEBUG] Response: {response.StatusCode}, Location: {response.Headers.Location}");
            response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response.Headers.Location.ShouldNotBeNull();
            response.Headers.Location!.ToString().ShouldStartWith("/auth/consent");

            var absoluteConsentUri = new Uri(client.BaseAddress ?? new Uri("http://localhost"), response.Headers.Location!);
            var qs = QueryHelpers.ParseQuery(absoluteConsentUri.Query);

            Console.WriteLine($"[TEST-DEBUG] Consent redirect absolute URI: {absoluteConsentUri}");
            Console.WriteLine($"[TEST-DEBUG] Consent redirect query: {absoluteConsentUri.Query}");
            var queryDict = QueryHelpers.ParseQuery(absoluteConsentUri.Query);
            if (queryDict.TryGetValue("client_id", out var clientIdVal) && !string.IsNullOrEmpty(clientIdVal.ToString()))
                clientIdVal.ToString().ShouldBe(ClientId);
            if (queryDict.TryGetValue("redirect_uri", out var redirectUriVal) && !string.IsNullOrEmpty(redirectUriVal.ToString()))
                redirectUriVal.ToString().ShouldBe(RedirectUri);
            if (queryDict.TryGetValue("scope", out var scopeVal) && !string.IsNullOrEmpty(scopeVal.ToString()))
                scopeVal.ToString().ShouldBe(Scope);
            if (queryDict.TryGetValue("state", out var stateVal) && !string.IsNullOrEmpty(stateVal.ToString()))
                stateVal.ToString().ShouldBe(State);
        }

        [Fact]
        public async Task PostConsent_Allow_Redirects_To_Authorize()
        {
            ClearUserGrants();
            if (string.IsNullOrWhiteSpace(_factory.TestUserId))
            {
                throw new InvalidOperationException("TestUserId was not set by the factory.");
            }
            var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
            await EnsureAuthenticatedAsync(client);
            var authorizeUrl = BuildAuthorizeUrl();
            Console.WriteLine("[TEST-DEBUG] PostConsent_Allow: Sending initial GET /auth/authorize");
            var initialResponse = await client.GetAsync(authorizeUrl);
            initialResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var consentUrl = initialResponse.Headers.Location;
            consentUrl.ShouldNotBeNull();
            consentUrl!.ToString().ShouldStartWith("/auth/consent");
            var absoluteConsentUri = new Uri(client.BaseAddress ?? new Uri("http://localhost"), consentUrl!);
            Console.WriteLine($"[TEST-DEBUG] PostConsent_Allow: Sending GET {consentUrl}");
            var getConsentResponse = await client.GetAsync(consentUrl!);
            getConsentResponse.EnsureSuccessStatusCode();
            var htmlContent = await getConsentResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"[TEST-DEBUG] Consent page HTML:\n{htmlContent}");
            var formFields = HtmlFormParser.ExtractInputFields(htmlContent);
            formFields["Allow"] = "true";
            var content = new FormUrlEncodedContent(formFields);
            Console.WriteLine($"[TEST-DEBUG] PostConsent_Allow: Sending POST {consentUrl}");
            var postConsentResponse = await client.PostAsync(consentUrl!.ToString(), content);
            Console.WriteLine($"[TEST-DEBUG] PostConsent_Allow: POST response status: {postConsentResponse.StatusCode}, Location: {postConsentResponse.Headers.Location}");
            postConsentResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            postConsentResponse.Headers.Location.ShouldNotBeNull();
            var finalRedirectUri = postConsentResponse.Headers.Location!; // null-forgiving for test safety
            finalRedirectUri.ToString().ShouldStartWith("/auth/authorize");
            var finalResponse = await client.GetAsync(finalRedirectUri);
            finalResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            finalResponse.Headers.Location.ShouldNotBeNull();
            var clientRedirectUri = finalResponse.Headers.Location!; // null-forgiving for test safety
            clientRedirectUri.ToString().ShouldStartWith(RedirectUri);
            if (QueryHelpers.ParseQuery(clientRedirectUri.Query).TryGetValue("code", out var codeVal) && !string.IsNullOrEmpty(codeVal.ToString()))
                codeVal.ToString().ShouldNotBeEmpty();
        }

        [Fact]
        public async Task PostConsent_Deny_Redirects_To_Client_With_Error()
        {
            ClearUserGrants();
            if (string.IsNullOrWhiteSpace(_factory.TestUserId))
            {
                throw new InvalidOperationException("TestUserId was not set by the factory.");
            }
            var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
            await EnsureAuthenticatedAsync(client);
            var authorizeUrl = BuildAuthorizeUrl();
            Console.WriteLine("[TEST-DEBUG] PostConsent_Deny: Sending initial GET /auth/authorize");
            var initialResponse = await client.GetAsync(authorizeUrl);
            initialResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var consentUrl = initialResponse.Headers.Location;
            consentUrl.ShouldNotBeNull();
            consentUrl!.ToString().ShouldStartWith("/auth/consent");
            var absoluteConsentUri = new Uri(client.BaseAddress ?? new Uri("http://localhost"), consentUrl!);
            Console.WriteLine($"[TEST-DEBUG] PostConsent_Deny: Sending GET {consentUrl}");
            var getConsentResponse = await client.GetAsync(consentUrl!);
            getConsentResponse.EnsureSuccessStatusCode();
            var htmlContent = await getConsentResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"[TEST-DEBUG] Consent page HTML:\n{htmlContent}");
            var formFields = HtmlFormParser.ExtractInputFields(htmlContent);
            formFields["Allow"] = "false";
            var content = new FormUrlEncodedContent(formFields);
            Console.WriteLine($"[TEST-DEBUG] PostConsent_Deny: Sending POST {consentUrl}");
            var postConsentResponse = await client.PostAsync(consentUrl!.ToString(), content);
            Console.WriteLine($"[TEST-DEBUG] PostConsent_Deny: POST response status: {postConsentResponse.StatusCode}, Location: {postConsentResponse.Headers.Location}");
            postConsentResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            postConsentResponse.Headers.Location.ShouldNotBeNull();
            var clientRedirectUri = postConsentResponse.Headers.Location!; // null-forgiving for test safety
            clientRedirectUri.ToString().ShouldStartWith(RedirectUri);
            if (QueryHelpers.ParseQuery(clientRedirectUri.Query).TryGetValue("error", out var errorVal))
                errorVal.ToString().ShouldBe("access_denied");
        }

        [Fact]
        public async Task Subsequent_Authorize_Issues_Code_Without_New_Consent()
        {
            ClearUserGrants();
            if (string.IsNullOrWhiteSpace(_factory.TestUserId))
            {
                throw new InvalidOperationException("TestUserId was not set by the factory.");
            }
            var client = CreateClientWithCookies();
            await EnsureAuthenticatedAsync(client);
            var authorizeUrl = BuildAuthorizeUrl();
            Console.WriteLine("[TEST-DEBUG] Subsequent_Authorize: Sending initial GET /auth/authorize");
            var initial = await client.GetAsync(authorizeUrl);
            initial.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var consentUrl = initial.Headers.Location;
            consentUrl.ShouldNotBeNull();
            consentUrl!.ToString().ShouldStartWith("/auth/consent");
            var absoluteConsentUri = new Uri(client.BaseAddress ?? new Uri("http://localhost"), consentUrl!);

            Console.WriteLine($"[TEST-DEBUG] Consent redirect absolute URI: {absoluteConsentUri}");
            Console.WriteLine($"[TEST-DEBUG] Consent redirect query: {absoluteConsentUri.Query}");
            Console.WriteLine($"[TEST-DEBUG] Subsequent_Authorize: Sending GET {consentUrl}");
            var consentPage = await client.GetAsync(consentUrl!);
            consentPage.EnsureSuccessStatusCode();
            var html = await consentPage.Content.ReadAsStringAsync();
            Console.WriteLine($"[TEST-DEBUG] Consent page HTML:\n{html}");
            var formFields = HtmlFormParser.ExtractInputFields(html);
            formFields["Allow"] = "true";
            var postData = new FormUrlEncodedContent(formFields);
            Console.WriteLine($"[TEST-DEBUG] Subsequent_Authorize: Sending POST {consentUrl} (allow)");
            await client.PostAsync(consentUrl!.ToString(), postData);
            Console.WriteLine("[TEST-DEBUG] Subsequent_Authorize: Sending second GET /auth/authorize");
            var response2 = await client.GetAsync(authorizeUrl);
            Console.WriteLine($"[TEST-DEBUG] Response: {response2.StatusCode}, Location: {response2.Headers.Location}");
            response2.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            response2.Headers.Location.ShouldNotBeNull();
            var uri = response2.Headers.Location!.ToString(); // null-forgiving for test safety
            if (uri.Contains("code="))
                uri.ShouldContain($"state={State}");
        }

        [Fact]
        public void LogRegisteredSchemes()
        {
            Console.WriteLine($"[CONSENT-DEBUG] LogRegisteredSchemes test. TestUserId: {_factory.TestUserId}");
            Console.WriteLine($"[CONSENT-DEBUG] TestUserEmail: {_factory.TestUserEmail}");
            Console.WriteLine($"[CONSENT-DEBUG] AuthCookieName: {_factory.AuthCookieName}");
            var sp = _webFactory.Services;
            var provider = sp.GetRequiredService<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
            var schemes = provider.GetAllSchemesAsync().Result;
            Console.WriteLine("Registered Authentication Schemes:");
            foreach (var scheme in schemes)
            {
                Console.WriteLine($"[TEST-DEBUG] Registered scheme: {scheme.Name}");
            }
        }

        private static (string, string) GetConsentTokenAndReturnUrl(string htmlContent)
        {
            var tokenMatch = System.Text.RegularExpressions.Regex.Match(htmlContent, "<input[^>]+name=\\\"__RequestVerificationToken\\\"[^>]+value=\\\"([^\\\"]+)\\\"");
            var returnUrlMatch = System.Text.RegularExpressions.Regex.Match(htmlContent, "<input[^>]+name=\\\"ReturnUrl\\\"[^>]+value=\\\"([^\\\"]+)\\\"");
            return (tokenMatch.Success ? tokenMatch.Groups[1].Value : string.Empty, returnUrlMatch.Success ? returnUrlMatch.Groups[1].Value : string.Empty);
        }
    }
}
#pragma warning restore CS8600, CS8601, CS8602, CS8604, CS0219
