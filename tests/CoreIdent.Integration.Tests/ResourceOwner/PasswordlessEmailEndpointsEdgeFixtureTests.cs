using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Testing.Fixtures;
using CoreIdent.Testing.Mocks;
using CoreIdent.Testing.TestUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.ResourceOwner;

public sealed class PasswordlessEmailEndpointsEdgeFixtureTests : CoreIdentTestFixture
{
    private MockEmailSender _emailSender = null!;
    private MutableTimeProvider _timeProvider = null!;

    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        _emailSender = new MockEmailSender();
        _timeProvider = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        factory.ConfigureTestServices = services =>
        {
            services.Configure<PasswordlessEmailOptions>(opts =>
            {
                opts.SuccessRedirectUrl = string.Empty;
                opts.MaxAttemptsPerHour = 10;
                opts.TokenLifetime = TimeSpan.FromMinutes(15);
                opts.VerifyEndpointUrl = "https://verify.example/passwordless/email/verify";
            });

            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(_timeProvider);

            services.RemoveAll<IEmailSender>();
            services.AddSingleton(_emailSender);
            services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<MockEmailSender>());
        };
    }

    [Fact]
    public async Task Start_with_invalid_email_returns_ok_and_does_not_send_email()
    {
        _emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "not-an-email" });

        var response = await Client.SendAsync(startRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Start should return 200 even for invalid emails.");

        _emailSender.LastMessage.ShouldBeNull("Email sender should not be invoked for invalid email input.");
    }

    [Fact]
    public async Task Start_with_form_content_type_sends_email()
    {
        _emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["email"] = "form-user@example.com"
        });

        var response = await Client.SendAsync(startRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Start should return 200 OK for valid emails submitted via form.");

        _emailSender.LastMessage.ShouldNotBeNull("Email sender should be invoked for valid form input.");
    }

    [Fact]
    public async Task Verify_without_token_returns_html_error_for_html_clients()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/passwordless/email/verify");
        request.Headers.Accept.ParseAdd("text/html");

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Missing token should return 400.");
        response.Content.Headers.ContentType?.MediaType.ShouldBe("text/html", "HTML clients should get text/html error response.");

        var html = await response.Content.ReadAsStringAsync();
        html.ShouldContain("<h1>Error</h1>", Shouldly.Case.Sensitive, "HTML error response should include Error heading.");
    }

    [Fact]
    public async Task Verify_without_success_redirect_returns_html_success_page()
    {
        // Use the standard token store for this test, just configure SuccessRedirectUrl to be empty
        using var factory = new CoreIdentWebApplicationFactory();
        var emailSender = new MockEmailSender();
        
        factory.ConfigureTestServices = services =>
        {
            services.Configure<PasswordlessEmailOptions>(opts =>
            {
                opts.SuccessRedirectUrl = ""; // Empty to test HTML response
                opts.MaxAttemptsPerHour = 10;
                opts.TokenLifetime = TimeSpan.FromMinutes(15);
            });

            services.RemoveAll<IEmailSender>();
            services.AddSingleton(emailSender);
            services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<MockEmailSender>());
        };

        using var client = factory.CreateClient();
        emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "html-success@example.com" });

        var startResponse = await client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Start should return 200 OK.");

        emailSender.LastMessage.ShouldNotBeNull("Email sender should be invoked.");

        var verifyUrl = ExtractVerifyUrl(emailSender.LastMessage!.HtmlBody);
        verifyUrl.ShouldNotBeNullOrWhiteSpace("Verify URL should be included in email.");

        var verifyResponse = await client.GetAsync(verifyUrl);
        
        // If we get BadRequest, let's debug the error response
        if (verifyResponse.StatusCode == HttpStatusCode.BadRequest)
        {
            var errorContent = await verifyResponse.Content.ReadAsStringAsync();
            verifyResponse.StatusCode.ShouldBe(HttpStatusCode.OK, $"Verify should return HTML page when SuccessRedirectUrl is empty. Got BadRequest with content: {errorContent}");
        }

        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Verify should return HTML page when SuccessRedirectUrl is empty.");

        verifyResponse.Content.Headers.ContentType?.MediaType.ShouldBe("text/html", "Verify should return HTML content when not redirecting.");

        var html = await verifyResponse.Content.ReadAsStringAsync();
        html.ShouldContain("Signed in", Shouldly.Case.Sensitive, "Verify HTML response should indicate authentication success.");
    }

    [Fact]
    public async Task Start_rate_limit_exceeded_is_handled_and_still_returns_ok()
    {
        using var factory = new CoreIdentWebApplicationFactory();

        var emailSender = new MockEmailSender();

        factory.ConfigureTestServices = services =>
        {
            services.Configure<PasswordlessEmailOptions>(opts =>
            {
                opts.SuccessRedirectUrl = string.Empty;
                opts.MaxAttemptsPerHour = 10;
                opts.TokenLifetime = TimeSpan.FromMinutes(15);
            });

            services.RemoveAll<IEmailSender>();
            services.AddSingleton(emailSender);
            services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<MockEmailSender>());

            services.RemoveAll<IPasswordlessTokenStore>();
            services.AddSingleton<IPasswordlessTokenStore>(new ThrowingPasswordlessTokenStore(throwRateLimit: true));
        };

        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        factory.EnsureSeeded();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "rate-limit@example.com" });

        var response = await client.SendAsync(startRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Start should still return 200 OK when rate limit exception occurs.");

        emailSender.LastMessage.ShouldBeNull("Email sender should not be invoked when token store throws rate limit exception.");
    }

    private static string ExtractVerifyUrl(string html)
    {
        var match = Regex.Match(html, "href=\"(?<url>[^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups["url"].Value : string.Empty;
    }

    private static string ComputeTokenHash(string token)
    {
        return System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token))
            .Select(b => b.ToString("x2"))
            .Aggregate(string.Concat);
    }

    private sealed class ThrowingPasswordlessTokenStore : IPasswordlessTokenStore
    {
        private readonly bool _throwRateLimit;
        private string? _lastRawToken;
        private PasswordlessToken? _lastPasswordlessToken;

        public ThrowingPasswordlessTokenStore(bool throwRateLimit = false)
        {
            _throwRateLimit = throwRateLimit;
        }

        public Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default)
        {
            if (_throwRateLimit)
            {
                throw new PasswordlessRateLimitExceededException();
            }

            // Generate a simple token and store it
            _lastRawToken = "test-token-" + Guid.NewGuid().ToString("N")[..8];
            _lastPasswordlessToken = new PasswordlessToken
            {
                Id = token.Id,
                Email = token.Email,
                Recipient = token.Recipient,
                TokenType = token.TokenType,
                TokenHash = ComputeTokenHash(_lastRawToken),
                CreatedAt = token.CreatedAt,
                ExpiresAt = token.ExpiresAt,
                Consumed = false,
                UserId = token.UserId
            };
            return Task.FromResult(_lastRawToken);
        }

        public Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default)
        {
            return ValidateAndConsumeAsync(token, tokenType: null, recipient: null, ct);
        }

        public Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, string? tokenType, string? recipient, CancellationToken ct = default)
        {
            if (_lastPasswordlessToken != null && !string.IsNullOrWhiteSpace(_lastRawToken))
            {
                var tokenHash = ComputeTokenHash(token);
                if (tokenHash == _lastPasswordlessToken.TokenHash && !_lastPasswordlessToken.Consumed)
                {
                    var result = _lastPasswordlessToken;
                    result.Consumed = true; // Mark as consumed
                    _lastPasswordlessToken = null; // Clear after consumption
                    _lastRawToken = null;
                    return Task.FromResult<PasswordlessToken?>(result);
                }
            }
            return Task.FromResult<PasswordlessToken?>(null);
        }

        public Task CleanupExpiredAsync(CancellationToken ct = default)
        {
            return Task.CompletedTask;
        }
    }
}
