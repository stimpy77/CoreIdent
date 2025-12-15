using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using CoreIdent.Testing.Fixtures;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.ResourceOwner;

public sealed class PasswordlessEmailEndpointsFixtureTests : CoreIdentTestFixture
{
    private CapturingEmailSender _emailSender = null!;
    private MutableTimeProvider _timeProvider = null!;

    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        _emailSender = new CapturingEmailSender();
        _timeProvider = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        factory.ConfigureTestServices = services =>
        {
            services.Configure<PasswordlessEmailOptions>(opts =>
            {
                opts.SuccessRedirectUrl = "https://client.example/signed-in";
                opts.MaxAttemptsPerHour = 10;
                opts.TokenLifetime = TimeSpan.FromMinutes(15);
            });

            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(_timeProvider);

            services.RemoveAll<IEmailSender>();
            services.AddSingleton(_emailSender);
            services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<CapturingEmailSender>());
        };
    }

    [Fact]
    public async Task Start_then_verify_redirects_with_tokens()
    {
        _emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "user@example.com" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        _emailSender.LastMessage.ShouldNotBeNull("email sender should be invoked");

        var verifyUrl = ExtractVerifyUrl(_emailSender.LastMessage!.HtmlBody);
        verifyUrl.ShouldNotBeNullOrWhiteSpace("verify url should be present in email body");

        var verifyResponse = await Client.GetAsync(verifyUrl);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect, "verify should redirect to success URL");

        var location = verifyResponse.Headers.Location;
        location.ShouldNotBeNull();
        location!.AbsoluteUri.ShouldStartWith("https://client.example/signed-in", Shouldly.Case.Sensitive);

        var query = QueryHelpers.ParseQuery(location.Query);
        query.TryGetValue("access_token", out var accessToken).ShouldBeTrue("access_token should be present");
        query.TryGetValue("refresh_token", out var refreshToken).ShouldBeTrue("refresh_token should be present");

        accessToken.ToString().ShouldNotBeNullOrWhiteSpace();
        refreshToken.ToString().ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Verify_with_expired_token_returns_bad_request()
    {
        _emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "expire@example.com" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var verifyUrl = ExtractVerifyUrl(_emailSender.LastMessage!.HtmlBody);
        verifyUrl.ShouldNotBeNullOrWhiteSpace();

        _timeProvider.Advance(TimeSpan.FromMinutes(16));

        var verifyResponse = await Client.GetAsync(verifyUrl);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Verify_with_already_consumed_token_returns_bad_request()
    {
        _emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "consumed@example.com" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var verifyUrl = ExtractVerifyUrl(_emailSender.LastMessage!.HtmlBody);
        verifyUrl.ShouldNotBeNullOrWhiteSpace();

        var first = await Client.GetAsync(verifyUrl);
        first.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var second = await Client.GetAsync(verifyUrl);
        second.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Existing_user_is_authenticated_and_subject_matches()
    {
        _emailSender.Clear();

        var existing = await CreateUserAsync(u => u.WithEmail("existing@example.com"));

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "existing@example.com" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var verifyUrl = ExtractVerifyUrl(_emailSender.LastMessage!.HtmlBody);
        verifyUrl.ShouldNotBeNullOrWhiteSpace();

        var verifyResponse = await Client.GetAsync(verifyUrl);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var location = verifyResponse.Headers.Location;
        location.ShouldNotBeNull();

        var query = QueryHelpers.ParseQuery(location!.Query);
        query.TryGetValue("access_token", out var accessToken).ShouldBeTrue();

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(accessToken.ToString());
        var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
        sub.ShouldBe(existing.Id, "passwordless verify should authenticate the existing user");
    }

    private static string ExtractVerifyUrl(string html)
    {
        var match = Regex.Match(html, "href=\"(?<url>[^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups["url"].Value : string.Empty;
    }

    private sealed class CapturingEmailSender : IEmailSender
    {
        public EmailMessage? LastMessage { get; private set; }

        public void Clear()
        {
            LastMessage = null;
        }

        public Task SendAsync(EmailMessage message, CancellationToken ct = default)
        {
            LastMessage = message;
            return Task.CompletedTask;
        }
    }

    private sealed class MutableTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public MutableTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public void Advance(TimeSpan delta)
        {
            _utcNow = _utcNow.Add(delta);
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }
}
