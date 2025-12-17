using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using CoreIdent.Testing.Fixtures;
using CoreIdent.Testing.Mocks;
using CoreIdent.Testing.TestUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.ResourceOwner;

public sealed class PasswordlessSmsEndpointsFixtureTests : CoreIdentTestFixture
{
    private MockSmsProvider _smsProvider = null!;
    private MutableTimeProvider _timeProvider = null!;

    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        _smsProvider = new MockSmsProvider();
        _timeProvider = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        factory.ConfigureTestServices = services =>
        {
            services.Configure<PasswordlessSmsOptions>(opts =>
            {
                opts.MaxAttemptsPerHour = 2;
                opts.OtpLifetime = TimeSpan.FromMinutes(5);
            });

            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(_timeProvider);

            services.RemoveAll<ISmsProvider>();
            services.AddSingleton(_smsProvider);
            services.AddSingleton<ISmsProvider>(sp => sp.GetRequiredService<MockSmsProvider>());
        };
    }

    [Fact]
    public async Task Start_sends_otp_via_provider()
    {
        _smsProvider.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/sms/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { phone_number = "+15551234567" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        _smsProvider.LastMessage.ShouldNotBeNull("sms provider should be invoked");
        _smsProvider.LastMessage!.PhoneNumber.ShouldBe("+15551234567");

        ExtractOtp(_smsProvider.LastMessage!.Message).ShouldNotBeNullOrWhiteSpace("otp should be present in sms message");
    }

    [Fact]
    public async Task Start_then_verify_returns_tokens_json()
    {
        _smsProvider.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/sms/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { phone_number = "+15550001111" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var otp = ExtractOtp(_smsProvider.LastMessage!.Message);
        otp.ShouldNotBeNullOrWhiteSpace("otp should be extractable");

        using var verifyRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/sms/verify");
        verifyRequest.Headers.Accept.ParseAdd("application/json");
        verifyRequest.Content = JsonContent.Create(new { phone_number = "+15550001111", otp });

        var verifyResponse = await Client.SendAsync(verifyRequest);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokenResponse = await verifyResponse.Content.ReadFromJsonAsync<Dictionary<string, object?>>();
        tokenResponse.ShouldNotBeNull();
        tokenResponse!.ContainsKey("access_token").ShouldBeTrue("access_token should be present");
        tokenResponse.ContainsKey("refresh_token").ShouldBeTrue("refresh_token should be present");
    }

    [Fact]
    public async Task Verify_with_expired_otp_returns_bad_request()
    {
        _smsProvider.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/sms/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { phone_number = "+15552223333" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var otp = ExtractOtp(_smsProvider.LastMessage!.Message);
        otp.ShouldNotBeNullOrWhiteSpace();

        _timeProvider.Advance(TimeSpan.FromMinutes(6));

        using var verifyRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/sms/verify");
        verifyRequest.Headers.Accept.ParseAdd("application/json");
        verifyRequest.Content = JsonContent.Create(new { phone_number = "+15552223333", otp });

        var verifyResponse = await Client.SendAsync(verifyRequest);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        verifyResponse.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json", "Expired OTP should return RFC 7807 Problem Details for JSON clients.");

        var body = await verifyResponse.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("status").GetInt32().ShouldBe((int)HttpStatusCode.BadRequest);
        doc.RootElement.GetProperty("error_code").GetString().ShouldBe("invalid_request");
        doc.RootElement.GetProperty("correlation_id").GetString().ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Start_rate_limit_is_enforced()
    {
        _smsProvider.Clear();

        var phone = "+15553334444";

        for (var i = 0; i < 3; i++)
        {
            using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/sms/start");
            startRequest.Headers.Accept.ParseAdd("application/json");
            startRequest.Content = JsonContent.Create(new { phone_number = phone });

            var resp = await Client.SendAsync(startRequest);
            resp.StatusCode.ShouldBe(HttpStatusCode.OK);
        }

        _smsProvider.Messages.Count.ShouldBe(2, "provider should only be called up to MaxAttemptsPerHour");
    }

    private static string ExtractOtp(string message)
    {
        var match = Regex.Match(message, "(?<otp>\\d{6})", RegexOptions.CultureInvariant);
        return match.Success ? match.Groups["otp"].Value : string.Empty;
    }
}
