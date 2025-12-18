using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using CoreIdent.Testing.Fixtures;
using CoreIdent.Testing.Mocks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Infrastructure;

public sealed class PasswordlessSensitiveLoggingFixtureTests : CoreIdentTestFixture
{
    private MockSmsProvider _smsProvider = null!;
    private MockEmailSender _emailSender = null!;
    private TestLoggerProvider _loggerProvider = null!;

    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        _smsProvider = new MockSmsProvider();
        _emailSender = new MockEmailSender();
        _loggerProvider = new TestLoggerProvider();

        factory.ConfigureTestServices = services =>
        {
            services.Configure<PasswordlessEmailOptions>(opts =>
            {
                opts.SuccessRedirectUrl = "https://client.example/signed-in";
                opts.MaxAttemptsPerHour = 10;
                opts.TokenLifetime = TimeSpan.FromMinutes(15);
            });

            services.Configure<PasswordlessSmsOptions>(opts =>
            {
                opts.MaxAttemptsPerHour = 10;
                opts.OtpLifetime = TimeSpan.FromMinutes(5);
            });

            services.RemoveAll<ISmsProvider>();
            services.AddSingleton(_smsProvider);
            services.AddSingleton<ISmsProvider>(sp => sp.GetRequiredService<MockSmsProvider>());

            services.RemoveAll<IEmailSender>();
            services.AddSingleton(_emailSender);
            services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<MockEmailSender>());

            services.AddSingleton<ILoggerProvider>(_loggerProvider);
        };
    }

    [Fact]
    public async Task Passwordless_sms_start_does_not_log_otp()
    {
        _smsProvider.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/sms/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { phone_number = "+15551234567" });

        var response = await Client.SendAsync(startRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "SMS start should return 200 OK.");

        _smsProvider.LastMessage.ShouldNotBeNull("SMS provider should be invoked.");
        var otp = ExtractOtp(_smsProvider.LastMessage!.Message);
        otp.ShouldNotBeNullOrWhiteSpace("OTP should be present in SMS message.");

        _loggerProvider.Entries.Any(e => e.Message.Contains(otp, StringComparison.Ordinal))
            .ShouldBeFalse("Logs must not contain the OTP value.");
    }

    [Fact]
    public async Task Passwordless_email_start_does_not_log_magic_link_token()
    {
        _emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "user@example.com" });

        var response = await Client.SendAsync(startRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Email start should return 200 OK.");

        _emailSender.LastMessage.ShouldNotBeNull("Email sender should be invoked.");

        var verifyUrl = ExtractVerifyUrl(_emailSender.LastMessage!.HtmlBody);
        verifyUrl.ShouldNotBeNullOrWhiteSpace("Verify URL should be included in email body.");

        var uri = new Uri(verifyUrl, UriKind.RelativeOrAbsolute);
        var query = QueryHelpers.ParseQuery(uri.IsAbsoluteUri ? uri.Query : new Uri("https://host.example" + verifyUrl).Query);

        query.TryGetValue("token", out var token).ShouldBeTrue("Verify URL should include token query parameter.");
        token.ToString().ShouldNotBeNullOrWhiteSpace("Token query parameter should have a value.");

        _loggerProvider.Entries.Any(e => e.Message.Contains(token.ToString(), StringComparison.Ordinal))
            .ShouldBeFalse("Logs must not contain the magic link token value.");
    }

    private static string ExtractOtp(string message)
    {
        var match = Regex.Match(message, "(?<otp>\\d{6})", RegexOptions.CultureInvariant);
        return match.Success ? match.Groups["otp"].Value : string.Empty;
    }

    private static string ExtractVerifyUrl(string html)
    {
        var match = Regex.Match(html, "href=\"(?<url>[^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups["url"].Value : string.Empty;
    }
}
