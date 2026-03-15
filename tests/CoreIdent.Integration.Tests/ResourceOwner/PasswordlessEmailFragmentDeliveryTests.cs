using System.Net;
using System.Net.Http.Json;
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

public sealed class PasswordlessEmailFragmentDeliveryTests : CoreIdentTestFixture
{
    private MockEmailSender _emailSender = null!;

    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        _emailSender = new MockEmailSender();

        factory.ConfigureTestServices = services =>
        {
            services.Configure<PasswordlessEmailOptions>(opts =>
            {
                opts.SuccessRedirectUrl = "https://client.example/signed-in";
                opts.MaxAttemptsPerHour = 10;
                opts.TokenLifetime = TimeSpan.FromMinutes(15);
                opts.TokenDelivery = TokenDeliveryMode.Fragment;
            });

            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero)));

            services.RemoveAll<IEmailSender>();
            services.AddSingleton(_emailSender);
            services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<MockEmailSender>());
        };
    }

    [Fact]
    public async Task Verify_with_fragment_mode_redirects_with_hash_tokens()
    {
        _emailSender.Clear();

        using var startRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/passwordless/email/start");
        startRequest.Headers.Accept.ParseAdd("application/json");
        startRequest.Content = JsonContent.Create(new { email = "fragment@example.com" });

        var startResponse = await Client.SendAsync(startRequest);
        startResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var verifyUrl = ExtractVerifyUrl(_emailSender.LastMessage!.HtmlBody);
        verifyUrl.ShouldNotBeNullOrWhiteSpace("verify url should be present in email body");

        var verifyResponse = await Client.GetAsync(verifyUrl);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect, "verify should redirect to success URL");

        var location = verifyResponse.Headers.Location;
        location.ShouldNotBeNull();

        var uri = location!.OriginalString;
        uri.ShouldStartWith("https://client.example/signed-in#");
        uri.ShouldContain("access_token=");
        uri.ShouldContain("refresh_token=");
        uri.ShouldNotContain("?access_token=");
    }

    private static string ExtractVerifyUrl(string html)
    {
        var match = Regex.Match(html, "href=\"(?<url>[^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups["url"].Value : string.Empty;
    }
}
