using System.Net;
using CoreIdent.Integration.Tests.Infrastructure;
using CoreIdent.Testing.Fixtures;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class ConsentForbidFixtureTests : CoreIdentTestFixture
{
    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        factory.ConfigureTestServices = services =>
        {
            services.PostConfigure<AuthenticationOptions>(options =>
            {
                options.DefaultAuthenticateScheme = NoSubjectAuthenticationHandler.SchemeName;
                options.DefaultChallengeScheme = NoSubjectAuthenticationHandler.SchemeName;
            });

            services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, NoSubjectAuthenticationHandler>(
                    NoSubjectAuthenticationHandler.SchemeName,
                    _ => { });
        };
    }

    [Fact]
    public async Task Consent_post_returns_403_when_subject_id_is_missing()
    {
        using var consentPost = new HttpRequestMessage(HttpMethod.Post, "/auth/consent")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["decision"] = "allow",
                ["client_id"] = "client",
                ["redirect_uri"] = "https://client.example/cb",
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["state"] = "st",
                ["code_challenge"] = "cc",
                ["code_challenge_method"] = "S256"
            })
        };

        var response = await Client.SendAsync(consentPost);
        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, "Consent POST should return 403 when authenticated principal has no subject id.");
    }
}
