using System.Net;
using CoreIdent.Integration.Tests.Infrastructure;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class AuthorizationForbidFixtureTests : CoreIdentTestFixture
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
    public async Task Authorize_returns_403_when_subject_id_is_missing()
    {
        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("authorize-forbid")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var response = await Client.GetAsync($"/auth/authorize?client_id=authorize-forbid" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&scope={Uri.EscapeDataString("openid")}" +
                                             $"&state=st" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=S256");

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, "Authorize should return 403 when authenticated principal has no subject id.");
    }
}
