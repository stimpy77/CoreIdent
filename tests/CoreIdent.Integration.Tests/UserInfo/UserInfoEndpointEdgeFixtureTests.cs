using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Testing.Fixtures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.UserInfo;

public sealed class UserInfoEndpointEdgeFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Invalid_authorization_header_returns_401()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/userinfo");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "abc");

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "UserInfo should return 401 for non-bearer authorization headers.");
    }

    [Fact]
    public async Task With_openid_email_scope_and_non_email_username_does_not_emit_email()
    {
        var user = await CreateUserAsync(u => u
            .WithEmail("15550001111")
            .WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("userinfo-phone-client")
            .AsConfidentialClient("userinfo-phone-secret")
            .WithGrantTypes(GrantTypes.Password)
            .WithScopes("openid", "email"));

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = user.UserName,
                ["password"] = "Test123!",
                ["scope"] = "openid email"
            })
        };

        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("userinfo-phone-client:userinfo-phone-secret")));

        var tokenResponse = await Client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Token endpoint should return 200 OK.");

        var tokens = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        tokens.ShouldNotBeNull("Token response should deserialize.");
        tokens!.AccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be present.");

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/userinfo");
        userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var userInfoResponse = await Client.SendAsync(userInfoRequest);
        userInfoResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "UserInfo should return 200 OK for valid token.");

        var json = await userInfoResponse.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        doc.RootElement.TryGetProperty("email", out _).ShouldBeFalse("UserInfo should not infer email when username is not an email address.");
    }

    public sealed class EmptyValidationKeysSigningKeyProvider : ISigningKeyProvider
    {
        public string Algorithm => SecurityAlgorithms.HmacSha256;

        public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default)
            => Task.FromResult(new SigningCredentials(new SymmetricSecurityKey(new byte[32]), Algorithm));

        public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default)
            => Task.FromResult<IEnumerable<SecurityKeyInfo>>(Array.Empty<SecurityKeyInfo>());
    }

    [Fact]
    public async Task UserInfo_returns_401_when_signing_key_provider_returns_no_validation_keys()
    {
        using var scope = Services.CreateScope();

        using var factory = new CoreIdentWebApplicationFactory();
        factory.ConfigureTestServices = services =>
        {
            services.RemoveAll<ISigningKeyProvider>();
            services.AddSingleton<ISigningKeyProvider>(new EmptyValidationKeysSigningKeyProvider());
        };

        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        factory.EnsureSeeded();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/userinfo");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "not-a-jwt");

        var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "UserInfo should return 401 when no validation keys are available.");
    }
}
