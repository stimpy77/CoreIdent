using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Testing.Fixtures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.UserInfo;

public sealed class UserInfoEndpointAdditionalFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task UserInfo_returns_403_when_openid_scope_missing()
    {
        var user = await CreateUserAsync(u => u.WithEmail("no-openid@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("no-openid-client")
            .AsConfidentialClient("no-openid-secret")
            .WithGrantTypes(GrantTypes.Password)
            .WithScopes("profile"));

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = user.UserName,
                ["password"] = "Test123!",
                ["scope"] = "profile"
            })
        };

        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("no-openid-client:no-openid-secret")));

        var tokenResponse = await Client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokens = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        tokens.ShouldNotBeNull();

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/userinfo");
        userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        var userInfoResponse = await Client.SendAsync(userInfoRequest);
        userInfoResponse.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task UserInfo_returns_401_when_subject_user_does_not_exist()
    {
        await CreateClientAsync(c => c
            .WithClientId("userinfo-missing-user-client")
            .AsConfidentialClient("userinfo-missing-user-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        var provider = Services.GetRequiredService<ISigningKeyProvider>();
        var creds = await provider.GetSigningCredentialsAsync();

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://localhost",
            Audience = "https://localhost",
            Expires = DateTime.UtcNow.AddMinutes(5),
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "missing-user"),
                new Claim("scope", "openid"),
                new Claim("client_id", "userinfo-missing-user-client")
            }),
            SigningCredentials = creds
        });

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/userinfo");
        userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await Client.SendAsync(userInfoRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task UserInfo_normalizes_profile_and_includes_phone_claims_when_scoped()
    {
        var user = await CreateUserAsync(u => u
            .WithEmail("userinfo-names@example.com")
            .WithPassword("Test123!")
            .WithClaim(ClaimTypes.GivenName, "Alice")
            .WithClaim(ClaimTypes.Surname, "Smith")
            .WithClaim("phone_number", "+15550001111")
            .WithClaim("phone_number", "+15550002222"));

        await CreateClientAsync(c => c
            .WithClientId("userinfo-names-client")
            .AsConfidentialClient("userinfo-names-secret")
            .WithGrantTypes(GrantTypes.Password)
            .WithScopes("openid", "profile", "phone"));

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = user.UserName,
                ["password"] = "Test123!",
                ["scope"] = "openid profile phone"
            })
        };

        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("userinfo-names-client:userinfo-names-secret")));

        var tokenResponse = await Client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokens = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        tokens.ShouldNotBeNull();

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/userinfo");
        userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        var userInfoResponse = await Client.SendAsync(userInfoRequest);
        userInfoResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var json = await userInfoResponse.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        doc.RootElement.GetProperty("given_name").GetString().ShouldBe("Alice");
        doc.RootElement.GetProperty("family_name").GetString().ShouldBe("Smith");

        var phone = doc.RootElement.GetProperty("phone_number");
        phone.ValueKind.ShouldBe(JsonValueKind.Array);
        phone.EnumerateArray().Select(x => x.GetString()).ShouldBe(new[] { "+15550001111", "+15550002222" });
    }
}
