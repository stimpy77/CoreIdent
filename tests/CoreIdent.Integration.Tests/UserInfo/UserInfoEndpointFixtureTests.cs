using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.UserInfo;

public sealed class UserInfoEndpointFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Unauthenticated_request_returns_401()
    {
        var response = await Client.GetAsync("/auth/userinfo");
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "UserInfo should return 401 for missing bearer token.");
    }

    [Fact]
    public async Task With_openid_profile_scope_userinfo_returns_sub_and_profile_claims()
    {
        var user = await CreateUserAsync(u => u
            .WithEmail("userinfo-profile@example.com")
            .WithPassword("Test123!")
            .WithClaim("name", "Alice"));

        await CreateClientAsync(c => c
            .WithClientId("userinfo-profile-client")
            .AsConfidentialClient("userinfo-profile-secret")
            .WithGrantTypes(GrantTypes.Password)
            .WithScopes("openid", "profile"));

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = user.UserName,
                ["password"] = "Test123!",
                ["scope"] = "openid profile"
            })
        };

        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("userinfo-profile-client:userinfo-profile-secret")));

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

        doc.RootElement.GetProperty("sub").GetString().ShouldBe(user.Id, "UserInfo should include sub.");
        doc.RootElement.GetProperty("name").GetString().ShouldBe("Alice", "UserInfo should include profile name when profile scope is granted.");
    }

    [Fact]
    public async Task With_openid_email_scope_userinfo_returns_email()
    {
        var user = await CreateUserAsync(u => u
            .WithEmail("userinfo-email@example.com")
            .WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("userinfo-email-client")
            .AsConfidentialClient("userinfo-email-secret")
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
            Convert.ToBase64String(Encoding.UTF8.GetBytes("userinfo-email-client:userinfo-email-secret")));

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

        doc.RootElement.GetProperty("email").GetString().ShouldBe(user.UserName, "UserInfo should include email when email scope is granted.");
    }
}
