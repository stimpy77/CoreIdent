using System.Net;
using System.Net.Http.Json;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class TokenManagementEndpointsEdgeFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Revoke_rejects_non_form_content_type()
    {
        await CreateClientAsync(c => c
            .WithClientId("revoke-edge-client")
            .AsConfidentialClient("revoke-edge-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = JsonContent.Create(new { token = "abc" })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("revoke-edge-client:revoke-edge-secret")));

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var body = await response.Content.ReadAsStringAsync();
        body.ShouldContain("invalid_request");
    }

    [Fact]
    public async Task Revoke_requires_client_authentication()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "abc",
                ["token_type_hint"] = "refresh_token"
            })
        };

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var json = await response.Content.ReadAsStringAsync();
        json.ShouldContain("invalid_client");
    }

    [Fact]
    public async Task Revoke_refresh_token_attempt_by_different_client_does_not_revoke()
    {
        var user = await CreateUserAsync(u => u.WithEmail("rt-owner@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("rt-owner-client")
            .AsConfidentialClient("rt-owner-secret")
            .WithGrantTypes(GrantTypes.Password, GrantTypes.RefreshToken)
            .AllowOfflineAccess(true)
            .WithScopes("openid", "offline_access"));

        await CreateClientAsync(c => c
            .WithClientId("rt-attacker-client")
            .AsConfidentialClient("rt-attacker-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        using var issue = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = user.UserName,
                ["password"] = "Test123!",
                ["scope"] = "openid offline_access"
            })
        };

        issue.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("rt-owner-client:rt-owner-secret")));

        var issuedResponse = await Client.SendAsync(issue);
        issuedResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var issued = await issuedResponse.Content.ReadFromJsonAsync<TokenResponse>();
        issued.ShouldNotBeNull();
        issued!.RefreshToken.ShouldNotBeNullOrWhiteSpace();

        using var revoke = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = issued.RefreshToken!,
                ["token_type_hint"] = "refresh_token"
            })
        };

        revoke.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("rt-attacker-client:rt-attacker-secret")));

        var revokeResponse = await Client.SendAsync(revoke);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        using var refresh = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.RefreshToken,
                ["refresh_token"] = issued.RefreshToken!
            })
        };

        refresh.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("rt-owner-client:rt-owner-secret")));

        var refreshResponse = await Client.SendAsync(refresh);
        refreshResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Refresh should still succeed since the token belongs to a different client.");
    }

    [Fact]
    public async Task Introspect_with_invalid_basic_header_uses_form_credentials_and_returns_inactive_for_unknown_token()
    {
        await CreateClientAsync(c => c
            .WithClientId("introspect-form-client")
            .AsConfidentialClient("introspect-form-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        using var introspect = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "not-a-jwt",
                ["client_id"] = "introspect-form-client",
                ["client_secret"] = "introspect-form-secret"
            })
        };

        introspect.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "not-base64");

        var response = await Client.SendAsync(introspect);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload!.Active.ShouldBeFalse();
    }

    [Fact]
    public async Task Introspect_access_token_hint_with_invalid_jwt_returns_inactive()
    {
        await CreateClientAsync(c => c
            .WithClientId("introspect-invalid-jwt")
            .AsConfidentialClient("introspect-invalid-jwt-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        using var introspect = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "not-a-jwt",
                ["token_type_hint"] = "access_token"
            })
        };

        introspect.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("introspect-invalid-jwt:introspect-invalid-jwt-secret")));

        var response = await Client.SendAsync(introspect);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload!.Active.ShouldBeFalse();
    }
}
