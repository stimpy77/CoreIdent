using System.Net;
using System.Net.Http.Json;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class TokenRevocationFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Revoke_refresh_token_makes_it_unusable_for_refresh_grant()
    {
        var user = await CreateUserAsync(u => u.WithEmail("revoke-rt-user@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("rt-revoke-client")
            .AsConfidentialClient("rt-revoke-secret")
            .WithGrantTypes(GrantTypes.Password, GrantTypes.RefreshToken)
            .AllowOfflineAccess(true)
            .WithScopes("openid", "offline_access"));

        var tokenResponse = await RequestPasswordGrantAsync(
            clientId: "rt-revoke-client",
            clientSecret: "rt-revoke-secret",
            username: user.UserName,
            password: "Test123!",
            scope: "openid offline_access");

        tokenResponse.RefreshToken.ShouldNotBeNullOrWhiteSpace("Password grant should yield refresh_token when offline_access is granted.");

        using var revoke = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = tokenResponse.RefreshToken!,
                ["token_type_hint"] = "refresh_token"
            })
        };

        revoke.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("rt-revoke-client:rt-revoke-secret")));

        var revokeResponse = await Client.SendAsync(revoke);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation endpoint should return 200 OK for refresh token revocation.");

        using var refresh = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.RefreshToken,
                ["refresh_token"] = tokenResponse.RefreshToken!
            })
        };

        refresh.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("rt-revoke-client:rt-revoke-secret")));

        var refreshResponse = await Client.SendAsync(refresh);
        refreshResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "A revoked refresh token must not be usable for the refresh_token grant.");

        var error = await refreshResponse.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull("Response should deserialize to TokenErrorResponse.");
        error.Error.ShouldBe(TokenErrors.InvalidGrant, "Using a revoked refresh token should return invalid_grant.");
    }

    [Fact]
    public async Task Revoke_access_token_makes_introspection_inactive()
    {
        await CreateClientAsync(c => c
            .WithClientId("at-revoke-client")
            .AsConfidentialClient("at-revoke-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        var tokenResponse = await RequestClientCredentialsAsync(
            clientId: "at-revoke-client",
            clientSecret: "at-revoke-secret",
            scope: "api");

        using var revoke = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = tokenResponse.AccessToken,
                ["token_type_hint"] = "access_token"
            })
        };

        revoke.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("at-revoke-client:at-revoke-secret")));

        var revokeResponse = await Client.SendAsync(revoke);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation endpoint should return 200 OK for access token revocation.");

        using var introspect = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = tokenResponse.AccessToken,
                ["token_type_hint"] = "access_token"
            })
        };

        introspect.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("at-revoke-client:at-revoke-secret")));

        var introspectResponse = await Client.SendAsync(introspect);
        introspectResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Introspection endpoint should return 200 OK for authenticated requests.");

        var payload = await introspectResponse.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull("Introspection response should deserialize to TokenIntrospectionResponse.");
        payload.Active.ShouldBeFalse("Revoked access tokens should be reported as inactive.");
    }

    private async Task<TokenResponse> RequestClientCredentialsAsync(string clientId, string clientSecret, string? scope)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["scope"] = scope ?? string.Empty
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}")));

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Client credentials grant should return 200 OK.");

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull("Token response should deserialize to TokenResponse.");
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("access_token should be present.");

        return tokenResponse;
    }

    private async Task<TokenResponse> RequestPasswordGrantAsync(
        string clientId,
        string clientSecret,
        string username,
        string password,
        string? scope)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = username,
                ["password"] = password,
                ["scope"] = scope ?? string.Empty
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}")));

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Password grant should succeed in test fixture when client and credentials are valid.");

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull("Password grant response should deserialize to TokenResponse.");

        return tokenResponse;
    }
}
