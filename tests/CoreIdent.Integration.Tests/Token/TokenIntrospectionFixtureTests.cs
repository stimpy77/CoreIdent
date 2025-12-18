using System.Net;
using System.Net.Http.Json;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class TokenIntrospectionFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Introspection_returns_active_true_for_valid_access_token()
    {
        await CreateClientAsync(c => c
            .WithClientId("issuing-client")
            .AsConfidentialClient("issuing-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        await CreateClientAsync(c => c
            .WithClientId("introspect-client")
            .AsConfidentialClient("introspect-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        var tokenResponse = await RequestClientCredentialsAsync(
            clientId: "issuing-client",
            clientSecret: "issuing-secret",
            scope: "api");

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
            Convert.ToBase64String(Encoding.UTF8.GetBytes("introspect-client:introspect-secret")));

        var response = await Client.SendAsync(introspect);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Introspection endpoint should return 200 OK for authenticated requests.");

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull("Introspection response should deserialize to TokenIntrospectionResponse.");
        payload.Active.ShouldBeTrue("Valid access tokens should be reported as active.");
        payload.TokenType.ShouldBe("Bearer", "Access token introspection should return token_type=Bearer.");
        payload.ClientId.ShouldBe("issuing-client", "client_id should reflect the token's client_id claim.");
        payload.Exp.ShouldNotBeNull("exp should be present for active tokens.");
    }

    [Fact]
    public async Task Introspection_returns_active_true_for_valid_refresh_token()
    {
        var user = await CreateUserAsync(u => u.WithEmail("introspect-user@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("rt-client")
            .AsConfidentialClient("rt-secret")
            .WithGrantTypes(GrantTypes.Password, GrantTypes.RefreshToken)
            .AllowOfflineAccess(true)
            .WithScopes("openid", "offline_access"));

        await CreateClientAsync(c => c
            .WithClientId("introspect-rt-client")
            .AsConfidentialClient("introspect-rt-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        var tokenResponse = await RequestPasswordGrantAsync(
            clientId: "rt-client",
            clientSecret: "rt-secret",
            username: user.UserName,
            password: "Test123!",
            scope: "openid offline_access");

        tokenResponse.RefreshToken.ShouldNotBeNullOrWhiteSpace("Password grant should yield refresh_token when offline_access is granted.");

        using var introspect = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = tokenResponse.RefreshToken!,
                ["token_type_hint"] = "refresh_token"
            })
        };

        introspect.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("introspect-rt-client:introspect-rt-secret")));

        var response = await Client.SendAsync(introspect);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Introspection endpoint should return 200 OK for refresh token introspection.");

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull("Introspection response should deserialize to TokenIntrospectionResponse.");
        payload.Active.ShouldBeTrue("Valid refresh tokens should be reported as active.");
        payload.TokenType.ShouldBe("refresh_token", "Refresh token introspection should return token_type=refresh_token.");
        payload.ClientId.ShouldBe("rt-client", "Refresh token introspection should return the issuing client_id.");
        payload.Sub.ShouldBe(user.Id, "Refresh token introspection should return sub as the user id.");
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
