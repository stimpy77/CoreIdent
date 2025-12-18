using System.Net;
using System.Net.Http.Json;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class TokenEndpointFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Token_endpoint_client_credentials_works_with_fixture_and_client_builder()
    {
        await CreateClientAsync(c =>
            c.WithClientId("test-client")
                .AsConfidentialClient("test-secret")
                .WithGrantTypes(GrantTypes.ClientCredentials)
                .WithScopes("api"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["scope"] = "api"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));

        var response = await Client.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Client credentials grant should return 200 OK.");

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull("Response should deserialize to TokenResponse.");
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be present.");
        tokenResponse.TokenType.ShouldBe("Bearer", "Token type should be Bearer.");
    }

    [Fact]
    public async Task Token_endpoint_refresh_token_grant_rotates_refresh_token()
    {
        var user = await CreateUserAsync(u => u.WithEmail("refresh-user@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("refresh-client")
            .AsConfidentialClient("refresh-secret")
            .WithGrantTypes(GrantTypes.Password, GrantTypes.RefreshToken)
            .AllowOfflineAccess(true)
            .WithScopes("openid", "offline_access"));

        var initial = await RequestPasswordGrantAsync(
            clientId: "refresh-client",
            clientSecret: "refresh-secret",
            username: user.UserName,
            password: "Test123!",
            scope: "openid offline_access");

        initial.RefreshToken.ShouldNotBeNullOrWhiteSpace("Password grant should yield refresh_token when offline_access is granted.");

        using var refreshRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.RefreshToken,
                ["refresh_token"] = initial.RefreshToken!
            })
        };

        refreshRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("refresh-client:refresh-secret")));

        var response = await Client.SendAsync(refreshRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "refresh_token grant should return 200 OK for a valid refresh token.");

        var refreshed = await response.Content.ReadFromJsonAsync<TokenResponse>();
        refreshed.ShouldNotBeNull("Response should deserialize to TokenResponse.");
        refreshed.AccessToken.ShouldNotBeNullOrWhiteSpace("Refreshed response should include a new access_token.");
        refreshed.RefreshToken.ShouldNotBeNullOrWhiteSpace("Refreshed response should include a new refresh_token.");
        refreshed.RefreshToken.ShouldNotBe(initial.RefreshToken, "Refresh token should be rotated on use.");
    }

    [Fact]
    public async Task Token_endpoint_refresh_token_grant_rejects_reuse_of_consumed_refresh_token()
    {
        var user = await CreateUserAsync(u => u.WithEmail("reuse-user@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("reuse-client")
            .AsConfidentialClient("reuse-secret")
            .WithGrantTypes(GrantTypes.Password, GrantTypes.RefreshToken)
            .AllowOfflineAccess(true)
            .WithScopes("openid", "offline_access"));

        var initial = await RequestPasswordGrantAsync(
            clientId: "reuse-client",
            clientSecret: "reuse-secret",
            username: user.UserName,
            password: "Test123!",
            scope: "openid offline_access");

        initial.RefreshToken.ShouldNotBeNullOrWhiteSpace("Password grant should yield refresh_token when offline_access is granted.");

        async Task<HttpResponseMessage> RefreshAsync()
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = GrantTypes.RefreshToken,
                    ["refresh_token"] = initial.RefreshToken!
                })
            };

            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("reuse-client:reuse-secret")));

            return await Client.SendAsync(request);
        }

        var first = await RefreshAsync();
        first.StatusCode.ShouldBe(HttpStatusCode.OK, "First use of a refresh token should succeed.");

        var second = await RefreshAsync();
        second.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Reusing a consumed refresh token should be rejected.");

        var error = await second.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull("Response should deserialize to TokenErrorResponse.");
        error.Error.ShouldBe(TokenErrors.InvalidGrant, "Reusing a consumed refresh token should return invalid_grant.");
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
