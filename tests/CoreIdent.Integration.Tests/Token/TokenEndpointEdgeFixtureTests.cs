using System.Net;
using System.Net.Http.Json;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class TokenEndpointEdgeFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Token_endpoint_rejects_non_form_content_type()
    {
        await CreateClientAsync(c => c
            .WithClientId("edge-client")
            .AsConfidentialClient("edge-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = JsonContent.Create(new { grant_type = GrantTypes.ClientCredentials })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("edge-client:edge-secret")));

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull();
        error!.Error.ShouldBe(TokenErrors.InvalidRequest);
    }

    [Fact]
    public async Task Token_endpoint_returns_401_when_confidential_client_secret_missing()
    {
        await CreateClientAsync(c => c
            .WithClientId("no-secret-client")
            .AsConfidentialClient("expected-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["client_id"] = "no-secret-client",
                ["scope"] = "api"
            })
        };

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull();
        error!.Error.ShouldBe(TokenErrors.InvalidClient);
    }

    [Fact]
    public async Task Token_endpoint_uses_form_credentials_when_basic_header_is_invalid_base64()
    {
        await CreateClientAsync(c => c
            .WithClientId("fallback-client")
            .AsConfidentialClient("fallback-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("api"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["client_id"] = "fallback-client",
                ["client_secret"] = "fallback-secret",
                ["scope"] = "api"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "not-base64");

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();
        token.ShouldNotBeNull();
        token!.AccessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Token_endpoint_returns_unsupported_grant_type_when_client_allows_unknown_grant()
    {
        await CreateClientAsync(c => c
            .WithClientId("weird-grant-client")
            .AsConfidentialClient("weird-grant-secret")
            .WithGrantTypes("weird_grant")
            .WithScopes("api"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "weird_grant",
                ["scope"] = "api"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("weird-grant-client:weird-grant-secret")));

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull();
        error!.Error.ShouldBe(TokenErrors.UnsupportedGrantType);
    }

    [Fact]
    public async Task Token_endpoint_refresh_token_grant_requires_refresh_token_parameter()
    {
        await CreateClientAsync(c => c
            .WithClientId("rt-missing-param")
            .AsConfidentialClient("rt-missing-param-secret")
            .WithGrantTypes(GrantTypes.RefreshToken)
            .WithScopes("openid"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.RefreshToken
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("rt-missing-param:rt-missing-param-secret")));

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull();
        error!.Error.ShouldBe(TokenErrors.InvalidRequest);
    }
}
