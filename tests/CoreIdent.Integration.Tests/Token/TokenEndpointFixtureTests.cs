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
}
