using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Shouldly;
using Xunit;
using CoreIdent.TestHost;

namespace CoreIdent.Core.Tests.Extensions
{
    public class OidcDiscoveryAndJwksEndpointTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly WebApplicationFactory<Program> _factory;
        private readonly HttpClient _client;

        public OidcDiscoveryAndJwksEndpointTests(WebApplicationFactory<Program> factory)
        {
            _factory = factory;
            _client = _factory.CreateClient();
        }

        [Fact]
        public async Task WellKnown_OpenIdConfiguration_ReturnsMetadata()
        {
            // Act
            var response = await _client.GetAsync("/.well-known/openid-configuration");

            // Assert
            var responseContent = await response.Content.ReadAsStringAsync();
            response.StatusCode.ShouldBe(HttpStatusCode.OK, $"Discovery endpoint error: {responseContent}");
            responseContent.ShouldContain("issuer");
            responseContent.ShouldContain("jwks_uri");
            responseContent.ShouldContain("authorization_endpoint");
            responseContent.ShouldContain("token_endpoint");
        }

        [Fact]
        public async Task WellKnown_Jwks_ReturnsJwksJson()
        {
            // Act
            var response = await _client.GetAsync("/.well-known/jwks.json");

            // Assert
            var responseContent = await response.Content.ReadAsStringAsync();
            response.StatusCode.ShouldBe(HttpStatusCode.OK, $"JWKS endpoint error: {responseContent}");
            responseContent.ShouldContain("keys");
            responseContent.ShouldContain("kty"); // Key type (for symmetric: oct, for RSA: RSA)
        }
    }
}
