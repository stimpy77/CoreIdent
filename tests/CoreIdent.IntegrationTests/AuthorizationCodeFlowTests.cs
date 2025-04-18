using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Xunit;
using Microsoft.AspNetCore.WebUtilities;

namespace CoreIdent.IntegrationTests
{
    public class AuthorizationCodeFlowTests
    {
        private readonly TestFixture _fixture;

        public AuthorizationCodeFlowTests(TestFixture fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task Authorize_WithInvalidRedirectUri_ReturnsErrorRedirect()
        {
            // Arrange
            var client = await _fixture.EnsureTestClientAsync();
            var state = Guid.NewGuid().ToString();
            var codeVerifier = PkceUtil.GenerateCodeVerifier();
            var codeChallenge = PkceUtil.GenerateCodeChallenge(codeVerifier);
            var invalidRedirectUri = "https://invalid-redirect.com/callback";

            // Ensure the invalidRedirectUri is NOT registered for the client
            Assert.DoesNotContain(client.RedirectUris, uri => uri == invalidRedirectUri);

            var authorizeUrl = $"/auth/authorize?response_type=code"
                             + $"&client_id={client.ClientId}"
                             + $"&redirect_uri={Uri.EscapeDataString(invalidRedirectUri)}"
                             + $"&scope={Uri.EscapeDataString(client.AllowedScopes.First())}"
                             + $"&state={state}"
                             + $"&code_challenge={codeChallenge}"
                             + $"&code_challenge_method=S256";

            // Act
            var response = await _fixture.HttpClient.GetAsync(authorizeUrl);

            // Assert
            // The spec technically recommends showing an error page or redirecting to a *registered* URI.
            // However, redirecting to the specified (invalid) URI with an error is common.
            // We test for this common behavior first.
            // Status code should NOT be a success or standard redirect (like 302 Found)
            // Often results in a 400 Bad Request or a 302 redirect TO THE INVALID URI with error params.
            // Let's check for the redirect to the invalid URI first.

            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.NotNull(response.Headers.Location);

            var locationUri = response.Headers.Location;
            Assert.StartsWith(invalidRedirectUri, locationUri.OriginalString); // Should redirect back to the provided invalid URI

            var queryParams = QueryHelpers.ParseQuery(locationUri.Query);
            Assert.True(queryParams.ContainsKey("error"));
            Assert.Equal("invalid_request", queryParams["error"]); // Or potentially "unauthorized_client"
            Assert.True(queryParams.ContainsKey("error_description"));
            Assert.Contains("redirect_uri", queryParams["error_description"].ToString().ToLowerInvariant()); // Check if the error mentions redirect_uri
            Assert.Equal(state, queryParams["state"]); // State MUST be returned
        }
    }
} 