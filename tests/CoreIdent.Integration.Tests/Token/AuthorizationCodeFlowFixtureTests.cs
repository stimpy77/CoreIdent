using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Microsoft.IdentityModel.JsonWebTokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class AuthorizationCodeFlowFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Authorization_code_flow_works_end_to_end_authorize_to_token()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("ac-client")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId, StandardScopes.Profile)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        // PKCE
        var codeVerifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = CreateCodeChallenge(codeVerifier);

        var authorizeUrl = $"/auth/authorize?client_id=ac-client" +
                          $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                          $"&response_type=code" +
                          $"&scope={Uri.EscapeDataString("openid profile")}" +
                          $"&state=xyz" +
                          $"&nonce=n-123" +
                          $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
                          $"&code_challenge_method=S256";

        var authorizeResponse = await Client.GetAsync(authorizeUrl);
        authorizeResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Authorize endpoint should redirect back to client.");

        var location = authorizeResponse.Headers.Location;
        location.ShouldNotBeNull("Authorize response should contain Location header.");

        location!.AbsoluteUri.ShouldStartWith(redirectUri, Shouldly.Case.Sensitive, "Redirect should go to the registered redirect_uri.");

        var code = GetQueryParam(location, "code");
        code.ShouldNotBeNullOrWhiteSpace("Redirect should include authorization code.");

        GetQueryParam(location, "state").ShouldBe("xyz", "state must round-trip.");

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.AuthorizationCode,
                ["client_id"] = "ac-client",
                ["code"] = code!,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier
            })
        };

        // Public client: no Authorization header
        var tokenResponse = await Client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Token endpoint should exchange code for tokens.");

        var payload = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        payload.ShouldNotBeNull("Token response should deserialize.");

        payload.AccessToken.ShouldNotBeNullOrWhiteSpace("access_token should be present.");
        payload.IdToken.ShouldNotBeNullOrWhiteSpace("id_token should be present when openid scope is granted.");

        var handler = new JsonWebTokenHandler();
        var idJwt = handler.ReadJsonWebToken(payload.IdToken);
        idJwt.Audiences.ShouldContain("ac-client", "id_token aud should be client_id.");

        var nonce = idJwt.Claims.FirstOrDefault(c => c.Type == "nonce");
        nonce.ShouldNotBeNull("id_token should include nonce.");
        nonce.Value.ShouldBe("n-123", "nonce should match authorize request.");
    }

    [Fact]
    public async Task Pkce_failure_returns_invalid_grant()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("ac-client-2")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var codeVerifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = CreateCodeChallenge(codeVerifier);

        var authorizeUrl = $"/auth/authorize?client_id=ac-client-2" +
                          $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                          $"&response_type=code" +
                          $"&scope={Uri.EscapeDataString("openid")}" +
                          $"&state=abc" +
                          $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
                          $"&code_challenge_method=S256";

        var authorizeResponse = await Client.GetAsync(authorizeUrl);
        authorizeResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var location = authorizeResponse.Headers.Location;
        location.ShouldNotBeNull();

        var code = GetQueryParam(location!, "code");
        code.ShouldNotBeNullOrWhiteSpace();

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.AuthorizationCode,
                ["client_id"] = "ac-client-2",
                ["code"] = code!,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = "wrong-verifier"
            })
        };

        var tokenResponse = await Client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "PKCE failure must be 400 invalid_grant.");

        var error = await tokenResponse.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull();
        error.Error.ShouldBe(TokenErrors.InvalidGrant, "PKCE failure should return invalid_grant.");
    }

    [Fact]
    public async Task Consumed_code_cannot_be_reused()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("ac-client-3")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var codeVerifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = CreateCodeChallenge(codeVerifier);

        var authorizeUrl = $"/auth/authorize?client_id=ac-client-3" +
                          $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                          $"&response_type=code" +
                          $"&scope={Uri.EscapeDataString("openid")}" +
                          $"&state=aaa" +
                          $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
                          $"&code_challenge_method=S256";

        var authorizeResponse = await Client.GetAsync(authorizeUrl);
        authorizeResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var code = GetQueryParam(authorizeResponse.Headers.Location!, "code");
        code.ShouldNotBeNullOrWhiteSpace();

        async Task<HttpResponseMessage> ExchangeAsync()
        {
            using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = GrantTypes.AuthorizationCode,
                    ["client_id"] = "ac-client-3",
                    ["code"] = code!,
                    ["redirect_uri"] = redirectUri,
                    ["code_verifier"] = codeVerifier
                })
            };

            return await Client.SendAsync(tokenRequest);
        }

        var first = await ExchangeAsync();
        first.StatusCode.ShouldBe(HttpStatusCode.OK, "First code exchange should succeed.");

        var second = await ExchangeAsync();
        second.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Second exchange must fail.");

        var error = await second.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull();
        error.Error.ShouldBe(TokenErrors.InvalidGrant, "Reusing a code should yield invalid_grant.");
    }

    private static string CreateCodeChallenge(string verifier)
    {
        var bytes = Encoding.ASCII.GetBytes(verifier);
        var hashed = SHA256.HashData(bytes);
        var s = Convert.ToBase64String(hashed);
        s = s.TrimEnd('=');
        s = s.Replace('+', '-');
        s = s.Replace('/', '_');
        return s;
    }

    private static string? GetQueryParam(Uri uri, string key)
    {
        var query = uri.Query.TrimStart('?');
        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 2 && string.Equals(Uri.UnescapeDataString(kv[0]), key, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(kv[1]);
            }
        }

        return null;
    }
}
