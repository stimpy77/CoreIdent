using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class ConsentFlowFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Consent_required_redirects_to_consent_ui()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("consent-client")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequireConsent(true)
                .RequirePkce(true));

        var codeVerifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = CreateCodeChallenge(codeVerifier);

        var authorizeUrl = $"/auth/authorize?client_id=consent-client" +
                          $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                          $"&response_type=code" +
                          $"&scope={Uri.EscapeDataString("openid")}" +
                          $"&state=st" +
                          $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
                          $"&code_challenge_method=S256";

        var response = await Client.GetAsync(authorizeUrl);
        response.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var location = response.Headers.Location;
        location.ShouldNotBeNull();
        location!.AbsolutePath.ShouldBe("/auth/consent", "Consent redirect should go to consent endpoint.");
    }

    [Fact]
    public async Task Allow_persists_grant_and_completes_code_flow()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("consent-client-2")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequireConsent(true)
                .RequirePkce(true));

        var codeVerifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = CreateCodeChallenge(codeVerifier);

        // Start at authorize (will redirect to consent)
        var authorizeUrl = $"/auth/authorize?client_id=consent-client-2" +
                          $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                          $"&response_type=code" +
                          $"&scope={Uri.EscapeDataString("openid")}" +
                          $"&state=st2" +
                          $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
                          $"&code_challenge_method=S256";

        var authorizeResponse = await Client.GetAsync(authorizeUrl);
        authorizeResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var consentLocation = authorizeResponse.Headers.Location;
        consentLocation.ShouldNotBeNull();

        // POST consent allow
        using var consentPost = new HttpRequestMessage(HttpMethod.Post, "/auth/consent")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["decision"] = "allow",
                ["client_id"] = "consent-client-2",
                ["redirect_uri"] = redirectUri,
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["state"] = "st2",
                ["code_challenge"] = codeChallenge,
                ["code_challenge_method"] = "S256"
            })
        };

        var consentResponse = await Client.SendAsync(consentPost);
        consentResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var backToAuthorize = consentResponse.Headers.Location;
        backToAuthorize.ShouldNotBeNull();
        backToAuthorize!.AbsolutePath.ShouldBe("/auth/authorize");

        // Now call authorize again (grant exists) -> redirects back to client with code
        var authorized = await Client.GetAsync(backToAuthorize.PathAndQuery);
        authorized.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var clientRedirect = authorized.Headers.Location;
        clientRedirect.ShouldNotBeNull();
        clientRedirect!.AbsoluteUri.ShouldStartWith(redirectUri, Shouldly.Case.Sensitive);

        var code = GetQueryParam(clientRedirect, "code");
        code.ShouldNotBeNullOrWhiteSpace();

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.AuthorizationCode,
                ["client_id"] = "consent-client-2",
                ["code"] = code!,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier
            })
        };

        var tokenResponse = await Client.SendAsync(tokenRequest);
        tokenResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        payload.ShouldNotBeNull();
        payload.AccessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Deny_returns_access_denied_to_client()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("consent-client-3")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequireConsent(true)
                .RequirePkce(true));

        using var consentPost = new HttpRequestMessage(HttpMethod.Post, "/auth/consent")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["decision"] = "deny",
                ["client_id"] = "consent-client-3",
                ["redirect_uri"] = redirectUri,
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["state"] = "st3",
                ["code_challenge"] = "x",
                ["code_challenge_method"] = "S256"
            })
        };

        var denyResponse = await Client.SendAsync(consentPost);
        denyResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);

        var location = denyResponse.Headers.Location;
        location.ShouldNotBeNull();
        location!.AbsoluteUri.ShouldStartWith(redirectUri, Shouldly.Case.Sensitive);

        GetQueryParam(location, "error").ShouldBe("access_denied");
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
