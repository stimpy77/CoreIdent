using System.Net;
using System.Text;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class ConsentEndpointEdgeFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Consent_get_without_authentication_returns_401()
    {
        var response = await Client.GetAsync("/auth/consent");
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Consent GET should challenge unauthenticated requests.");
    }

    [Fact]
    public async Task Consent_get_missing_required_parameters_returns_400()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var response = await Client.GetAsync("/auth/consent?client_id=x");
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Consent GET should return 400 when redirect_uri is missing.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().ShouldBe("invalid_request", "Error code should be invalid_request.");
    }

    [Fact]
    public async Task Consent_get_unknown_client_returns_400_invalid_client()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var response = await Client.GetAsync("/auth/consent?client_id=unknown&redirect_uri=https%3A%2F%2Fclient.example%2Fcb");
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Consent GET should return 400 for unknown clients.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().ShouldBe("invalid_client", "Error code should be invalid_client.");
    }

    [Fact]
    public async Task Consent_get_with_empty_scope_returns_html_without_requested_scopes_list()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        await CreateClientAsync(c =>
            c.WithClientId("consent-empty-scope")
                .WithClientName("Consent Empty Scope")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris("https://client.example/cb")
                .RequireConsent(true)
                .RequirePkce(true));

        var response = await Client.GetAsync("/auth/consent?client_id=consent-empty-scope&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&response_type=code&scope=&state=st&code_challenge=cc&code_challenge_method=S256");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Consent GET should return 200 for authenticated requests.");

        var html = await response.Content.ReadAsStringAsync();
        html.ShouldContain("<form", Shouldly.Case.Sensitive, "Consent page should include an HTML form.");
        html.ShouldNotContain("Requested scopes", Shouldly.Case.Sensitive, "Consent page should not render a requested scopes list when scope is empty.");
    }

    [Fact]
    public async Task Consent_post_non_form_content_returns_400()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/consent")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        };

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Consent POST should require form content type.");
    }

    [Fact]
    public async Task Consent_post_deny_preserves_existing_redirect_uri_query_parameters()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb?foo=bar";

        using var consentPost = new HttpRequestMessage(HttpMethod.Post, "/auth/consent")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["decision"] = "deny",
                ["client_id"] = "client",
                ["redirect_uri"] = redirectUri,
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["state"] = "st",
                ["code_challenge"] = "cc",
                ["code_challenge_method"] = "S256"
            })
        };

        var response = await Client.SendAsync(consentPost);
        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Consent deny should redirect back to redirect_uri.");

        var location = response.Headers.Location;
        location.ShouldNotBeNull("Consent deny should include a Location header.");

        GetQueryParam(location!, "foo").ShouldBe("bar", "Existing redirect_uri query params should be preserved.");
        GetQueryParam(location!, "error").ShouldBe("access_denied", "Deny redirect should include error=access_denied.");
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
