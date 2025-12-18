using System.Net;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class AuthorizationEndpointEdgeFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Authorize_without_authentication_returns_401_challenge()
    {
        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("authorize-noauth")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var response = await Client.GetAsync($"/auth/authorize?client_id=authorize-noauth" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&scope={Uri.EscapeDataString("openid")}" +
                                             $"&state=st" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=S256");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Authorize should challenge unauthenticated requests after validation passes.");
    }

    [Fact]
    public async Task Authorize_missing_client_id_returns_400_invalid_request()
    {
        var response = await Client.GetAsync("/auth/authorize?redirect_uri=https%3A%2F%2Fclient.example%2Fcb");
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Missing client_id should return 400 invalid_request.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().ShouldBe("invalid_request", "Error code should be invalid_request.");
    }

    [Fact]
    public async Task Authorize_missing_redirect_uri_returns_400_invalid_request()
    {
        var response = await Client.GetAsync("/auth/authorize?client_id=any");
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Missing redirect_uri should return 400 invalid_request.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().ShouldBe("invalid_request", "Error code should be invalid_request.");
    }

    [Fact]
    public async Task Authorize_with_unsupported_response_type_redirects_error_when_redirect_uri_is_absolute()
    {
        var redirectUri = "https://client.example/cb";

        var response = await Client.GetAsync($"/auth/authorize?client_id=any" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=token" +
                                             $"&state=st");

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Unsupported response_type should redirect with error for absolute redirect_uri.");

        var location = response.Headers.Location;
        location.ShouldNotBeNull("Authorize error redirect should include Location.");

        GetQueryParam(location!, "error").ShouldBe("unsupported_response_type", "Error should be unsupported_response_type.");
        GetQueryParam(location!, "state").ShouldBe("st", "State should be present on redirect errors.");
    }

    [Fact]
    public async Task Authorize_with_invalid_redirect_uri_and_bad_response_type_returns_400()
    {
        var response = await Client.GetAsync("/auth/authorize?client_id=any&redirect_uri=not-a-url&response_type=token&state=st");
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "When redirect_uri is not absolute, errors should be returned as 400 JSON.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().ShouldBe("unsupported_response_type", "Error should be unsupported_response_type.");
    }

    [Fact]
    public async Task Authorize_missing_state_redirects_invalid_request()
    {
        var redirectUri = "https://client.example/cb";

        var response = await Client.GetAsync($"/auth/authorize?client_id=any" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=S256");

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Missing state should redirect invalid_request when redirect_uri is absolute.");
        GetQueryParam(response.Headers.Location!, "error").ShouldBe("invalid_request", "Error should be invalid_request.");
    }

    [Fact]
    public async Task Authorize_missing_pkce_parameters_redirects_invalid_request()
    {
        var redirectUri = "https://client.example/cb";

        var response = await Client.GetAsync($"/auth/authorize?client_id=any" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&state=st");

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Missing PKCE parameters should redirect invalid_request.");
        GetQueryParam(response.Headers.Location!, "error").ShouldBe("invalid_request", "Error should be invalid_request.");
    }

    [Fact]
    public async Task Authorize_with_non_s256_pkce_method_redirects_invalid_request()
    {
        var redirectUri = "https://client.example/cb";

        var response = await Client.GetAsync($"/auth/authorize?client_id=any" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&state=st" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=plain");

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Invalid PKCE method should redirect invalid_request.");
        GetQueryParam(response.Headers.Location!, "error").ShouldBe("invalid_request", "Error should be invalid_request.");
    }

    [Fact]
    public async Task Authorize_unknown_client_returns_400_invalid_client()
    {
        var redirectUri = "https://client.example/cb";

        var response = await Client.GetAsync($"/auth/authorize?client_id=unknown" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&scope={Uri.EscapeDataString("openid")}" +
                                             $"&state=st" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=S256");

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Unknown client should return 400 invalid_client.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().ShouldBe("invalid_client", "Error should be invalid_client.");
    }

    [Fact]
    public async Task Authorize_client_without_auth_code_grant_redirects_unauthorized_client()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("unauthorized-grant")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.ClientCredentials)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var response = await Client.GetAsync($"/auth/authorize?client_id=unauthorized-grant" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&scope={Uri.EscapeDataString("openid")}" +
                                             $"&state=st" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=S256");

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Client not authorized for authorization_code should redirect with unauthorized_client.");
        GetQueryParam(response.Headers.Location!, "error").ShouldBe("unauthorized_client", "Error should be unauthorized_client.");
    }

    [Fact]
    public async Task Authorize_with_unregistered_redirect_uri_returns_400_invalid_request()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        await CreateClientAsync(c =>
            c.WithClientId("redirect-mismatch")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris("https://client.example/registered")
                .RequirePkce(true));

        var response = await Client.GetAsync($"/auth/authorize?client_id=redirect-mismatch" +
                                             $"&redirect_uri={Uri.EscapeDataString("https://client.example/unregistered")}" +
                                             $"&response_type=code" +
                                             $"&scope={Uri.EscapeDataString("openid")}" +
                                             $"&state=st" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=S256");

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Unregistered redirect_uri should return 400 invalid_request.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().ShouldBe("invalid_request", "Error should be invalid_request.");
    }

    [Fact]
    public async Task Authorize_with_scope_not_allowed_by_client_redirects_invalid_scope()
    {
        var user = await CreateUserAsync();
        await AuthenticateAsAsync(user);

        var redirectUri = "https://client.example/cb";

        await CreateClientAsync(c =>
            c.WithClientId("scope-not-allowed")
                .AsPublicClient()
                .WithGrantTypes(GrantTypes.AuthorizationCode)
                .WithScopes(StandardScopes.OpenId)
                .WithRedirectUris(redirectUri)
                .RequirePkce(true));

        var response = await Client.GetAsync($"/auth/authorize?client_id=scope-not-allowed" +
                                             $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                             $"&response_type=code" +
                                             $"&scope={Uri.EscapeDataString("email")}" +
                                             $"&state=st" +
                                             $"&code_challenge=cc" +
                                             $"&code_challenge_method=S256");

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, "Requesting only scopes not allowed by client should redirect invalid_scope.");
        GetQueryParam(response.Headers.Location!, "error").ShouldBe("invalid_scope", "Error should be invalid_scope.");
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
