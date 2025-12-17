using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Passkeys;

public sealed class PasskeyOptionsEndpointsFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Register_options_requires_authentication()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/passkey/register/options");
        request.Headers.Accept.ParseAdd("application/json");

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Authenticate_options_returns_json()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/passkey/authenticate/options")
        {
            Content = System.Net.Http.Json.JsonContent.Create(new { username = (string?)null })
        };
        request.Headers.Accept.ParseAdd("application/json");

        var response = await Client.SendAsync(request);

        // We only validate the options endpoint shape here. Full WebAuthn ceremonies need browser automation.
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/json");

        var body = await response.Content.ReadAsStringAsync();
        body.ShouldNotBeNullOrWhiteSpace();
        body.TrimStart().StartsWith("{", StringComparison.Ordinal).ShouldBeTrue();
    }

    [Fact]
    public async Task Register_options_returns_json_when_authenticated()
    {
        var user = await CreateUserAsync(u => u.WithEmail("passkey-options@example.com").WithPassword("Test123!"));

        // get a regular CoreIdent access token (resource owner) to call the authenticated endpoint
        using var login = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["email"] = user.UserName,
                ["password"] = "Test123!"
            })
        };
        login.Headers.Accept.ParseAdd("application/json");

        var loginResponse = await Client.SendAsync(login);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokenResponse = await loginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.TokenResponse>();
        tokenResponse.ShouldNotBeNull();
        tokenResponse!.AccessToken.ShouldNotBeNullOrWhiteSpace();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/passkey/register/options");
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/json");

        var body = await response.Content.ReadAsStringAsync();
        body.ShouldNotBeNullOrWhiteSpace();
        body.TrimStart().StartsWith("{", StringComparison.Ordinal).ShouldBeTrue();
    }

    [Fact]
    public async Task Register_complete_returns_problem_details_for_invalid_credential_json()
    {
        var user = await CreateUserAsync(u => u.WithEmail("passkey-complete@example.com").WithPassword("Test123!"));

        using var login = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["email"] = user.UserName,
                ["password"] = "Test123!"
            })
        };
        login.Headers.Accept.ParseAdd("application/json");

        var loginResponse = await Client.SendAsync(login);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokenResponse = await loginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.TokenResponse>();
        tokenResponse.ShouldNotBeNull();
        tokenResponse!.AccessToken.ShouldNotBeNullOrWhiteSpace();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/passkey/register/complete")
        {
            Content = JsonContent.Create(new { credentialJson = "{}" })
        };
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Invalid passkey registration should return 400.");
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json", "Passkey errors should use RFC 7807 Problem Details for JSON clients.");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("status").GetInt32().ShouldBe((int)HttpStatusCode.BadRequest);
        doc.RootElement.GetProperty("error_code").GetString().ShouldBe("invalid_request");
        doc.RootElement.GetProperty("correlation_id").GetString().ShouldNotBeNullOrWhiteSpace();
    }
}
