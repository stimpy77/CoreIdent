using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using CoreIdent.Testing.Fixtures;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.ResourceOwner;

public sealed class ResourceOwnerEndpointsFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Register_login_profile_flow_works_for_json_clients()
    {
        var email = "fixture-json@example.com";
        var password = "Test123!";

        using var registerRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/register");
        registerRequest.Headers.Accept.ParseAdd("application/json");
        registerRequest.Content = JsonContent.Create(new { email, password });

        var registerResponse = await Client.SendAsync(registerRequest);
        registerResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Register should return 200 OK.");

        var registerJson = await registerResponse.Content.ReadAsStringAsync();
        using var registerDoc = JsonDocument.Parse(registerJson);
        var userId = registerDoc.RootElement.GetProperty("userId").GetString();
        userId.ShouldNotBeNullOrWhiteSpace("Register response should include userId.");

        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login");
        loginRequest.Headers.Accept.ParseAdd("application/json");
        loginRequest.Content = JsonContent.Create(new { email, password });

        var loginResponse = await Client.SendAsync(loginRequest);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Login should return 200 OK.");

        var tokenResponse = await loginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.TokenResponse>();
        tokenResponse.ShouldNotBeNull("Login response should deserialize.");
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("Login should return access token.");

        using var profileRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/profile");
        profileRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
        profileRequest.Headers.Accept.ParseAdd("application/json");

        var profileResponse = await Client.SendAsync(profileRequest);
        profileResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Profile should return 200 OK for valid bearer token.");

        var profileBody = await profileResponse.Content.ReadAsStringAsync();
        profileBody.Contains(email, StringComparison.Ordinal)
            .ShouldBeTrue("Profile JSON should contain the email.");
        profileBody.Contains(userId!, StringComparison.Ordinal)
            .ShouldBeTrue("Profile JSON should contain the user id.");
    }

    [Fact]
    public async Task Register_login_flow_works_for_html_form_clients()
    {
        var email = "fixture-form@example.com";
        var password = "Test123!";

        var registerPage = await Client.GetAsync("/auth/register");
        registerPage.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await registerPage.Content.ReadAsStringAsync()).Contains("<form", StringComparison.Ordinal)
            .ShouldBeTrue("Register page should include a form.");

        var registerResponse = await Client.PostAsync("/auth/register", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["email"] = email,
            ["password"] = password
        }));

        registerResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
        registerResponse.Content.Headers.ContentType?.MediaType.ShouldBe("text/html", "Default form registration should return HTML.");

        var loginPage = await Client.GetAsync("/auth/login");
        loginPage.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await loginPage.Content.ReadAsStringAsync()).Contains("<form", StringComparison.Ordinal)
            .ShouldBeTrue("Login page should include a form.");

        var loginResponse = await Client.PostAsync("/auth/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["email"] = email,
            ["password"] = password
        }));

        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
        loginResponse.Content.Headers.ContentType?.MediaType.ShouldBe("text/html", "Default form login should return HTML.");

        using var tokenLoginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["email"] = email,
                ["password"] = password
            })
        };
        tokenLoginRequest.Headers.Accept.ParseAdd("application/json");

        var tokenLoginResponse = await Client.SendAsync(tokenLoginRequest);
        tokenLoginResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Login with JSON accept should return a token response.");

        var tokenResponse = await tokenLoginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.TokenResponse>();
        tokenResponse.ShouldNotBeNull("Token response should deserialize.");
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be present.");

        using var profileRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/profile");
        profileRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);

        var profileResponse = await Client.SendAsync(profileRequest);
        profileResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Profile should return 200 OK with bearer token.");
        profileResponse.Content.Headers.ContentType?.MediaType.ShouldBe("text/html", "Default profile should return HTML.");
        (await profileResponse.Content.ReadAsStringAsync()).Contains(email, StringComparison.Ordinal)
            .ShouldBeTrue("Profile HTML should include the email.");
    }

    [Fact]
    public async Task Delegates_can_override_and_fallback_to_default()
    {
        var overriddenCalled = false;
        var fallbackCalled = false;

        var factory = new CoreIdentWebApplicationFactory();
        factory.ConfigureTestServices = services =>
        {
            services.Configure<CoreIdent.Core.Configuration.CoreIdentResourceOwnerOptions>(opts =>
            {
                opts.RegisterHandler = (ctx, user, ct) =>
                {
                    overriddenCalled = true;
                    return Task.FromResult<IResult?>(Results.Json(new { overridden = true }));
                };

                opts.LoginHandler = (ctx, user, tokens, ct) =>
                {
                    fallbackCalled = true;
                    return Task.FromResult<IResult?>(null);
                };
            });
        };

        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        factory.EnsureSeeded();

        using var registerRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/register");
        registerRequest.Headers.Accept.ParseAdd("application/json");
        registerRequest.Content = JsonContent.Create(new { email = "override@example.com", password = "Test123!" });

        var registerResponse = await client.SendAsync(registerRequest);
        registerResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await registerResponse.Content.ReadAsStringAsync()).Contains("overridden", StringComparison.Ordinal)
            .ShouldBeTrue("Delegate override should control response.");
        overriddenCalled.ShouldBeTrue("RegisterHandler delegate should be invoked.");

        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login");
        loginRequest.Headers.Accept.ParseAdd("application/json");
        loginRequest.Content = JsonContent.Create(new { email = "override@example.com", password = "Test123!" });

        var loginResponse = await client.SendAsync(loginRequest);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
        fallbackCalled.ShouldBeTrue("LoginHandler delegate should be invoked.");

        // Since the delegate returned null, default JSON token response should be returned.
        var tokenResponse = await loginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.TokenResponse>();
        tokenResponse.ShouldNotBeNull();
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace();

        factory.Dispose();
    }
}
