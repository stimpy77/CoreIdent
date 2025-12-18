using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using CoreIdent.Testing.Fixtures;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.ResourceOwner;

public sealed class ResourceOwnerEndpointsEdgeFixtureTests
{
    [Fact]
    public async Task Register_rejects_invalid_email_for_json_clients()
    {
        using var factory = new CoreIdentWebApplicationFactory();
        using var client = factory.CreateClient();
        factory.EnsureSeeded();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/register");
        request.Headers.Accept.ParseAdd("application/json");
        request.Content = JsonContent.Create(new { email = "not-an-email", password = "Test123!" });

        var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        doc.RootElement.GetProperty("error_code").GetString().ShouldBe("invalid_request");
    }

    [Fact]
    public async Task Register_rejects_invalid_password_for_json_clients()
    {
        using var factory = new CoreIdentWebApplicationFactory();
        using var client = factory.CreateClient();
        factory.EnsureSeeded();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/register");
        request.Headers.Accept.ParseAdd("application/json");
        request.Content = JsonContent.Create(new { email = "edge-password@example.com", password = "123" });

        var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json");
    }

    [Fact]
    public async Task Login_redirects_when_redirect_uri_is_provided_for_html_clients()
    {
        using var factory = new CoreIdentWebApplicationFactory();
        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        factory.EnsureSeeded();

        var email = "redirect-login@example.com";
        var password = "Test123!";

        var registerResponse = await client.PostAsJsonAsync("/auth/register", new { email, password });
        registerResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var redirectUri = "https://client.example/after";
        var loginResponse = await client.PostAsync(
            $"/auth/login?redirect_uri={Uri.EscapeDataString(redirectUri)}",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["email"] = email,
                ["password"] = password
            }));

        loginResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        loginResponse.Headers.Location.ShouldNotBeNull();
        loginResponse.Headers.Location!.ToString().ShouldBe(redirectUri);
    }

    [Fact]
    public async Task Profile_handler_can_override_default_response()
    {
        using var factory = new CoreIdentWebApplicationFactory();
        factory.ConfigureTestServices = services =>
        {
            services.Configure<CoreIdent.Core.Configuration.CoreIdentResourceOwnerOptions>(opts =>
            {
                opts.ProfileHandler = (ctx, user, claims, ct) =>
                    Task.FromResult<IResult?>(Results.Json(new { overridden = true }));
            });
        };

        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        factory.EnsureSeeded();

        var email = "profile-override@example.com";
        var password = "Test123!";

        var register = await client.PostAsJsonAsync("/auth/register", new { email, password });
        register.StatusCode.ShouldBe(HttpStatusCode.OK);

        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login");
        loginRequest.Headers.Accept.ParseAdd("application/json");
        loginRequest.Content = JsonContent.Create(new { email, password });

        var loginResponse = await client.SendAsync(loginRequest);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokens = await loginResponse.Content.ReadFromJsonAsync<CoreIdent.Core.Models.TokenResponse>();
        tokens.ShouldNotBeNull();
        tokens!.AccessToken.ShouldNotBeNullOrWhiteSpace();

        using var profileRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/profile");
        profileRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        profileRequest.Headers.Accept.ParseAdd("application/json");

        var profileResponse = await client.SendAsync(profileRequest);
        profileResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var body = await profileResponse.Content.ReadAsStringAsync();
        body.ShouldContain("overridden");

        factory.Dispose();
    }
}
