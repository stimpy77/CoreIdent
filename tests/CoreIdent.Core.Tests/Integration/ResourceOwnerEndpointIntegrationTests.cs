using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Endpoints;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Passwords.AspNetIdentity.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Integration;

public sealed class ResourceOwnerEndpointIntegrationTests
{
    private const string Issuer = "https://issuer.example";
    private const string Audience = "https://api.example";

    [Fact]
    public async Task Register_creates_user_with_hashed_password()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var email = "user@example.com";
        var password = "Test123!";

        using var registerRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/register")
        {
            Content = JsonContent.Create(new { email, password })
        };

        registerRequest.Headers.Accept.ParseAdd("application/json");

        var response = await client.SendAsync(registerRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Register should return 200 OK.");

        var userStore = host.Services.GetRequiredService<IUserStore>();
        var stored = await userStore.FindByUsernameAsync(email);
        stored.ShouldNotBeNull("User should have been created.");
        stored!.PasswordHash.ShouldNotBeNullOrWhiteSpace("Password hash should be stored.");
        stored.PasswordHash.ShouldNotBe(password, "Password should be hashed and not stored in plain text.");
    }

    [Fact]
    public async Task Register_rejects_duplicate_email()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var email = "dupe@example.com";
        var password = "Test123!";

        var first = await client.PostAsJsonAsync("/auth/register", new { email, password });
        first.StatusCode.ShouldBe(HttpStatusCode.OK);

        var second = await client.PostAsJsonAsync("/auth/register", new { email, password });
        second.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Duplicate registration should be rejected.");
    }

    [Fact]
    public async Task Login_returns_tokens_for_valid_credentials()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var email = "login@example.com";
        var password = "Test123!";

        var register = await client.PostAsJsonAsync("/auth/register", new { email, password });
        register.StatusCode.ShouldBe(HttpStatusCode.OK);

        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { email, password })
        };
        loginRequest.Headers.Accept.ParseAdd("application/json");

        var loginResponse = await client.SendAsync(loginRequest);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokens = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>();
        tokens.ShouldNotBeNull();
        tokens.AccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be returned.");
        tokens.RefreshToken.ShouldNotBeNullOrWhiteSpace("Refresh token should be returned.");
    }

    [Fact]
    public async Task Login_rejects_invalid_credentials()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var email = "login2@example.com";
        var password = "Test123!";

        var register = await client.PostAsJsonAsync("/auth/register", new { email, password });
        register.StatusCode.ShouldBe(HttpStatusCode.OK);

        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { email, password = "WrongPassword" })
        };
        loginRequest.Headers.Accept.ParseAdd("application/json");

        var loginResponse = await client.SendAsync(loginRequest);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Invalid credentials should return 401.");
    }

    [Fact]
    public async Task Profile_returns_user_data_for_authenticated_request_and_rejects_unauthenticated()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var email = "profile@example.com";
        var password = "Test123!";

        var unauth = await client.GetAsync("/auth/profile");
        unauth.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Profile without bearer token should return 401.");

        using var registerRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/register")
        {
            Content = JsonContent.Create(new { email, password })
        };
        registerRequest.Headers.Accept.ParseAdd("application/json");

        var registerResponse = await client.SendAsync(registerRequest);
        registerResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { email, password })
        };
        loginRequest.Headers.Accept.ParseAdd("application/json");

        var loginResponse = await client.SendAsync(loginRequest);
        loginResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokens = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>();
        tokens.ShouldNotBeNull();

        using var profileRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/profile");
        profileRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        profileRequest.Headers.Accept.ParseAdd("application/json");

        var profileResponse = await client.SendAsync(profileRequest);
        profileResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Profile should return 200 OK for valid bearer token.");

        var content = await profileResponse.Content.ReadAsStringAsync();
        content.Contains(email, StringComparison.Ordinal)
            .ShouldBeTrue("Profile response should contain the user email.");
    }

    private static async Task<IHost> CreateHostAsync(RSA rsa)
    {
        var rsaPem = rsa.ExportRSAPrivateKeyPem();

        var builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        services.AddLogging();

                        services.AddCoreIdent(options =>
                        {
                            options.Issuer = Issuer;
                            options.Audience = Audience;
                        });

                        services.AddSigningKey(o => o.UseRsaPem(rsaPem));

                        services.AddAspNetIdentityPasswordHasher();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();

                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapCoreIdentResourceOwnerEndpoints();
                        });
                    });
            });

        return await builder.StartAsync();
    }
}
