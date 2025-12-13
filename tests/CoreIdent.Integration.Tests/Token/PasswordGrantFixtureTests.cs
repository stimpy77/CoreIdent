using System.Net;
using System.Net.Http.Json;
using System.Text;
using CoreIdent.Core.Models;
using CoreIdent.Integration.Tests.Infrastructure;
using CoreIdent.Testing.Fixtures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Token;

public sealed class PasswordGrantFixtureTests : CoreIdentTestFixture
{
    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        factory.ConfigureTestServices = services =>
        {
            var provider = new TestLoggerProvider();
            services.AddSingleton(provider);
            services.AddSingleton<ILoggerProvider>(sp => sp.GetRequiredService<TestLoggerProvider>());
        };
    }

    [Fact]
    public async Task Password_grant_returns_tokens_for_valid_credentials()
    {
        var user = await CreateUserAsync(u => u.WithEmail("user@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("pwd-client")
            .AsConfidentialClient("pwd-secret")
            .WithGrantTypes(GrantTypes.Password)
            .AllowOfflineAccess(true)
            .WithScopes("openid", "offline_access"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = user.UserName,
                ["password"] = "Test123!",
                ["scope"] = "openid offline_access"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("pwd-client:pwd-secret")));

        var response = await Client.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Password grant should return 200 OK for valid credentials.");

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull("Response should deserialize to TokenResponse.");
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be present.");

        // offline_access should yield refresh token
        tokenResponse.RefreshToken.ShouldNotBeNullOrWhiteSpace("Refresh token should be present when offline_access is granted.");

        var loggerProvider = Services.GetRequiredService<TestLoggerProvider>();
        loggerProvider.Entries.Any(e =>
                e.Level == LogLevel.Warning &&
                e.Message.Contains("Password grant is deprecated in OAuth 2.1", StringComparison.Ordinal))
            .ShouldBeTrue("Deprecation warning should be logged when password grant is used.");
    }

    [Fact]
    public async Task Password_grant_rejects_invalid_credentials()
    {
        await CreateUserAsync(u => u.WithEmail("user2@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("pwd-client2")
            .AsConfidentialClient("pwd-secret2")
            .WithGrantTypes(GrantTypes.Password)
            .WithScopes("openid"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = "user2@example.com",
                ["password"] = "WrongPassword!"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("pwd-client2:pwd-secret2")));

        var response = await Client.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Invalid resource owner credentials should return 400.");

        var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull("Response should deserialize to TokenErrorResponse.");
        error.Error.ShouldBe(TokenErrors.InvalidGrant, "Error should be invalid_grant for bad username/password.");
    }

    [Fact]
    public async Task Password_grant_rejected_if_client_does_not_allow_it()
    {
        var user = await CreateUserAsync(u => u.WithEmail("user3@example.com").WithPassword("Test123!"));

        await CreateClientAsync(c => c
            .WithClientId("no-pwd-client")
            .AsConfidentialClient("no-pwd-secret")
            .WithGrantTypes(GrantTypes.ClientCredentials)
            .WithScopes("openid"));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = user.UserName,
                ["password"] = "Test123!"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("no-pwd-client:no-pwd-secret")));

        var response = await Client.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Client not allowed for password grant should return 400.");

        var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull();
        error.Error.ShouldBe(TokenErrors.UnauthorizedClient, "Error should be unauthorized_client when client doesn't allow password grant.");
    }
}
