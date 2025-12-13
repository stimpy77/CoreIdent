using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Endpoints;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Integration;

public class TokenIntrospectionIntegrationTests
{
    private const string Issuer = "https://issuer.example";
    private const string Audience = "https://api.example";

    private const string ResourceServerClientId = "rs";
    private const string ResourceServerClientSecret = "rs-secret";

    [Fact]
    public async Task Valid_access_token_returns_active_true_with_claims()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var tokenService = host.Services.GetRequiredService<ITokenService>();
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString("N");

        var accessToken = await tokenService.CreateJwtAsync(
            issuer: Issuer,
            audience: Audience,
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "user-1"),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("client_id", ResourceServerClientId),
                new Claim("scope", "openid profile")
            },
            expiresAt: now.AddMinutes(5));

        var response = await PostIntrospectAsync(client, new Dictionary<string, string>
        {
            { "token", accessToken },
            { "token_type_hint", "access_token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload.Active.ShouldBeTrue();
        payload.TokenType.ShouldBe("Bearer");
        payload.ClientId.ShouldBe(ResourceServerClientId);
        payload.Sub.ShouldBe("user-1");
        payload.Scope.ShouldBe("openid profile");
        payload.Iss.ShouldBe(Issuer);
        payload.Aud.ShouldBe(Audience);
        payload.Jti.ShouldBe(jti);
        payload.Exp.ShouldNotBeNull();
        payload.Iat.ShouldBe(now.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task Expired_token_returns_active_false()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var tokenService = host.Services.GetRequiredService<ITokenService>();
        var now = DateTimeOffset.UtcNow;

        var token = await tokenService.CreateJwtAsync(
            issuer: Issuer,
            audience: Audience,
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "user-1"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim("client_id", ResourceServerClientId)
            },
            expiresAt: now.AddMinutes(-1));

        var response = await PostIntrospectAsync(client, new Dictionary<string, string>
        {
            { "token", token }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload.Active.ShouldBeFalse();
    }

    [Fact]
    public async Task Revoked_token_returns_active_false()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var tokenService = host.Services.GetRequiredService<ITokenService>();
        var tokenRevocationStore = host.Services.GetRequiredService<ITokenRevocationStore>();
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString("N");

        var token = await tokenService.CreateJwtAsync(
            issuer: Issuer,
            audience: Audience,
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "user-1"),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
                new Claim("client_id", ResourceServerClientId)
            },
            expiresAt: now.AddMinutes(10));

        await tokenRevocationStore.RevokeTokenAsync(jti, tokenType: "access_token", expiry: now.AddMinutes(10).UtcDateTime);

        var response = await PostIntrospectAsync(client, new Dictionary<string, string>
        {
            { "token", token }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload.Active.ShouldBeFalse();
    }

    [Fact]
    public async Task Invalid_token_returns_active_false()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await PostIntrospectAsync(client, new Dictionary<string, string>
        {
            { "token", "not-a-token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload.Active.ShouldBeFalse();
    }

    [Fact]
    public async Task Unauthenticated_request_returns_401()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await client.PostAsync("/auth/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", "not-a-token" }
        }));

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Valid_refresh_token_returns_active_true()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        await refreshTokenStore.StoreAsync(new CoreIdentRefreshToken
        {
            Handle = "rt-1",
            SubjectId = "user-rt",
            ClientId = ResourceServerClientId,
            FamilyId = "fam-1",
            Scopes = ["openid", "profile"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        });

        var response = await PostIntrospectAsync(client, new Dictionary<string, string>
        {
            { "token", "rt-1" },
            { "token_type_hint", "refresh_token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload.Active.ShouldBeTrue();
        payload.TokenType.ShouldBe("refresh_token");
        payload.ClientId.ShouldBe(ResourceServerClientId);
        payload.Sub.ShouldBe("user-rt");
        payload.Scope.ShouldBe("openid profile");
        payload.Exp.ShouldNotBeNull();
        payload.Iat.ShouldNotBeNull();
    }

    [Fact]
    public async Task Revoked_or_consumed_refresh_token_returns_active_false()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        await refreshTokenStore.StoreAsync(new CoreIdentRefreshToken
        {
            Handle = "rt-2",
            SubjectId = "user-rt2",
            ClientId = ResourceServerClientId,
            FamilyId = "fam-2",
            Scopes = ["openid"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        });

        var consumed = await refreshTokenStore.ConsumeAsync("rt-2");
        consumed.ShouldBeTrue();

        var response = await PostIntrospectAsync(client, new Dictionary<string, string>
        {
            { "token", "rt-2" },
            { "token_type_hint", "refresh_token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>();
        payload.ShouldNotBeNull();
        payload.Active.ShouldBeFalse();
    }

    private static async Task<HttpResponseMessage> PostIntrospectAsync(HttpClient client, Dictionary<string, string> parameters)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect")
        {
            Content = new FormUrlEncodedContent(parameters)
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ResourceServerClientId}:{ResourceServerClientSecret}")));

        return await client.SendAsync(request);
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
                        services.AddTokenRevocation();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapCoreIdentTokenManagementEndpoints();
                        });
                    });
            });

        var host = await builder.StartAsync();

        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var secretHasher = host.Services.GetRequiredService<IClientSecretHasher>();

        await clientStore.CreateAsync(new CoreIdentClient
        {
            ClientId = ResourceServerClientId,
            ClientSecretHash = secretHasher.HashSecret(ResourceServerClientSecret),
            ClientName = "Resource Server",
            ClientType = ClientType.Confidential,
            Enabled = true,
            CreatedAt = DateTime.UtcNow
        });

        return host;
    }
}
