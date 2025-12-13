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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Integration;

public class TokenRevocationIntegrationTests
{
    private const string TestClientId = "client";
    private const string TestClientSecret = "secret";

    [Fact]
    public async Task Post_revoke_with_invalid_token_returns_200_ok()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "token", "not-a-token" },
                { "token_type_hint", "access_token" }
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            scheme: "Basic",
            parameter: Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:{TestClientSecret}")));

        var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "RFC7009 requires returning 200 OK even when the token is invalid.");
    }

    [Fact]
    public async Task Revoked_access_token_is_rejected_by_protected_endpoint()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var tokenService = host.Services.GetRequiredService<ITokenService>();

        var token = await tokenService.CreateJwtAsync(
            issuer: Issuer,
            audience: Audience,
            claims: new[]
            {
                new Claim("sub", "user"),
                new Claim("client_id", TestClientId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
            },
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(5));

        var before = await CallProtectedAsync(client, token);
        before.StatusCode.ShouldBe(HttpStatusCode.OK, "Protected endpoint should accept a non-revoked access token.");

        using var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "token", token },
                { "token_type_hint", "access_token" }
            })
        };

        revokeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            scheme: "Basic",
            parameter: Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:{TestClientSecret}")));

        var revokeResponse = await client.SendAsync(revokeRequest);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation endpoint should return 200 OK.");

        var after = await CallProtectedAsync(client, token);
        after.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Protected endpoint should reject revoked access tokens.");
    }

    [Fact]
    public async Task Revoke_requires_client_authentication()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await client.PostAsync("/auth/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", "not-a-token" },
            { "token_type_hint", "access_token" }
        }));

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Confidential client requests should be rejected when no client authentication is provided.");
    }

    [Fact]
    public async Task Post_revoke_with_valid_refresh_token_invalidates_it()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        await refreshTokenStore.StoreAsync(new CoreIdentRefreshToken
        {
            Handle = "refresh-token-1",
            SubjectId = "user-1",
            ClientId = TestClientId,
            FamilyId = "family-1",
            Scopes = ["api"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        });

        using var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "token", "refresh-token-1" },
                { "token_type_hint", "refresh_token" }
            })
        };

        revokeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            scheme: "Basic",
            parameter: Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:{TestClientSecret}")));

        var revokeResponse = await client.SendAsync(revokeRequest);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation endpoint should return 200 OK.");

        var stored = await refreshTokenStore.GetAsync("refresh-token-1");
        stored.ShouldNotBeNull("Refresh token should still be present in the store.");
        stored.IsRevoked.ShouldBeTrue("Refresh token should be marked revoked after revocation.");
    }

    [Fact]
    public async Task Revoked_refresh_token_cannot_be_used_for_token_refresh()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        await refreshTokenStore.StoreAsync(new CoreIdentRefreshToken
        {
            Handle = "refresh-token-2",
            SubjectId = "user-2",
            ClientId = TestClientId,
            FamilyId = "family-2",
            Scopes = ["api"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        });

        using var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "token", "refresh-token-2" },
                { "token_type_hint", "refresh_token" }
            })
        };

        revokeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            scheme: "Basic",
            parameter: Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:{TestClientSecret}")));

        var revokeResponse = await client.SendAsync(revokeRequest);
        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation endpoint should return 200 OK.");

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", "refresh-token-2" }
            })
        };

        tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            scheme: "Basic",
            parameter: Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:{TestClientSecret}")));

        var response = await client.SendAsync(tokenRequest);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Revoked refresh token must not be usable for token refresh.");

        var error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        error.ShouldNotBeNull("Response should deserialize to TokenErrorResponse.");
        error.Error.ShouldBe(TokenErrors.InvalidGrant, "Revoked refresh token should return invalid_grant.");
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

                        var signingKey = new RsaSecurityKey(rsa) { KeyId = "test" };

                        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                            .AddJwtBearer(options =>
                            {
                                options.MapInboundClaims = false;
                                options.TokenValidationParameters = new TokenValidationParameters
                                {
                                    ValidateIssuer = true,
                                    ValidIssuer = Issuer,
                                    ValidateAudience = true,
                                    ValidAudience = Audience,
                                    ValidateLifetime = true,
                                    ValidateIssuerSigningKey = true,
                                    IssuerSigningKey = signingKey
                                };
                            });

                        services.AddAuthorization();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseCoreIdentTokenRevocation();
                        app.UseAuthorization();

                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapCoreIdentTokenEndpoint();
                            endpoints.MapCoreIdentTokenManagementEndpoints();
                            endpoints.MapGet("/protected", () => Results.Ok()).RequireAuthorization();
                        });
                    });
            });

        var host = await builder.StartAsync();

        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var secretHasher = host.Services.GetRequiredService<IClientSecretHasher>();
        await clientStore.CreateAsync(new CoreIdentClient
        {
            ClientId = TestClientId,
            ClientSecretHash = secretHasher.HashSecret(TestClientSecret),
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            AllowedGrantTypes = ["client_credentials", "refresh_token"],
            AllowedScopes = ["openid", "api"],
            Enabled = true,
            CreatedAt = DateTime.UtcNow
        });

        return host;
    }

    private static async Task<HttpResponseMessage> CallProtectedAsync(HttpClient client, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        return await client.SendAsync(request);
    }

    private const string Issuer = "https://issuer.example";
    private const string Audience = "https://api.example";
}
