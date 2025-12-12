using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Endpoints;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Services;
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
            parameter: Convert.ToBase64String(Encoding.ASCII.GetBytes("client:secret")));

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
            parameter: Convert.ToBase64String(Encoding.ASCII.GetBytes("client:secret")));

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
                            endpoints.MapCoreIdentTokenManagementEndpoints();
                            endpoints.MapGet("/protected", () => Results.Ok()).RequireAuthorization();
                        });
                    });
            });

        return await builder.StartAsync();
    }

    private static async Task<HttpResponseMessage> CallProtectedAsync(HttpClient client, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        return await client.SendAsync(request);
    }

    private const string Issuer = "https://issuer.example";
    private const string Audience = "resource";
}
