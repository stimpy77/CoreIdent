using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Endpoints;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Services;
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

public class JwksTokenValidationIntegrationTests
{
    [Fact]
    public async Task Token_signed_with_RSA_can_be_validated_using_JWKS_public_key()
    {
        using var host = await CreateHostAsync(services =>
        {
            services.AddSigningKey(o => o.UseRsaPem(GenerateRsaPrivatePem()));
        });

        using var client = host.GetTestClient();

        var tokenService = host.Services.GetRequiredService<ITokenService>();
        var token = await tokenService.CreateJwtAsync(
            issuer: "https://issuer.example",
            audience: "resource",
            claims: new[] { new Claim("sub", "user") },
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(5));

        var jwks = await GetJwksAsync(client);
        jwks.Keys.ShouldHaveSingleItem("JWKS should return a single key for this test.");

        var jwk = jwks.Keys.Single();
        jwk.Kty.ShouldBe("RSA", "kty should be RSA.");

        SecurityKey key = jwk;

        // Validate with JsonWebTokenHandler (same stack)
        var jwtHandler = new JsonWebTokenHandler();
        var result = await jwtHandler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "https://issuer.example",
            ValidAudience = "resource",
            IssuerSigningKey = key
        });

        result.IsValid.ShouldBeTrue("Token should validate using RSA key derived from JWKS.");
    }

    [Fact]
    public async Task Token_signed_with_ECDSA_can_be_validated_using_JWKS_public_key()
    {
        var pemPath = WriteTempPem(GenerateEcdsaPrivatePem());

        using var host = await CreateHostAsync(services =>
        {
            services.AddSigningKey(o => o.UseEcdsa(pemPath));
        });

        using var client = host.GetTestClient();

        var tokenService = host.Services.GetRequiredService<ITokenService>();
        var token = await tokenService.CreateJwtAsync(
            issuer: "https://issuer.example",
            audience: "resource",
            claims: new[] { new Claim("sub", "user") },
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(5));

        var jwks = await GetJwksAsync(client);
        jwks.Keys.ShouldHaveSingleItem("JWKS should return a single key for this test.");

        var jwk = jwks.Keys.Single();
        jwk.Kty.ShouldBe("EC", "kty should be EC.");

        SecurityKey key = jwk;

        var jwtHandler = new JsonWebTokenHandler();
        var result = await jwtHandler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "https://issuer.example",
            ValidAudience = "resource",
            IssuerSigningKey = key
        });

        result.IsValid.ShouldBeTrue("Token should validate using EC key derived from JWKS.");

        TryDelete(pemPath);
    }

    [Fact]
    public async Task External_JwtSecurityTokenHandler_can_validate_token_using_published_JWKS()
    {
        using var host = await CreateHostAsync(services =>
        {
            services.AddSigningKey(o => o.UseRsaPem(GenerateRsaPrivatePem()));
        });

        using var client = host.GetTestClient();

        var tokenService = host.Services.GetRequiredService<ITokenService>();
        var token = await tokenService.CreateJwtAsync(
            issuer: "https://issuer.example",
            audience: "resource",
            claims: new[] { new Claim("sub", "user") },
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(5));

        var jwks = await GetJwksAsync(client);
        jwks.Keys.ShouldHaveSingleItem("JWKS should return a single key for this test.");

        var jwk = jwks.Keys.Single();

        SecurityKey key = jwk;

        var handler = new JwtSecurityTokenHandler
        {
            MapInboundClaims = false
        };
        var principal = handler.ValidateToken(token, new TokenValidationParameters
        {
            ValidIssuer = "https://issuer.example",
            ValidAudience = "resource",
            ValidateLifetime = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key
        }, out _);

        principal.ShouldNotBeNull("JwtSecurityTokenHandler should validate token using JWKS-derived key.");
        principal.FindFirstValue("sub").ShouldBe("user", "Subject claim should flow through.");
    }

    private static async Task<IHost> CreateHostAsync(Action<IServiceCollection> configureServices)
    {
        var builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        configureServices(services);
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapCoreIdentDiscoveryEndpoints();
                        });
                    });
            });

        return await builder.StartAsync();
    }

    private static async Task<JsonWebKeySet> GetJwksAsync(HttpClient client)
    {
        var response = await client.GetAsync("/.well-known/jwks.json");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "JWKS endpoint should return 200.");

        var json = await response.Content.ReadAsStringAsync();
        var jwks = new JsonWebKeySet(json);
        jwks.Keys.ShouldNotBeNull("JWKS should deserialize into JsonWebKeySet.");
        return jwks;
    }

    private static string GenerateRsaPrivatePem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem();
    }

    private static string GenerateEcdsaPrivatePem()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportECPrivateKeyPem();
    }

    private static string WriteTempPem(string pem)
    {
        var path = Path.Combine(Path.GetTempPath(), $"coreident-ecdsa-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, pem);
        return path;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }
}
