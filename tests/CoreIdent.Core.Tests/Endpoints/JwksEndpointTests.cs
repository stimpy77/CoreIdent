using CoreIdent.Core.Configuration;
using CoreIdent.Core.Endpoints;
using CoreIdent.Core.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using System.Net;
using System.Text.Json;
using Xunit;

namespace CoreIdent.Core.Tests.Endpoints;

public class JwksEndpointTests
{
    [Fact]
    public async Task Jwks_returns_RSA_key_with_n_and_e_and_metadata()
    {
        using var host = await CreateHostAsync(services =>
        {
            services.AddSigningKey(o => o.UseRsaPem(GenerateRsaPrivatePem()));
        });

        using var client = host.GetTestClient();

        var response = await client.GetAsync("/.well-known/jwks.json");

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "JWKS endpoint should return 200.");
        var json = await response.Content.ReadAsStringAsync();
        json.ShouldNotBeNullOrWhiteSpace("JWKS response should have JSON body.");

        using var doc = JsonDocument.Parse(json);
        doc.RootElement.TryGetProperty("keys", out var keys).ShouldBeTrue("JWKS should have 'keys' array.");
        keys.ValueKind.ShouldBe(JsonValueKind.Array, "JWKS keys should be an array.");
        keys.GetArrayLength().ShouldBe(1, "JWKS should return a single key for this test.");

        var key = keys[0];
        key.GetProperty("kty").GetString().ShouldBe("RSA", "kty should be RSA.");
        key.GetProperty("use").GetString().ShouldBe("sig", "use should be sig.");
        key.GetProperty("alg").GetString().ShouldBe(SecurityAlgorithms.RsaSha256, "alg should be RS256.");
        key.GetProperty("kid").GetString().ShouldNotBeNullOrWhiteSpace("kid should be present.");
        key.GetProperty("n").GetString().ShouldNotBeNullOrWhiteSpace("RSA modulus n should be present.");
        key.GetProperty("e").GetString().ShouldNotBeNullOrWhiteSpace("RSA exponent e should be present.");
    }

    [Fact]
    public async Task Jwks_does_not_publish_symmetric_keys()
    {
        using var host = await CreateHostAsync(services =>
        {
            services.AddSigningKey(o => o.UseSymmetric(new string('a', 32)));
        });

        using var client = host.GetTestClient();

        var response = await client.GetAsync("/.well-known/jwks.json");

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "JWKS endpoint should return 200.");
        var json = await response.Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(json);
        var keys = doc.RootElement.GetProperty("keys");
        keys.GetArrayLength().ShouldBe(0, "JWKS must not publish symmetric keys.");
    }

    private static async Task<IHost> CreateHostAsync(Action<IServiceCollection> configure)
    {
        var builder = new HostBuilder()
            .ConfigureLogging(logging =>
            {
                logging.AddFilter("CoreIdent.Core.Services.SymmetricSigningKeyProvider", LogLevel.Error);
            })
            .ConfigureWebHost(webHost =>
            {
                webHost
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        configure(services);
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(endpoints => { endpoints.MapCoreIdentDiscoveryEndpoints(); });
                    });
            });

        var host = await builder.StartAsync();
        return host;
    }

    private static string GenerateRsaPrivatePem()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem();
    }
}
