using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using CoreIdent.Core.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Integration;

public class OpenIdDiscoveryEndpointTests
{
    [Fact]
    public async Task Discovery_endpoint_returns_valid_json_with_correct_issuer_and_endpoint_urls()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Discovery endpoint should return 200 OK.");

        var json = await response.Content.ReadAsStringAsync();
        json.ShouldNotBeNullOrWhiteSpace("Discovery endpoint should return a JSON body.");

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("issuer").GetString().ShouldBe("https://issuer.example", "issuer must exactly match CoreIdentOptions.Issuer.");

        root.GetProperty("jwks_uri").GetString().ShouldBe("https://issuer.example/.well-known/jwks.json", "jwks_uri should be issuer-relative and match the configured JWKS path.");
        root.GetProperty("token_endpoint").GetString().ShouldBe("https://issuer.example/auth/token", "token_endpoint should be advertised using CoreIdentRouteOptions.");
        root.GetProperty("revocation_endpoint").GetString().ShouldBe("https://issuer.example/auth/revoke", "revocation_endpoint should be advertised using CoreIdentRouteOptions.");
        root.GetProperty("introspection_endpoint").GetString().ShouldBe("https://issuer.example/auth/introspect", "introspection_endpoint should be advertised using CoreIdentRouteOptions.");

        root.TryGetProperty("scopes_supported", out var scopes).ShouldBeTrue("Discovery document should include scopes_supported.");
        scopes.ValueKind.ShouldBe(JsonValueKind.Array, "scopes_supported should be an array.");
        scopes.EnumerateArray().Select(e => e.GetString()).Where(s => s is not null).Cast<string>().ShouldContain("openid", "Discovery document should include standard OIDC scopes.");

        root.TryGetProperty("id_token_signing_alg_values_supported", out var algs).ShouldBeTrue("Discovery document should include id_token_signing_alg_values_supported.");
        algs.ValueKind.ShouldBe(JsonValueKind.Array, "id_token_signing_alg_values_supported should be an array.");
        algs.EnumerateArray().Select(e => e.GetString()).Where(s => s is not null).Cast<string>().ShouldContain("RS256", "Discovery document should include signing algorithm from ISigningKeyProvider.");
    }

    [Fact]
    public async Task Discovery_jwks_uri_is_reachable()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        var discoveryResponse = await client.GetAsync("/.well-known/openid-configuration");
        discoveryResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Discovery endpoint should return 200 OK.");

        var json = await discoveryResponse.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        var jwksUri = doc.RootElement.GetProperty("jwks_uri").GetString();
        jwksUri.ShouldNotBeNullOrWhiteSpace("jwks_uri must be present.");

        var jwksPath = new Uri(jwksUri!, UriKind.Absolute).AbsolutePath;

        var jwksResponse = await client.GetAsync(jwksPath);
        jwksResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "JWKS URI from discovery must be reachable.");
    }

    private static async Task<IHost> CreateHostAsync()
    {
        var rsaPem = GenerateRsaPrivatePem();

        var builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();

                        services.AddCoreIdent(o =>
                        {
                            o.Issuer = "https://issuer.example";
                            o.Audience = "https://resource.example";
                        });

                        services.AddSigningKey(o => o.UseRsaPem(rsaPem));
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(endpoints => { endpoints.MapCoreIdentEndpoints(); });
                    });
            });

        return await builder.StartAsync();
    }

    private static string GenerateRsaPrivatePem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem();
    }
}
