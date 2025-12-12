using System.Net;
using System.Security.Cryptography;
using CoreIdent.Core.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Integration;

public class CoreIdentEndpointsSmokeTests
{
    [Fact]
    public async Task App_can_boot_with_AddCoreIdent_and_MapCoreIdentEndpoints_and_required_routes_respond()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        var jwksResponse = await client.GetAsync("/.well-known/jwks.json");
        jwksResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "JWKS endpoint should respond with 200 OK.");

        var revokeResponse = await client.PostAsync("/auth/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", "not-a-token" },
            { "token_type_hint", "access_token" }
        }));

        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Revocation endpoint should respond (not 404) and require client authentication.");
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
