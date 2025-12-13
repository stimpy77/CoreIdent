using CoreIdent.Core.Endpoints;
using CoreIdent.Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace CoreIdent.Core.Tests.Endpoints;

public class JwksEndpointRotationTests
{
    [Fact]
    public async Task Jwks_supports_multiple_keys()
    {
        var key1 = CreateRsaKey("kid-1");
        var key2 = CreateRsaKey("kid-2");

        var provider = new StaticSigningKeyProvider(
            signingCredentials: new SigningCredentials(key1, SecurityAlgorithms.RsaSha256),
            validationKeys: [
                new SecurityKeyInfo("kid-1", key1, ExpiresAt: null),
                new SecurityKeyInfo("kid-2", key2, ExpiresAt: null)
            ],
            algorithm: SecurityAlgorithms.RsaSha256);

        using var host = await CreateHostAsync(services =>
        {
            services.AddSingleton<ISigningKeyProvider>(provider);
        });

        using var client = host.GetTestClient();
        var response = await client.GetAsync("/.well-known/jwks.json");

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "JWKS endpoint should return 200.");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        var keys = doc.RootElement.GetProperty("keys");
        keys.GetArrayLength().ShouldBe(2, "JWKS should return both keys for rotation.");

        var kids = keys.EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToList();
        kids.ShouldContain("kid-1", "JWKS should include kid-1.");
        kids.ShouldContain("kid-2", "JWKS should include kid-2.");
    }

    private static async Task<IHost> CreateHostAsync(Action<IServiceCollection> configure)
    {
        var builder = new HostBuilder()
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

        return await builder.StartAsync();
    }

    private static RsaSecurityKey CreateRsaKey(string kid)
    {
        using var rsa = RSA.Create(2048);
        var publicParams = rsa.ExportParameters(includePrivateParameters: false);

        var key = new RsaSecurityKey(publicParams)
        {
            KeyId = kid
        };

        return key;
    }

    private sealed class StaticSigningKeyProvider : ISigningKeyProvider
    {
        private readonly SigningCredentials _signingCredentials;
        private readonly IReadOnlyList<SecurityKeyInfo> _validationKeys;

        public StaticSigningKeyProvider(SigningCredentials signingCredentials, IReadOnlyList<SecurityKeyInfo> validationKeys, string algorithm)
        {
            _signingCredentials = signingCredentials;
            _validationKeys = validationKeys;
            Algorithm = algorithm;
        }

        public string Algorithm { get; }

        public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default) =>
            Task.FromResult(_signingCredentials);

        public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default) =>
            Task.FromResult<IEnumerable<SecurityKeyInfo>>(_validationKeys);
    }
}
