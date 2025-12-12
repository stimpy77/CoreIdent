using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

namespace CoreIdent.Core.Tests.DependencyInjection;

public class AddCoreIdentTests
{
    [Fact]
    public void AddCoreIdent_registers_route_options_with_defaults()
    {
        var services = new ServiceCollection();

        services.AddCoreIdent(_ =>
        {
            _.Issuer = "https://issuer.example";
            _.Audience = "https://api.example";
        });

        using var provider = services.BuildServiceProvider();

        var routes = provider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;
        routes.BasePath.ShouldBe("/auth", "BasePath should default to /auth.");
        routes.TokenPath.ShouldBe("token", "TokenPath should default to token.");
    }

    [Fact]
    public void AddCoreIdent_applies_route_configuration_delegate()
    {
        var services = new ServiceCollection();

        services.AddCoreIdent(
            configureOptions: o =>
            {
                o.Issuer = "https://issuer.example";
                o.Audience = "https://api.example";
            },
            configureRoutes: r => r.BasePath = "/id");

        using var provider = services.BuildServiceProvider();

        var routes = provider.GetRequiredService<IOptions<CoreIdentRouteOptions>>().Value;
        routes.BasePath.ShouldBe("/id", "Route configuration delegate should be applied.");
    }

    [Fact]
    public void AddCoreIdent_registers_default_core_services_and_stores()
    {
        var services = new ServiceCollection();

        services.AddCoreIdent(_ =>
        {
            _.Issuer = "https://issuer.example";
            _.Audience = "https://api.example";
        });

        services.AddLogging();
        services.AddSigningKey(b => b.UseSymmetric("0123456789abcdef0123456789abcdef"));

        using var provider = services.BuildServiceProvider();

        provider.GetService<ITokenService>().ShouldNotBeNull("ITokenService should be registered.");
        provider.GetService<IClientStore>().ShouldNotBeNull("IClientStore should be registered.");
        provider.GetService<IScopeStore>().ShouldNotBeNull("IScopeStore should be registered.");
        provider.GetService<IRefreshTokenStore>().ShouldNotBeNull("IRefreshTokenStore should be registered.");
        provider.GetService<ITokenRevocationStore>().ShouldNotBeNull("ITokenRevocationStore should be registered.");
    }

    [Fact]
    public void AddCoreIdent_does_not_override_existing_registrations()
    {
        var services = new ServiceCollection();

        services.AddSingleton<ITokenService, FakeTokenService>();

        services.AddCoreIdent(_ =>
        {
            _.Issuer = "https://issuer.example";
            _.Audience = "https://api.example";
        });

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<ITokenService>().ShouldBeOfType<FakeTokenService>("TryAdd should allow overriding ITokenService.");
    }

    private sealed class FakeTokenService : ITokenService
    {
        public Task<string> CreateJwtAsync(string issuer, string audience, IEnumerable<System.Security.Claims.Claim> claims, DateTimeOffset expires, CancellationToken ct = default)
        {
            return Task.FromResult("fake");
        }
    }
}
