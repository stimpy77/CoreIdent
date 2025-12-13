using System;
using CoreIdent.Core.Configuration;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Configuration;

public class CoreIdentRouteOptionsTests
{
    [Fact]
    public void CombineWithBase_combines_relative_path_with_default_base_path()
    {
        var routes = new CoreIdentRouteOptions();

        routes.CombineWithBase("token").ShouldBe("/auth/token", "Relative paths should be combined with BasePath.");
    }

    [Fact]
    public void CombineWithBase_returns_root_relative_path_unchanged_except_normalization()
    {
        var routes = new CoreIdentRouteOptions();

        routes.CombineWithBase("/me").ShouldBe("/me", "Root-relative paths should not be combined with BasePath.");
    }

    [Fact]
    public void CombineWithBase_normalizes_slashes()
    {
        var routes = new CoreIdentRouteOptions
        {
            BasePath = "/auth/"
        };

        routes.CombineWithBase("/auth//token/").ShouldBe("/auth/token", "Route templates should be normalized.");
        routes.CombineWithBase("token/").ShouldBe("/auth/token", "Combined routes should be normalized.");
    }

    [Fact]
    public void GetDiscoveryPath_derives_from_issuer_when_not_overridden_and_issuer_has_no_path()
    {
        var options = new CoreIdentOptions
        {
            Issuer = "https://example.com",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var routes = new CoreIdentRouteOptions();

        routes.GetDiscoveryPath(options).ShouldBe("/.well-known/openid-configuration", "Discovery path should be issuer-relative per OIDC Discovery.");
    }

    [Fact]
    public void GetDiscoveryPath_derives_from_issuer_when_not_overridden_and_issuer_has_path_component()
    {
        var options = new CoreIdentOptions
        {
            Issuer = "https://example.com/issuer1",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var routes = new CoreIdentRouteOptions();

        routes.GetDiscoveryPath(options).ShouldBe("/issuer1/.well-known/openid-configuration", "Discovery path should include issuer path component.");
    }

    [Fact]
    public void GetJwksPath_derives_from_issuer_when_not_overridden_and_issuer_has_path_component()
    {
        var options = new CoreIdentOptions
        {
            Issuer = "https://example.com/issuer1",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var routes = new CoreIdentRouteOptions();

        routes.GetJwksPath(options).ShouldBe("/issuer1/.well-known/jwks.json", "JWKS path should include issuer path component.");
    }

    [Fact]
    public void GetDiscoveryPath_uses_override_when_configured()
    {
        var options = new CoreIdentOptions
        {
            Issuer = "https://example.com/issuer1",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var routes = new CoreIdentRouteOptions
        {
            DiscoveryPath = "/custom/discovery/"
        };

        routes.GetDiscoveryPath(options).ShouldBe("/custom/discovery", "Explicit DiscoveryPath override should be honored and normalized.");
    }

    [Fact]
    public void GetJwksPath_uses_override_when_configured()
    {
        var options = new CoreIdentOptions
        {
            Issuer = "https://example.com/issuer1",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var routes = new CoreIdentRouteOptions
        {
            JwksPath = "custom/jwks.json"
        };

        routes.GetJwksPath(options).ShouldBe("/custom/jwks.json", "Explicit JwksPath override should be honored and normalized.");
    }
}
