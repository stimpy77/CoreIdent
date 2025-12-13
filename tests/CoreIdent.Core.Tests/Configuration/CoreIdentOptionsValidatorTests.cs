using System;
using CoreIdent.Core.Configuration;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Configuration;

public class CoreIdentOptionsValidatorTests
{
    [Fact]
    public void Validate_fails_when_issuer_missing()
    {
        var validator = new CoreIdentOptionsValidator();
        var options = new CoreIdentOptions
        {
            Issuer = null,
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var result = validator.Validate(name: null, options);

        result.Succeeded.ShouldBeFalse("Issuer is required.");
    }

    [Fact]
    public void Validate_fails_when_issuer_not_absolute_uri()
    {
        var validator = new CoreIdentOptionsValidator();
        var options = new CoreIdentOptions
        {
            Issuer = "not-a-uri",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var result = validator.Validate(name: null, options);

        result.Succeeded.ShouldBeFalse("Issuer must be a valid absolute URI.");
    }

    [Fact]
    public void Validate_fails_when_audience_missing()
    {
        var validator = new CoreIdentOptionsValidator();
        var options = new CoreIdentOptions
        {
            Issuer = "https://issuer.example",
            Audience = " ",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var result = validator.Validate(name: null, options);

        result.Succeeded.ShouldBeFalse("Audience is required.");
    }

    [Fact]
    public void Validate_fails_when_access_token_lifetime_is_not_positive()
    {
        var validator = new CoreIdentOptionsValidator();
        var options = new CoreIdentOptions
        {
            Issuer = "https://issuer.example",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.Zero,
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var result = validator.Validate(name: null, options);

        result.Succeeded.ShouldBeFalse("Access token lifetime must be positive.");
    }

    [Fact]
    public void Validate_fails_when_refresh_token_lifetime_is_not_positive()
    {
        var validator = new CoreIdentOptionsValidator();
        var options = new CoreIdentOptions
        {
            Issuer = "https://issuer.example",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.Zero
        };

        var result = validator.Validate(name: null, options);

        result.Succeeded.ShouldBeFalse("Refresh token lifetime must be positive.");
    }

    [Fact]
    public void Validate_fails_when_refresh_token_lifetime_not_greater_than_access_token_lifetime()
    {
        var validator = new CoreIdentOptionsValidator();
        var options = new CoreIdentOptions
        {
            Issuer = "https://issuer.example",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(10),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var result = validator.Validate(name: null, options);

        result.Succeeded.ShouldBeFalse("Refresh token lifetime must be greater than access token lifetime.");
    }

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var validator = new CoreIdentOptionsValidator();
        var options = new CoreIdentOptions
        {
            Issuer = "https://issuer.example",
            Audience = "https://api.example",
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromMinutes(10)
        };

        var result = validator.Validate(name: null, options);

        result.Succeeded.ShouldBeTrue("Valid options should succeed.");
    }
}
