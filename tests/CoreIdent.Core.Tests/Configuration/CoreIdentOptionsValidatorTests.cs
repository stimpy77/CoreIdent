using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Options;
using Shouldly;
using System;
using Xunit;

namespace CoreIdent.Core.Tests.Configuration;

public class CoreIdentOptionsValidatorTests
{
    private readonly CoreIdentOptionsValidator _validator = new();
    private CoreIdentOptions _options;

    // Helper to create a default valid options set
    private CoreIdentOptions CreateValidOptions()
    {
        return new CoreIdentOptions
        {
            Issuer = "urn:test:issuer",
            Audience = "urn:test:audience",
            SigningKeySecret = "a_super_secret_key_longer_than_32_bytes_for_hs256_security", // Ensure length >= 32
            AccessTokenLifetime = TimeSpan.FromMinutes(15),
            RefreshTokenLifetime = TimeSpan.FromDays(7),
            TokenSecurity = new TokenSecurityOptions
            {
                TokenTheftDetectionMode = TokenTheftDetectionMode.RevokeFamily,
                EnableTokenFamilyTracking = true
            }
        };
    }

    public CoreIdentOptionsValidatorTests()
    {
        _options = CreateValidOptions();
    }

    [Fact]
    public void Validate_WithValidOptions_ShouldReturnSuccess()
    {
        // Arrange
        _options = CreateValidOptions(); // Ensure fresh valid options

        // Act
        var result = _validator.Validate(null, _options); // Name is optional for Validate

        // Assert
        result.Succeeded.ShouldBeTrue(); // Success is indicated by Succeeded flag
        result.Failed.ShouldBeFalse();
        result.Skipped.ShouldBeFalse();
        // result.Failures might be null on success, so don't assert ShouldBeEmpty directly
    }

    // --- Issuer Tests ---
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")] // Whitespace
    public void Validate_WithInvalidIssuer_ShouldReturnFailure(string? invalidIssuer)
    {
        // Arrange
        _options.Issuer = invalidIssuer;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("Issuer is required.");
    }

    [Theory]
    [InlineData("not-a-uri")]
    [InlineData("relative/path")]
    public void Validate_WithMalformedIssuer_ShouldReturnFailure(string invalidIssuer)
    {
        _options.Issuer = invalidIssuer;

        var result = _validator.Validate(null, _options);

        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("Issuer must be a valid absolute URI.");
    }

    [Fact]
    public void Validate_WithHttpsIssuer_ShouldReturnSuccess()
    {
        _options.Issuer = "https://example.com";
        var result = _validator.Validate(null, _options);
        result.Succeeded.ShouldBeTrue();
    }

    [Theory]
    [InlineData("http://localhost")]
    [InlineData("http://127.0.0.1")]
    public void Validate_WithHttpLoopbackIssuer_ShouldReturnSuccess(string issuer)
    {
        _options.Issuer = issuer;
        var result = _validator.Validate(null, _options);
        result.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void Validate_WithHttpNonLoopbackIssuer_ShouldReturnFailure()
    {
        _options.Issuer = "http://example.com";
        var result = _validator.Validate(null, _options);
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("Issuer must use HTTPS scheme unless it's a loopback address.");
    }

    // --- Audience Tests ---
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithInvalidAudience_ShouldReturnFailure(string? invalidAudience)
    {
        // Arrange
        _options.Audience = invalidAudience;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("Audience is required.");
    }

    [Fact]
    public void Validate_WithInvalidAudienceUri_ShouldReturnFailure()
    {
        // Arrange
        _options.Audience = "not-a-uri";

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("Audience must be a valid absolute URI.");
    }

    [Fact]
    public void Validate_WithValidAudienceUri_ShouldReturnSuccess()
    {
        // Arrange
        _options.Audience = "https://example.org";

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    // --- SigningKeySecret Tests ---
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Validate_WithMissingSecret_ShouldReturnFailure(string? invalidSecret)
    {
        // Arrange
        _options.SigningKeySecret = invalidSecret;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        var failure = result.Failures.ShouldHaveSingleItem();
        failure.ShouldContain("SigningKeySecret is required."); // Specific message for missing
    }

    [Theory]
    [InlineData("   ")] // Whitespace only
    public void Validate_WithWhitespaceSecret_ShouldReturnFailure(string invalidSecret)
    {
        // Arrange
        _options.SigningKeySecret = invalidSecret;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        var failure = result.Failures.ShouldHaveSingleItem();
        // Whitespace should trigger the 'required' check due to IsNullOrWhiteSpace
        failure.ShouldContain("SigningKeySecret is required.");
    }

    [Theory]
    [InlineData("short")]           // Too short
    [InlineData("1234567890123456789012345678901")] // 31 chars
    public void Validate_WithShortSecret_ShouldReturnFailure(string invalidSecret)
    {
        // Arrange
        _options.SigningKeySecret = invalidSecret;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        var failure = result.Failures.ShouldHaveSingleItem();
        // Check for the 'too short' message, using the actual minimum length from the validator
        failure.ShouldContain("SigningKeySecret is too short. Minimum length is 32 bytes");
    }


    // --- AccessTokenLifetime Tests ---
    [Fact]
    public void Validate_WithZeroAccessTokenLifetime_ShouldReturnFailure()
    {
        // Arrange
        _options.AccessTokenLifetime = TimeSpan.Zero;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("AccessTokenLifetime must be a positive duration.");
    }

    [Fact]
    public void Validate_WithNegativeAccessTokenLifetime_ShouldReturnFailure()
    {
        // Arrange
        _options.AccessTokenLifetime = TimeSpan.FromMinutes(-1);

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("AccessTokenLifetime must be a positive duration.");
    }

    // --- RefreshTokenLifetime Tests ---
    [Fact]
    public void Validate_WithZeroRefreshTokenLifetime_ShouldReturnFailure()
    {
        // Arrange
        _options.RefreshTokenLifetime = TimeSpan.Zero;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("RefreshTokenLifetime must be a positive duration.");
    }

    [Fact]
    public void Validate_WithNegativeRefreshTokenLifetime_ShouldReturnFailure()
    {
        // Arrange
        _options.RefreshTokenLifetime = TimeSpan.FromDays(-1);

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("RefreshTokenLifetime must be a positive duration.");
    }

    [Fact]
    public void Validate_WithEqualRefreshTokenLifetime_ShouldReturnFailure()
    {
        // Arrange
        var equalLifetime = TimeSpan.FromHours(2);
        _options.AccessTokenLifetime = equalLifetime;
        _options.RefreshTokenLifetime = equalLifetime;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("RefreshTokenLifetime must be strictly greater than AccessTokenLifetime.");
    }

    [Fact]
    public void Validate_WithAccessTokenLifetimeExceedingMax_ShouldReturnFailure()
    {
        // Arrange
        var tooLong = TimeSpan.FromDays(1).Add(TimeSpan.FromSeconds(1));
        _options.AccessTokenLifetime = tooLong;
        _options.RefreshTokenLifetime = tooLong.Add(TimeSpan.FromHours(1));

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("AccessTokenLifetime must be no more than 1 day.");
    }

    [Fact]
    public void Validate_WithRefreshTokenLifetimeExceedingMax_ShouldReturnFailure()
    {
        // Arrange
        var tooLongRt = TimeSpan.FromDays(90).Add(TimeSpan.FromSeconds(1));
        _options.RefreshTokenLifetime = tooLongRt;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("RefreshTokenLifetime must be no more than 90 days.");
    }

    [Fact]
    public void Validate_WithAccessTokenLifetimeAtMax_ShouldReturnSuccess()
    {
        // Arrange
        _options.AccessTokenLifetime = TimeSpan.FromDays(1);
        _options.RefreshTokenLifetime = TimeSpan.FromDays(2);

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void Validate_WithRefreshTokenLifetimeAtMax_ShouldReturnSuccess()
    {
        // Arrange
        _options.RefreshTokenLifetime = TimeSpan.FromDays(90);

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    // --- TokenSecurity Tests ---
    [Fact]
    public void Validate_WithNullTokenSecurity_ShouldReturnFailure()
    {
        // Arrange
        _options.TokenSecurity = null!;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("TokenSecurity cannot be null.");
    }

    [Fact]
    public void Validate_WithInvalidTokenTheftDetectionMode_ShouldReturnFailure()
    {
        // Arrange
        // Cast an invalid value for the enum
        _options.TokenSecurity!.TokenTheftDetectionMode = (TokenTheftDetectionMode)99;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("TokenTheftDetectionMode must be a valid TokenTheftDetectionMode value.");
    }

    [Fact]
    public void Validate_WithRevokeFamilyAndNoTracking_ShouldReturnFailure()
    {
        // Arrange
        _options.TokenSecurity!.TokenTheftDetectionMode = TokenTheftDetectionMode.RevokeFamily;
        _options.TokenSecurity!.EnableTokenFamilyTracking = false;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("EnableTokenFamilyTracking must be true when TokenTheftDetectionMode is set to RevokeFamily.");
    }

    [Fact]
    public void Validate_WithSilentModeAndNoTracking_ShouldSucceed()
    {
        // Arrange
        _options.TokenSecurity!.TokenTheftDetectionMode = TokenTheftDetectionMode.Silent;
        _options.TokenSecurity!.EnableTokenFamilyTracking = false;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void Validate_WithRevokeAllUserTokensAndNoTracking_ShouldSucceed()
    {
        // Arrange
        _options.TokenSecurity!.TokenTheftDetectionMode = TokenTheftDetectionMode.RevokeAllUserTokens;
        _options.TokenSecurity!.EnableTokenFamilyTracking = false;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    // --- ConsumedTokenRetentionPeriod Tests ---
    [Fact]
    public void Validate_WithNegativeConsumedTokenRetentionPeriod_ShouldReturnFailure()
    {
        // Arrange
        _options.ConsumedTokenRetentionPeriod = TimeSpan.FromDays(-1);

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.ShouldHaveSingleItem().ShouldContain("ConsumedTokenRetentionPeriod must be non-negative.");
    }

    [Fact]
    public void Validate_WithZeroConsumedTokenRetentionPeriod_ShouldReturnSuccess()
    {
        // Arrange
        _options.ConsumedTokenRetentionPeriod = TimeSpan.Zero;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Succeeded.ShouldBeTrue();
    }

    // --- Multiple Failures Test ---
    [Fact]
    public void Validate_WithMultipleFailures_ShouldListAllFailures()
    {
        // Arrange
        _options.Issuer = null;
        _options.Audience = "";
        _options.SigningKeySecret = "short";
        _options.AccessTokenLifetime = TimeSpan.Zero;
        _options.RefreshTokenLifetime = TimeSpan.FromSeconds(-10);
        _options.TokenSecurity!.TokenTheftDetectionMode = TokenTheftDetectionMode.RevokeFamily;
        _options.TokenSecurity!.EnableTokenFamilyTracking = false;

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.Count().ShouldBe(6);
        result.Failures.ShouldContain(f => f.Contains("Issuer is required."));
        result.Failures.ShouldContain(f => f.Contains("Audience is required."));
        result.Failures.ShouldContain(f => f.Contains("SigningKeySecret is too short"));
        result.Failures.ShouldContain(f => f.Contains("AccessTokenLifetime must be a positive duration."));
        result.Failures.ShouldContain(f => f.Contains("RefreshTokenLifetime must be a positive duration."));
        result.Failures.ShouldContain(f => f.Contains("EnableTokenFamilyTracking must be true when TokenTheftDetectionMode is set to RevokeFamily."));
    }
}
