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
            RefreshTokenLifetime = TimeSpan.FromDays(7)
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

        // Act
        var result = _validator.Validate(null, _options);

        // Assert
        result.Failed.ShouldBeTrue();
        result.Failures.Count().ShouldBe(5);
        result.Failures.ShouldContain(f => f.Contains("Issuer is required."));
        result.Failures.ShouldContain(f => f.Contains("Audience is required."));
        result.Failures.ShouldContain(f => f.Contains("SigningKeySecret is too short"));
        result.Failures.ShouldContain(f => f.Contains("AccessTokenLifetime must be a positive duration."));
        result.Failures.ShouldContain(f => f.Contains("RefreshTokenLifetime must be a positive duration."));
    }
}
