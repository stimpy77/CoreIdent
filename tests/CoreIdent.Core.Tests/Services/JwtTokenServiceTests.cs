using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Shouldly;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class JwtTokenServiceTests
{
    private readonly Mock<IOptions<CoreIdentOptions>> _mockOptions;
    private readonly CoreIdentOptions _validOptions;
    private readonly JwtTokenService _tokenService;
    private readonly CoreIdentUser _testUser;

    public JwtTokenServiceTests()
    {
        _validOptions = new CoreIdentOptions
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningKeySecret = "a_super_secret_key_needs_to_be_long_enough_for_hs256", // >= 32 bytes
            AccessTokenLifetime = TimeSpan.FromMinutes(15),
            RefreshTokenLifetime = TimeSpan.FromDays(7)
        };

        _mockOptions = new Mock<IOptions<CoreIdentOptions>>();
        _mockOptions.Setup(o => o.Value).Returns(_validOptions);

        _tokenService = new JwtTokenService(_mockOptions.Object);

        _testUser = new CoreIdentUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = "test@example.com"
            // Email removed, user only has UserName
            // Add roles or other claims if needed for tests
        };
    }

    [Fact]
    public void Constructor_WithMissingSecret_ShouldThrowArgumentNullException()
    {
        // Arrange
        var invalidOptions = new CoreIdentOptions
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningKeySecret = null, // Missing secret
            AccessTokenLifetime = TimeSpan.FromMinutes(15)
        };
        var mockInvalidOptions = new Mock<IOptions<CoreIdentOptions>>();
        mockInvalidOptions.Setup(o => o.Value).Returns(invalidOptions);

        // Act
        Action act = () => new JwtTokenService(mockInvalidOptions.Object);

        // Assert
        Should.Throw<ArgumentNullException>(() => act())
              .ParamName.ShouldBe("SigningKeySecret");
    }

     [Fact]
    public void Constructor_WithShortSecret_ShouldThrowArgumentException()
    {
        // Arrange
        var invalidOptions = new CoreIdentOptions
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningKeySecret = "short", // Invalid secret
            AccessTokenLifetime = TimeSpan.FromMinutes(15)
        };
        var mockInvalidOptions = new Mock<IOptions<CoreIdentOptions>>();
        mockInvalidOptions.Setup(o => o.Value).Returns(invalidOptions);

        // Act
        Action act = () => new JwtTokenService(mockInvalidOptions.Object);

        // Assert
        var exception = Should.Throw<ArgumentException>(() => act());
        exception.ParamName.ShouldBe("SigningKeySecret");
        exception.Message.ShouldContain("must be at least 32 bytes");
    }


    [Fact]
    public async Task GenerateAccessTokenAsync_WithNullUser_ShouldThrowArgumentNullException()
    {
        // Arrange
        CoreIdentUser? user = null;

        // Act & Assert
        // Use await directly with Should.ThrowAsync for async method calls
        // Remove ConfigureAwait(false) to address xUnit1030
        await Should.ThrowAsync<ArgumentNullException>(() => _tokenService.GenerateAccessTokenAsync(user!));
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_WithValidUserAndOptions_ShouldGenerateValidJwt()
    {
        // Arrange
        var user = _testUser;

        // Act
        // Service returns string directly in Phase 1
        var tokenString = await _tokenService.GenerateAccessTokenAsync(user);

        // Assert
        tokenString.ShouldNotBeNullOrWhiteSpace();

        // Decode and validate the token
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _validOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = _validOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_validOptions.SigningKeySecret!)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // No tolerance for expiration in tests
        };

        ClaimsPrincipal? claimsPrincipal = null;
        Should.NotThrow(() => claimsPrincipal = handler.ValidateToken(tokenString, validationParameters, out _));

        claimsPrincipal.ShouldNotBeNull();

        // Check standard claims
        claimsPrincipal.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Iss && c.Value == _validOptions.Issuer);
        claimsPrincipal.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Aud && c.Value == _validOptions.Audience);
        claimsPrincipal.Claims.ShouldContain(c => c.Type == ClaimTypes.NameIdentifier && c.Value == user.Id); // Check for NameIdentifier
        claimsPrincipal.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Jti); // Check for JWT ID
        claimsPrincipal.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Exp); // Check for expiration
        claimsPrincipal.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Nbf); // Check for not before
        claimsPrincipal.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Iat); // Check for issued at

        // Check standard profile claim (Name)
        var nameClaim = claimsPrincipal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
        nameClaim.ShouldNotBeNull();
        nameClaim.Value.ShouldBe(user.UserName); // Assert value after ensuring claim exists

        // Check expiration is roughly correct
        var expClaim = claimsPrincipal.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp);
        expClaim.ShouldNotBeNull(); // Ensure the claim exists before accessing its value
        expClaim.Value.ShouldNotBeNullOrWhiteSpace(); // Explicitly check Value is not null/ws
        long expValue;
        long.TryParse(expClaim.Value, out expValue).ShouldBeTrue(); // Now this should be safe
        var expDateTime = DateTimeOffset.FromUnixTimeSeconds(expValue).UtcDateTime;

        var expectedExp = DateTime.UtcNow.Add(_validOptions.AccessTokenLifetime);
        expDateTime.ShouldBeGreaterThan(DateTime.UtcNow);
        // Allow a small delta for test execution time
        expDateTime.ShouldBeLessThanOrEqualTo(expectedExp.AddSeconds(10));
        expDateTime.ShouldBeGreaterThanOrEqualTo(expectedExp.AddSeconds(-10));
    }

    [Fact]
    public async Task GenerateRefreshTokenAsync_ShouldGenerateUniqueString()
    {
        // Arrange
        var user = _testUser;

        // Act
        var token1 = await _tokenService.GenerateRefreshTokenAsync(user);
        var token2 = await _tokenService.GenerateRefreshTokenAsync(user);

        // Assert
        token1.ShouldNotBeNullOrWhiteSpace();
        token2.ShouldNotBeNullOrWhiteSpace();
        token1.Length.ShouldBeGreaterThan(30); // Check for reasonable length (Base64 of 32 bytes is > 30)
        token2.Length.ShouldBeGreaterThan(30);
        token1.ShouldNotBe(token2); // Should be unique
    }

    // TODO: Add test for ValidateToken if needed (though covered indirectly by GenerateAccessToken test)
}
