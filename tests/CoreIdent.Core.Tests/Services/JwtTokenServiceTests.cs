using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Shouldly;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class JwtTokenServiceTests
{
    private readonly Mock<IOptions<CoreIdentOptions>> _mockOptions;
    private readonly Mock<IUserStore> _mockUserStore;
    private readonly Mock<IRefreshTokenStore> _mockRefreshTokenStore;
    private readonly Mock<IScopeStore> _mockScopeStore;
    private readonly Mock<ILogger<JwtTokenService>> _mockLogger;
    private readonly CoreIdentOptions _options;
    private readonly JwtTokenService _tokenService;
    private readonly CoreIdentUser _testUser;

    public JwtTokenServiceTests()
    {
        _options = new CoreIdentOptions
        {
            Issuer = "https://test.issuer.com",
            Audience = "test-audience",
            SigningKeySecret = Convert.ToBase64String(Encoding.UTF8.GetBytes("ThisIsAValidSecretKeyForTesting1234567890")), // >= 32 bytes
            AccessTokenLifetime = TimeSpan.FromMinutes(15),
            RefreshTokenLifetime = TimeSpan.FromDays(1)
        };

        _mockOptions = new Mock<IOptions<CoreIdentOptions>>();
        _mockOptions.Setup(o => o.Value).Returns(_options);

        _testUser = new CoreIdentUser { Id = "test-user-id", UserName = "test@example.com" };
        _mockUserStore = new Mock<IUserStore>();
        _mockUserStore.Setup(s => s.GetClaimsAsync(_testUser, It.IsAny<CancellationToken>()))
                      .ReturnsAsync(new List<Claim> { new Claim("custom_claim", "value") });

        _mockRefreshTokenStore = new Mock<IRefreshTokenStore>();
        _mockScopeStore = new Mock<IScopeStore>();
        _mockScopeStore.Setup(s => s.FindScopesByNameAsync(It.Is<IEnumerable<string>>(names => names.Contains("api1")), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(new List<CoreIdentScope>
                       {
                           new CoreIdentScope
                           {
                               Name = "api1",
                               UserClaims = new List<CoreIdentScopeClaim> { new CoreIdentScopeClaim { Type = "custom_claim" } }
                           }
                       });
        _mockScopeStore.Setup(s => s.FindScopesByNameAsync(It.Is<IEnumerable<string>>(names => !names.Contains("api1")), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(new List<CoreIdentScope>());
        _mockLogger = new Mock<ILogger<JwtTokenService>>();

        _tokenService = new JwtTokenService(
            _mockOptions.Object,
            _mockUserStore.Object,
            _mockRefreshTokenStore.Object,
            _mockScopeStore.Object,
            _mockLogger.Object
            );
    }

    [Fact]
    public void Constructor_Throws_When_Options_Null()
    {
        // Arrange
        var nullOptions = new Mock<IOptions<CoreIdentOptions>>();
        nullOptions.Setup(o => o.Value).Returns((CoreIdentOptions)null!); // Return null options

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => new JwtTokenService(nullOptions.Object, _mockUserStore.Object, _mockRefreshTokenStore.Object, _mockScopeStore.Object, _mockLogger.Object));
    }

    [Fact]
    public void Constructor_Throws_When_UserStore_Null()
    {
        // Act & Assert
        Should.Throw<ArgumentNullException>(() => new JwtTokenService(_mockOptions.Object, null!, _mockRefreshTokenStore.Object, _mockScopeStore.Object, _mockLogger.Object));
    }

    // TODO: Add tests for null RefreshTokenStore, ScopeStore, Logger

    [Fact]
    public void Constructor_Throws_When_SigningKeySecret_NullOrWhiteSpace()
    {
        // Arrange
        var invalidOptions = new CoreIdentOptions { Issuer = "iss", Audience = "aud", SigningKeySecret = " " };
        var mockInvalidOptions = new Mock<IOptions<CoreIdentOptions>>();
        mockInvalidOptions.Setup(o => o.Value).Returns(invalidOptions);

        // Act & Assert
        var ex = Should.Throw<ArgumentException>(() => new JwtTokenService(mockInvalidOptions.Object, _mockUserStore.Object, _mockRefreshTokenStore.Object, _mockScopeStore.Object, _mockLogger.Object));
        ex.ParamName.ShouldBe(nameof(CoreIdentOptions.SigningKeySecret));
    }

    [Fact]
    public void Constructor_Throws_When_SigningKeySecret_TooShort()
    {
        // Arrange
        var invalidOptions = new CoreIdentOptions { Issuer = "iss", Audience = "aud", SigningKeySecret = "tooshort" };
        var mockInvalidOptions = new Mock<IOptions<CoreIdentOptions>>();
        mockInvalidOptions.Setup(o => o.Value).Returns(invalidOptions);

        // Act & Assert
        var ex = Should.Throw<ArgumentException>(() => new JwtTokenService(mockInvalidOptions.Object, _mockUserStore.Object, _mockRefreshTokenStore.Object, _mockScopeStore.Object, _mockLogger.Object));
        ex.ParamName.ShouldBe(nameof(CoreIdentOptions.SigningKeySecret));
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ReturnsValidJwt()
    {
        // Arrange
        var user = _testUser;
        var requestedScopes = new List<string> { "api1" }; // Request the scope that allows "custom_claim"

        // --- Check claims generation separately ---
        var userClaimsFromStore = await _mockUserStore.Object.GetClaimsAsync(user, CancellationToken.None);
        // Need access to the private GetClaimsForTokenAsync or replicate its logic for testing
        // Let's create a minimal list based on expected logic for this test
        var expectedClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id), // This is the key check
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JTI is random, check type
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()), // IAT, check type/approx value
            new Claim("custom_claim", "value"), // Allowed by scope api1
            new Claim("scope", string.Join(" ", requestedScopes)) // Scope claim
        };

        // Act
        var token = await _tokenService.GenerateAccessTokenAsync(user, requestedScopes);

        // Assert
        token.ShouldNotBeNullOrWhiteSpace();

        var handler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKeySecret!)),
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // Important for testing expiry
        };

        SecurityToken validatedToken;
        var principal = handler.ValidateToken(token, validationParameters, out validatedToken);

        principal.ShouldNotBeNull();
        validatedToken.ShouldNotBeNull();
        validatedToken.ShouldBeOfType<JwtSecurityToken>();

        var jwtToken = (JwtSecurityToken)validatedToken;
        jwtToken.Issuer.ShouldBe(_options.Issuer);
        jwtToken.Audiences.ShouldContain(_options.Audience);

        // Assert core claims exist and have correct values/types
        var subClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub);
        subClaim.ShouldNotBeNull();
        subClaim.Value.ShouldBe(user.Id); // Specific assertion for sub claim

        jwtToken.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Jti); // Check for JTI
        jwtToken.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Iat); // Check for IAT
        jwtToken.Claims.ShouldContain(c => c.Type == "custom_claim" && c.Value == "value"); // Check for custom claim from store
        jwtToken.Claims.ShouldContain(c => c.Type == "scope" && c.Value == string.Join(" ", requestedScopes)); // Check scope claim

        // Check expiry is roughly correct
        var expectedExpiry = DateTime.UtcNow.Add(_options.AccessTokenLifetime);
        jwtToken.ValidTo.ShouldBeGreaterThan(expectedExpiry.Subtract(TimeSpan.FromSeconds(10)));
        jwtToken.ValidTo.ShouldBeLessThan(expectedExpiry.Add(TimeSpan.FromSeconds(10)));
    }

    // TODO: Add test for GenerateAccessTokenAsync with scopes
    // TODO: Add test for GenerateIdTokenAsync

    [Fact]
    public async Task GenerateRefreshTokenAsync_ReturnsUniqueTokens()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "test-user-id", UserName = "test@example.com" };
        var clientId = "test-client"; // Need a client ID for the new method

        // Act
        var token1 = await _tokenService.GenerateAndStoreRefreshTokenAsync(user, clientId);
        var token2 = await _tokenService.GenerateAndStoreRefreshTokenAsync(user, clientId);

        // Assert
        token1.ShouldNotBeNullOrWhiteSpace();
        token2.ShouldNotBeNullOrWhiteSpace();
        token1.ShouldNotBe(token2); // Should be unique handles

        // Verify store was called twice
        _mockRefreshTokenStore.Verify(s => s.StoreRefreshTokenAsync(It.IsAny<CoreIdentRefreshToken>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    // TODO: Add tests for GenerateAndStoreRefreshTokenAsync failure scenarios (e.g., store throws)
}
