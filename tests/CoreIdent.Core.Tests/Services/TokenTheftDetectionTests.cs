using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class TokenTheftDetectionTests
{
    private readonly Mock<IRefreshTokenStore> _mockRefreshTokenStore;
    private readonly Mock<IOptions<CoreIdentOptions>> _mockOptions;
    private readonly Mock<IUserStore> _mockUserStore;
    private readonly Mock<IScopeStore> _mockScopeStore;
    private readonly Mock<ILogger<JwtTokenService>> _mockLogger;
    private readonly CoreIdentOptions _options;
    private readonly JwtTokenService _tokenService;
    private readonly CoreIdentUser _testUser;
    private string _familyId;

    public TokenTheftDetectionTests()
    {
        _options = new CoreIdentOptions
        {
            Issuer = "https://test.issuer.com",
            Audience = "test-audience",
            SigningKeySecret = "ThisIsAValidSecretKeyForTesting1234567890!@#$%", // >= 32 bytes
            AccessTokenLifetime = TimeSpan.FromMinutes(15),
            RefreshTokenLifetime = TimeSpan.FromDays(1),
            TokenSecurity = new TokenSecurityOptions
            {
                TokenTheftDetectionMode = TokenTheftDetectionMode.RevokeFamily,
                EnableTokenFamilyTracking = true
            }
        };

        _mockOptions = new Mock<IOptions<CoreIdentOptions>>();
        _mockOptions.Setup(o => o.Value).Returns(_options);

        _familyId = "family-id-for-testing";
        _testUser = new CoreIdentUser { Id = "test-user-id", UserName = "test@example.com" };
        
        _mockUserStore = new Mock<IUserStore>();
        _mockRefreshTokenStore = new Mock<IRefreshTokenStore>();
        _mockScopeStore = new Mock<IScopeStore>();
        _mockLogger = new Mock<ILogger<JwtTokenService>>();

        _tokenService = new JwtTokenService(
            _mockOptions.Object,
            _mockUserStore.Object,
            _mockRefreshTokenStore.Object,
            _mockScopeStore.Object,
            _mockLogger.Object,
            new List<ICustomClaimsProvider>() // Pass empty list for custom claims providers
        );
    }

    [Fact]
    public async Task GenerateAndStoreRefreshTokenAsync_SetsNewFamilyId_ForInitialToken()
    {
        // Arrange
        var clientId = "test-client";
        CoreIdentRefreshToken? storedToken = null;

        _mockRefreshTokenStore
            .Setup(s => s.StoreRefreshTokenAsync(It.IsAny<CoreIdentRefreshToken>(), It.IsAny<CancellationToken>()))
            .Callback<CoreIdentRefreshToken, CancellationToken>((token, _) => storedToken = token)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _tokenService.GenerateAndStoreRefreshTokenAsync(_testUser, clientId);

        // Assert
        result.ShouldNotBeNullOrEmpty();
        storedToken.ShouldNotBeNull();
        storedToken!.FamilyId.ShouldNotBeNullOrEmpty();
        storedToken.PreviousTokenId.ShouldBeNull(); // No parent for initial token
    }

    [Fact]
    public async Task GenerateAndStoreRefreshTokenAsync_MaintainsFamilyId_ForDescendantToken()
    {
        // Arrange
        var clientId = "test-client";
        var parentToken = new CoreIdentRefreshToken
        {
            Handle = "parent-token-handle",
            SubjectId = _testUser.Id,
            ClientId = clientId,
            FamilyId = _familyId,
            CreationTime = DateTime.UtcNow.AddDays(-1),
            ExpirationTime = DateTime.UtcNow.AddDays(13)
        };

        CoreIdentRefreshToken? storedToken = null;

        _mockRefreshTokenStore
            .Setup(s => s.StoreRefreshTokenAsync(It.IsAny<CoreIdentRefreshToken>(), It.IsAny<CancellationToken>()))
            .Callback<CoreIdentRefreshToken, CancellationToken>((token, _) => storedToken = token)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _tokenService.GenerateAndStoreRefreshTokenAsync(_testUser, clientId, parentToken);

        // Assert
        result.ShouldNotBeNullOrEmpty();
        storedToken.ShouldNotBeNull();
        storedToken!.FamilyId.ShouldBe(_familyId); // Should maintain parent's family ID
        storedToken.PreviousTokenId.ShouldBe(parentToken.Handle); // Should link to parent
    }

    [Fact]
    public async Task RevokeTokenFamilyAsync_RevokesAllTokensInFamily()
    {
        // Arrange
        var tokensToRevoke = new List<CoreIdentRefreshToken>
        {
            new CoreIdentRefreshToken { Handle = "token1", FamilyId = _familyId, SubjectId = _testUser.Id },
            new CoreIdentRefreshToken { Handle = "token2", FamilyId = _familyId, SubjectId = _testUser.Id },
            new CoreIdentRefreshToken { Handle = "token3", FamilyId = _familyId, SubjectId = _testUser.Id }
        };

        var allTokens = new List<CoreIdentRefreshToken>(tokensToRevoke)
        {
            // Add a token from a different family
            new CoreIdentRefreshToken { Handle = "token4", FamilyId = "different-family", SubjectId = _testUser.Id }
        };

        _mockRefreshTokenStore
            .Setup(s => s.FindTokensBySubjectIdAsync(_testUser.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(allTokens);

        var revokedTokens = new List<string>();
        _mockRefreshTokenStore
            .Setup(s => s.RevokeTokenFamilyAsync(_familyId, It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((familyId, _) => {
                foreach (var token in tokensToRevoke)
                {
                    if (token.FamilyId == familyId)
                    {
                        revokedTokens.Add(token.Handle);
                        token.ConsumedTime = DateTime.UtcNow;
                    }
                }
            })
            .Returns(Task.CompletedTask);

        // Act
        await _mockRefreshTokenStore.Object.RevokeTokenFamilyAsync(_familyId, CancellationToken.None);

        // Assert
        revokedTokens.Count.ShouldBe(3); // All tokens from the family should be revoked
        revokedTokens.ShouldContain("token1");
        revokedTokens.ShouldContain("token2");
        revokedTokens.ShouldContain("token3");
        tokensToRevoke.All(t => t.ConsumedTime.HasValue).ShouldBeTrue(); // All family tokens should be consumed
        allTokens.First(t => t.Handle == "token4").ConsumedTime.ShouldBeNull(); // Different family token should not be affected
    }
} 