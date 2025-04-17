using CoreIdent.Core.Services;
using Shouldly;
using System;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class TokenHasherTests
{
    [Fact]
    public void HashToken_WithValidInput_ReturnsHashedValue()
    {
        // Arrange
        string tokenHandle = "some-random-token-handle";
        string salt = "salt-value";
        
        // Act
        string hash = TokenHasher.HashToken(tokenHandle, salt);
        
        // Assert
        hash.ShouldNotBeNullOrEmpty();
        hash.ShouldNotBe(tokenHandle); // Hash should be different from original
        hash.ShouldNotContain("+"); // Should be URL-safe
        hash.ShouldNotContain("/"); // Should be URL-safe
        hash.ShouldNotEndWith("="); // Should be URL-safe, no padding
    }
    
    [Fact]
    public void HashToken_SameInputAndSalt_ReturnsSameHash()
    {
        // Arrange
        string tokenHandle = "some-random-token-handle";
        string salt = "salt-value";
        
        // Act
        string hash1 = TokenHasher.HashToken(tokenHandle, salt);
        string hash2 = TokenHasher.HashToken(tokenHandle, salt);
        
        // Assert
        hash1.ShouldBe(hash2); // Hashing should be deterministic
    }
    
    [Fact]
    public void HashToken_DifferentSalts_ReturnsDifferentHashes()
    {
        // Arrange
        string tokenHandle = "some-random-token-handle";
        string salt1 = "salt-value-1";
        string salt2 = "salt-value-2";
        
        // Act
        string hash1 = TokenHasher.HashToken(tokenHandle, salt1);
        string hash2 = TokenHasher.HashToken(tokenHandle, salt2);
        
        // Assert
        hash1.ShouldNotBe(hash2); // Different salts should yield different hashes
    }
    
    [Fact]
    public void HashToken_WithUserIdAndClientId_ReturnsHashedValue()
    {
        // Arrange
        string tokenHandle = "some-random-token-handle";
        string userId = "user123";
        string clientId = "client456";
        
        // Act
        string hash = TokenHasher.HashToken(tokenHandle, userId, clientId);
        
        // Assert
        hash.ShouldNotBeNullOrEmpty();
        hash.ShouldNotBe(tokenHandle); // Hash should be different from original
    }
    
    [Theory]
    [InlineData(null, "salt")]
    [InlineData("", "salt")]
    public void HashToken_WithInvalidToken_ThrowsArgumentNullException(string? invalidToken, string salt)
    {
        // Act & Assert
        Should.Throw<ArgumentNullException>(() => TokenHasher.HashToken(invalidToken!, salt));
    }
    
    [Fact]
    public void HashToken_WithNullSalt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Should.Throw<ArgumentNullException>(() => TokenHasher.HashToken("token", null!));
    }
    
    [Fact]
    public void VerifyToken_WithMatchingTokenAndHash_ReturnsTrue()
    {
        // Arrange
        string tokenHandle = "some-random-token-handle";
        string salt = "salt-value";
        string hash = TokenHasher.HashToken(tokenHandle, salt);
        
        // Act
        bool result = TokenHasher.VerifyToken(tokenHandle, hash, salt);
        
        // Assert
        result.ShouldBeTrue();
    }
    
    [Fact]
    public void VerifyToken_WithNonMatchingToken_ReturnsFalse()
    {
        // Arrange
        string tokenHandle1 = "some-random-token-handle";
        string tokenHandle2 = "different-token-handle";
        string salt = "salt-value";
        string hash = TokenHasher.HashToken(tokenHandle1, salt);
        
        // Act
        bool result = TokenHasher.VerifyToken(tokenHandle2, hash, salt);
        
        // Assert
        result.ShouldBeFalse();
    }
    
    [Fact]
    public void VerifyToken_WithUserIdAndClientId_ReturnsTrueForMatch()
    {
        // Arrange
        string tokenHandle = "some-random-token-handle";
        string userId = "user123";
        string clientId = "client456";
        string hash = TokenHasher.HashToken(tokenHandle, userId, clientId);
        
        // Act
        bool result = TokenHasher.VerifyToken(tokenHandle, hash, userId, clientId);
        
        // Assert
        result.ShouldBeTrue();
    }
    
    [Fact]
    public void VerifyToken_WithDifferentUserIdOrClientId_ReturnsFalseForNonMatch()
    {
        // Arrange
        string tokenHandle = "some-random-token-handle";
        string userId1 = "user123";
        string userId2 = "user456";
        string clientId = "client456";
        string hash = TokenHasher.HashToken(tokenHandle, userId1, clientId);
        
        // Act
        bool result = TokenHasher.VerifyToken(tokenHandle, hash, userId2, clientId);
        
        // Assert
        result.ShouldBeFalse();
    }
} 