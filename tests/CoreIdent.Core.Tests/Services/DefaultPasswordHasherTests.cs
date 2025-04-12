using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class DefaultPasswordHasherTests
{
    private readonly DefaultPasswordHasher _hasher = new();
    private readonly CoreIdentUser _testUser = new() { Id = "test-user-id", UserName = "test@example.com" };
    private const string TestPassword = "Password123!";

    [Fact]
    public void HashPassword_WithUser_ShouldReturnNonNullNonEmptyString()
    {
        // Arrange
        var password = TestPassword;

        // Act
        var hashedPassword = _hasher.HashPassword(_testUser, password);

        // Assert
        Assert.NotNull(hashedPassword);
        Assert.NotEmpty(hashedPassword);
        hashedPassword.ShouldNotBe(password);
    }

    [Fact]
    public void HashPassword_WithNullUser_ShouldReturnNonNullNonEmptyString()
    {
        // Arrange
        var password = TestPassword;

        // Act
        var hashedPassword = _hasher.HashPassword(null, password);

        // Assert
        Assert.NotNull(hashedPassword);
        Assert.NotEmpty(hashedPassword);
        hashedPassword.ShouldNotBe(password);
    }

    [Fact]
    public void VerifyHashedPassword_WithCorrectPasswordAndUser_ShouldReturnSuccess()
    {
        // Arrange
        var password = TestPassword;
        var hashedPassword = _hasher.HashPassword(_testUser, password);

        // Act
        var result = _hasher.VerifyHashedPassword(_testUser, hashedPassword, password);

        // Assert
        result.ShouldBe(PasswordVerificationResult.Success);
    }

    [Fact]
    public void VerifyHashedPassword_WithCorrectPasswordAndNullUser_ShouldReturnSuccess()
    {
        // Arrange
        var password = TestPassword;
        // Hash with null user context initially
        var hashedPassword = _hasher.HashPassword(null, password);

        // Act
        // Verify with null user context
        var result = _hasher.VerifyHashedPassword(null, hashedPassword, password);

        // Assert
        result.ShouldBe(PasswordVerificationResult.Success);
    }


    [Fact]
    public void VerifyHashedPassword_WithIncorrectPassword_ShouldReturnFailed()
    {
        // Arrange
        var correctPassword = TestPassword;
        var incorrectPassword = "WrongPassword!";
        var hashedPassword = _hasher.HashPassword(_testUser, correctPassword);

        // Act
        var result = _hasher.VerifyHashedPassword(_testUser, hashedPassword, incorrectPassword);

        // Assert
        result.ShouldBe(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void VerifyHashedPassword_WithTamperedHash_ShouldReturnFailed()
    {
        // Arrange
        var password = TestPassword;
        var hashedPassword = _hasher.HashPassword(_testUser, password);
        // Slightly modify the hash
        var tamperedHash = "X" + hashedPassword.Substring(1);

        // Act
        var result = _hasher.VerifyHashedPassword(_testUser, tamperedHash, password);

        // Assert
        result.ShouldBe(PasswordVerificationResult.Failed);
    }

    // Note: Testing SuccessRehashNeeded is difficult without controlling the underlying
    // PasswordHasherOptions or knowing when Identity decides a rehash is needed.
    // We assume the mapping logic tested implicitly in the success case is sufficient.
}
