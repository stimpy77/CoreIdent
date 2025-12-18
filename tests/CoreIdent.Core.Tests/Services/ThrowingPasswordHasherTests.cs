using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public sealed class ThrowingPasswordHasherTests
{
    private readonly ThrowingPasswordHasher _hasher = new();
    private readonly CoreIdentUser _testUser = new()
    {
        Id = "test-user-id",
        UserName = "test@example.com",
        NormalizedUserName = "TEST@EXAMPLE.COM",
        CreatedAt = DateTime.UtcNow
    };

    [Fact]
    public void HashPassword_throws_when_user_is_null()
    {
        // Arrange
        CoreIdentUser? user = null;
        var password = "password123";

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => _hasher.HashPassword(user!, password));
    }

    [Fact]
    public void HashPassword_throws_when_password_is_null()
    {
        // Arrange
        var password = null as string;

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.HashPassword(_testUser, password!));
    }

    [Fact]
    public void HashPassword_throws_when_password_is_empty()
    {
        // Arrange
        var password = "";

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.HashPassword(_testUser, password));
    }

    [Fact]
    public void HashPassword_throws_when_password_is_whitespace()
    {
        // Arrange
        var password = "   ";

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.HashPassword(_testUser, password));
    }

    [Fact]
    public void HashPassword_throws_operation_exception_when_valid_inputs()
    {
        // Arrange
        var password = "password123";

        // Act & Assert
        var exception = Should.Throw<InvalidOperationException>(() => _hasher.HashPassword(_testUser, password));
        exception.Message.ShouldBe("No IPasswordHasher has been configured.");
    }

    [Fact]
    public void VerifyHashedPassword_throws_when_user_is_null()
    {
        // Arrange
        CoreIdentUser? user = null;
        var hashedPassword = "hashed123";
        var providedPassword = "password123";

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => _hasher.VerifyHashedPassword(user!, hashedPassword, providedPassword));
    }

    [Fact]
    public void VerifyHashedPassword_throws_when_hashed_password_is_null()
    {
        // Arrange
        string? hashedPassword = null;
        var providedPassword = "password123";

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword!, providedPassword));
    }

    [Fact]
    public void VerifyHashedPassword_throws_when_hashed_password_is_empty()
    {
        // Arrange
        var hashedPassword = "";
        var providedPassword = "password123";

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword));
    }

    [Fact]
    public void VerifyHashedPassword_throws_when_hashed_password_is_whitespace()
    {
        // Arrange
        var hashedPassword = "   ";
        var providedPassword = "password123";

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword));
    }

    [Fact]
    public void VerifyHashedPassword_throws_when_provided_password_is_null()
    {
        // Arrange
        var hashedPassword = "hashed123";
        string? providedPassword = null;

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword!));
    }

    [Fact]
    public void VerifyHashedPassword_throws_when_provided_password_is_empty()
    {
        // Arrange
        var hashedPassword = "hashed123";
        var providedPassword = "";

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword));
    }

    [Fact]
    public void VerifyHashedPassword_throws_when_provided_password_is_whitespace()
    {
        // Arrange
        var hashedPassword = "hashed123";
        var providedPassword = "   ";

        // Act & Assert
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword));
    }

    [Fact]
    public void VerifyHashedPassword_throws_operation_exception_when_valid_inputs()
    {
        // Arrange
        var hashedPassword = "hashed123";
        var providedPassword = "password123";

        // Act & Assert
        var exception = Should.Throw<InvalidOperationException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword));
        exception.Message.ShouldBe("No IPasswordHasher has been configured.");
    }

    [Fact]
    public void VerifyHashedPassword_throws_operation_exception_when_passwords_dont_match()
    {
        // Arrange
        var hashedPassword = "different_hash";
        var providedPassword = "different_password";

        // Act & Assert
        var exception = Should.Throw<InvalidOperationException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword));
        exception.Message.ShouldBe("No IPasswordHasher has been configured.");
    }

    [Fact]
    public void HashPassword_handles_different_user_types()
    {
        // Arrange
        var differentUser = new CoreIdentUser
        {
            Id = "different-user",
            UserName = "different@example.com",
            NormalizedUserName = "DIFFERENT@EXAMPLE.COM",
            CreatedAt = DateTime.UtcNow.AddDays(-1)
        };
        var password = "password123";

        // Act & Assert
        var exception = Should.Throw<InvalidOperationException>(() => _hasher.HashPassword(differentUser, password));
        exception.Message.ShouldBe("No IPasswordHasher has been configured.");
    }

    [Fact]
    public void VerifyHashedPassword_handles_special_characters_in_passwords()
    {
        // Arrange
        var hashedPassword = "hash_with_special_!@#$%";
        var providedPassword = "password_with_special_!@#$%";

        // Act & Assert
        var exception = Should.Throw<InvalidOperationException>(() => _hasher.VerifyHashedPassword(_testUser, hashedPassword, providedPassword));
        exception.Message.ShouldBe("No IPasswordHasher has been configured.");
    }
}
