using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Passwords.AspNetIdentity.Services;
using Shouldly;

namespace CoreIdent.Core.Tests.Services;

public class DefaultPasswordHasherTests
{
    private readonly DefaultPasswordHasher _hasher = new();

    private static CoreIdentUser CreateUser() => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        UserName = "test@example.com",
        NormalizedUserName = "TEST@EXAMPLE.COM",
        CreatedAt = DateTime.UtcNow
    };

    [Fact]
    public void HashPassword_ReturnsNonEmptyHash()
    {
        var user = CreateUser();

        var hash = _hasher.HashPassword(user, "Test123!");

        hash.ShouldNotBeNullOrWhiteSpace("hash should not be empty");
    }

    [Fact]
    public void VerifyHashedPassword_ReturnsTrue_ForValidPassword()
    {
        var user = CreateUser();
        const string password = "Test123!";
        var hash = _hasher.HashPassword(user, password);

        var result = _hasher.VerifyHashedPassword(user, hash, password);

        result.ShouldBeTrue("should verify correct password");
    }

    [Fact]
    public void VerifyHashedPassword_ReturnsFalse_ForInvalidPassword()
    {
        var user = CreateUser();
        var hash = _hasher.HashPassword(user, "Test123!");

        var result = _hasher.VerifyHashedPassword(user, hash, "WrongPassword!");

        result.ShouldBeFalse("should reject incorrect password");
    }

    [Fact]
    public void HashPassword_ThrowsException_WhenUserIsNull()
    {
        Should.Throw<ArgumentNullException>(() => _hasher.HashPassword(null!, "Test123!"));
    }

    [Fact]
    public void HashPassword_ThrowsException_WhenPasswordIsNullOrEmpty()
    {
        var user = CreateUser();

        Should.Throw<ArgumentException>(() => _hasher.HashPassword(user, null!));
        Should.Throw<ArgumentException>(() => _hasher.HashPassword(user, ""));
        Should.Throw<ArgumentException>(() => _hasher.HashPassword(user, "   "));
    }

    [Fact]
    public void VerifyHashedPassword_ThrowsException_WhenArgumentsInvalid()
    {
        var user = CreateUser();
        var hash = _hasher.HashPassword(user, "Test123!");

        Should.Throw<ArgumentNullException>(() => _hasher.VerifyHashedPassword(null!, hash, "Test123!"));

        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(user, null!, "Test123!"));
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(user, "", "Test123!"));
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(user, "   ", "Test123!"));

        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(user, hash, null!));
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(user, hash, ""));
        Should.Throw<ArgumentException>(() => _hasher.VerifyHashedPassword(user, hash, "   "));
    }
}
