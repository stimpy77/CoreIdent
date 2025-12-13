using CoreIdent.Core.Services;
using Shouldly;

namespace CoreIdent.Core.Tests.Services;

public class DefaultClientSecretHasherTests
{
    private readonly DefaultClientSecretHasher _hasher = new();

    [Fact]
    public void HashSecret_ReturnsNonEmptyString()
    {
        var hash = _hasher.HashSecret("test-secret");

        hash.ShouldNotBeNullOrWhiteSpace("hash should not be empty");
    }

    [Fact]
    public void HashSecret_ReturnsDifferentHashesForSameSecret()
    {
        var hash1 = _hasher.HashSecret("test-secret");
        var hash2 = _hasher.HashSecret("test-secret");

        hash1.ShouldNotBe(hash2, "hashes should be different due to random salt");
    }

    [Fact]
    public void VerifySecret_ReturnsTrue_ForCorrectSecret()
    {
        const string secret = "my-super-secret";
        var hash = _hasher.HashSecret(secret);

        var result = _hasher.VerifySecret(secret, hash);

        result.ShouldBeTrue("should verify correct secret");
    }

    [Fact]
    public void VerifySecret_ReturnsFalse_ForIncorrectSecret()
    {
        const string secret = "my-super-secret";
        var hash = _hasher.HashSecret(secret);

        var result = _hasher.VerifySecret("wrong-secret", hash);

        result.ShouldBeFalse("should reject incorrect secret");
    }

    [Fact]
    public void VerifySecret_ReturnsFalse_ForEmptySecret()
    {
        var hash = _hasher.HashSecret("test-secret");

        var result = _hasher.VerifySecret("", hash);

        result.ShouldBeFalse("should reject empty secret");
    }

    [Fact]
    public void VerifySecret_ReturnsFalse_ForEmptyHash()
    {
        var result = _hasher.VerifySecret("test-secret", "");

        result.ShouldBeFalse("should reject empty hash");
    }

    [Fact]
    public void VerifySecret_ReturnsFalse_ForInvalidHash()
    {
        var result = _hasher.VerifySecret("test-secret", "not-a-valid-base64-hash!");

        result.ShouldBeFalse("should reject invalid hash format");
    }

    [Fact]
    public void VerifySecret_ReturnsFalse_ForTruncatedHash()
    {
        var hash = _hasher.HashSecret("test-secret");
        var truncatedHash = hash[..10];

        var result = _hasher.VerifySecret("test-secret", truncatedHash);

        result.ShouldBeFalse("should reject truncated hash");
    }

    [Fact]
    public void HashSecret_ThrowsForNullOrWhitespace()
    {
        Should.Throw<ArgumentException>(() => _hasher.HashSecret(null!));
        Should.Throw<ArgumentException>(() => _hasher.HashSecret(""));
        Should.Throw<ArgumentException>(() => _hasher.HashSecret("   "));
    }
}
