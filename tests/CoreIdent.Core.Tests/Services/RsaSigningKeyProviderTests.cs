using System.Security.Cryptography;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class RsaSigningKeyProviderTests : IDisposable
{
    private readonly string _tempDir;

    public RsaSigningKeyProviderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"coreident-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task GetSigningCredentialsAsync_generates_key_when_none_configured()
    {
        // Arrange
        var provider = CreateProvider(new CoreIdentKeyOptions { RsaKeySize = 2048 });

        // Act
        var credentials = await provider.GetSigningCredentialsAsync();

        // Assert
        credentials.ShouldNotBeNull("Should return signing credentials.");
        credentials.Algorithm.ShouldBe(SecurityAlgorithms.RsaSha256, "Algorithm should be RS256.");
        credentials.Key.ShouldBeOfType<RsaSecurityKey>("Key should be RSA.");
        credentials.Key.KeyId.ShouldNotBeNullOrWhiteSpace("Key ID should be set.");
    }

    [Fact]
    public async Task GetSigningCredentialsAsync_loads_key_from_pem_string()
    {
        // Arrange
        var (pemPrivate, _) = GenerateRsaKeyPair();
        var options = new CoreIdentKeyOptions { PrivateKeyPem = pemPrivate };
        var provider = CreateProvider(options);

        // Act
        var credentials = await provider.GetSigningCredentialsAsync();

        // Assert
        credentials.ShouldNotBeNull("Should return signing credentials from PEM string.");
        credentials.Algorithm.ShouldBe(SecurityAlgorithms.RsaSha256, "Algorithm should be RS256.");
    }

    [Fact]
    public async Task GetSigningCredentialsAsync_loads_key_from_pem_file()
    {
        // Arrange
        var (pemPrivate, _) = GenerateRsaKeyPair();
        var pemPath = Path.Combine(_tempDir, "test-key.pem");
        await File.WriteAllTextAsync(pemPath, pemPrivate);

        var options = new CoreIdentKeyOptions { PrivateKeyPath = pemPath };
        var provider = CreateProvider(options);

        // Act
        var credentials = await provider.GetSigningCredentialsAsync();

        // Assert
        credentials.ShouldNotBeNull("Should return signing credentials from PEM file.");
        credentials.Algorithm.ShouldBe(SecurityAlgorithms.RsaSha256, "Algorithm should be RS256.");
    }

    [Fact]
    public async Task GetValidationKeysAsync_returns_public_key_only()
    {
        // Arrange
        var provider = CreateProvider(new CoreIdentKeyOptions { RsaKeySize = 2048 });

        // Act
        var keys = (await provider.GetValidationKeysAsync()).ToList();

        // Assert
        keys.ShouldHaveSingleItem("Should return exactly one validation key.");
        var keyInfo = keys[0];
        keyInfo.KeyId.ShouldNotBeNullOrWhiteSpace("Key ID should be set.");
        keyInfo.Key.ShouldBeOfType<RsaSecurityKey>("Key should be RSA.");

        var rsaKey = (RsaSecurityKey)keyInfo.Key;
        rsaKey.PrivateKeyStatus.ShouldBe(PrivateKeyStatus.DoesNotExist, "Validation key should not contain private key.");
    }

    [Fact]
    public async Task GetSigningCredentialsAsync_throws_when_pem_file_not_found()
    {
        // Arrange
        var options = new CoreIdentKeyOptions { PrivateKeyPath = "/nonexistent/path/key.pem" };
        var provider = CreateProvider(options);

        // Act & Assert
        await Should.ThrowAsync<FileNotFoundException>(
            async () => await provider.GetSigningCredentialsAsync(),
            "Should throw when PEM file not found.");
    }

    [Fact]
    public async Task Algorithm_returns_RS256()
    {
        // Arrange
        var provider = CreateProvider(new CoreIdentKeyOptions());

        // Assert
        provider.Algorithm.ShouldBe(SecurityAlgorithms.RsaSha256, "Algorithm property should return RS256.");
    }

    [Fact]
    public async Task Generated_key_can_sign_and_verify()
    {
        // Arrange
        var provider = CreateProvider(new CoreIdentKeyOptions { RsaKeySize = 2048 });
        var signingCredentials = await provider.GetSigningCredentialsAsync();
        var validationKeys = await provider.GetValidationKeysAsync();

        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = signingCredentials
        };

        // Act
        var token = handler.CreateToken(tokenDescriptor);
        var validationParams = new TokenValidationParameters
        {
            ValidIssuer = "test-issuer",
            ValidAudience = "test-audience",
            IssuerSigningKeys = validationKeys.Select(k => k.Key)
        };
        var result = await handler.ValidateTokenAsync(token, validationParams);

        // Assert
        result.IsValid.ShouldBeTrue("Token signed with generated key should be valid.");
    }

    private static RsaSigningKeyProvider CreateProvider(CoreIdentKeyOptions options)
    {
        var optionsWrapper = Options.Create(options);
        var logger = NullLogger<RsaSigningKeyProvider>.Instance;
        return new RsaSigningKeyProvider(optionsWrapper, logger);
    }

    private static (string PrivatePem, string PublicPem) GenerateRsaKeyPair()
    {
        using var rsa = RSA.Create(2048);
        var privatePem = rsa.ExportRSAPrivateKeyPem();
        var publicPem = rsa.ExportRSAPublicKeyPem();
        return (privatePem, publicPem);
    }
}
