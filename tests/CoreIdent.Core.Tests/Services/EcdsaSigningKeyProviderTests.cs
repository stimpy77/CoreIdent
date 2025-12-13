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

public class EcdsaSigningKeyProviderTests : IDisposable
{
    private readonly string _tempDir;

    public EcdsaSigningKeyProviderTests()
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
        var provider = CreateProvider(new CoreIdentKeyOptions());

        // Act
        var credentials = await provider.GetSigningCredentialsAsync();

        // Assert
        credentials.ShouldNotBeNull("Should return signing credentials.");
        credentials.Algorithm.ShouldBe(SecurityAlgorithms.EcdsaSha256, "Algorithm should be ES256.");
        credentials.Key.ShouldBeOfType<ECDsaSecurityKey>("Key should be ECDSA.");
        credentials.Key.KeyId.ShouldNotBeNullOrWhiteSpace("Key ID should be set.");
    }

    [Fact]
    public async Task GetSigningCredentialsAsync_loads_key_from_pem_string()
    {
        // Arrange
        var (pemPrivate, _) = GenerateEcdsaKeyPair();
        var options = new CoreIdentKeyOptions { PrivateKeyPem = pemPrivate };
        var provider = CreateProvider(options);

        // Act
        var credentials = await provider.GetSigningCredentialsAsync();

        // Assert
        credentials.ShouldNotBeNull("Should return signing credentials from PEM string.");
        credentials.Algorithm.ShouldBe(SecurityAlgorithms.EcdsaSha256, "Algorithm should be ES256.");
    }

    [Fact]
    public async Task GetSigningCredentialsAsync_loads_key_from_pem_file()
    {
        // Arrange
        var (pemPrivate, _) = GenerateEcdsaKeyPair();
        var pemPath = Path.Combine(_tempDir, "test-key.pem");
        await File.WriteAllTextAsync(pemPath, pemPrivate);

        var options = new CoreIdentKeyOptions { PrivateKeyPath = pemPath };
        var provider = CreateProvider(options);

        // Act
        var credentials = await provider.GetSigningCredentialsAsync();

        // Assert
        credentials.ShouldNotBeNull("Should return signing credentials from PEM file.");
        credentials.Algorithm.ShouldBe(SecurityAlgorithms.EcdsaSha256, "Algorithm should be ES256.");
    }

    [Fact]
    public async Task GetValidationKeysAsync_returns_public_key_only()
    {
        // Arrange
        var provider = CreateProvider(new CoreIdentKeyOptions());

        // Act
        var keys = (await provider.GetValidationKeysAsync()).ToList();

        // Assert
        keys.ShouldHaveSingleItem("Should return exactly one validation key.");
        var keyInfo = keys[0];
        keyInfo.KeyId.ShouldNotBeNullOrWhiteSpace("Key ID should be set.");
        keyInfo.Key.ShouldBeOfType<ECDsaSecurityKey>("Key should be ECDSA.");

        var ecdsaKey = (ECDsaSecurityKey)keyInfo.Key;
        // ECDSA keys may report Unknown for public-only keys; verify we can't export private params
        ecdsaKey.PrivateKeyStatus.ShouldNotBe(PrivateKeyStatus.Exists, "Validation key should not contain private key.");
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
    public async Task Algorithm_returns_ES256()
    {
        // Arrange
        var provider = CreateProvider(new CoreIdentKeyOptions());

        // Assert
        provider.Algorithm.ShouldBe(SecurityAlgorithms.EcdsaSha256, "Algorithm property should return ES256.");
    }

    [Fact]
    public async Task Generated_key_can_sign_and_verify()
    {
        // Arrange
        var provider = CreateProvider(new CoreIdentKeyOptions());
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
        result.IsValid.ShouldBeTrue("Token signed with generated ECDSA key should be valid.");
    }

    private static EcdsaSigningKeyProvider CreateProvider(CoreIdentKeyOptions options)
    {
        var optionsWrapper = Options.Create(options);
        var logger = NullLogger<EcdsaSigningKeyProvider>.Instance;
        return new EcdsaSigningKeyProvider(optionsWrapper, logger);
    }

    private static (string PrivatePem, string PublicPem) GenerateEcdsaKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePem = ecdsa.ExportECPrivateKeyPem();
        var publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();
        return (privatePem, publicPem);
    }
}
