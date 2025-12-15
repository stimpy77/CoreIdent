using System.Security.Cryptography;
using CoreIdent.Cli;
using Shouldly;

namespace CoreIdent.Cli.Tests;

public sealed class PemKeyGeneratorTests
{
    [Fact]
    public void GenerateRsa_CreatesImportablePemKeys()
    {
        var pair = PemKeyGenerator.GenerateRsa(2048);

        pair.PrivateKeyPem.ShouldNotBeNullOrWhiteSpace("Private key PEM should be generated");
        pair.PublicKeyPem.ShouldNotBeNullOrWhiteSpace("Public key PEM should be generated");

        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(pair.PrivateKeyPem);

        using var rsaPublic = RSA.Create();
        rsaPublic.ImportFromPem(pair.PublicKeyPem);

        var data = RandomNumberGenerator.GetBytes(32);
        var signature = rsaPrivate.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsaPublic.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .ShouldBeTrue("Public key should verify a signature created with the private key");
    }

    [Fact]
    public void GenerateEcdsaP256_CreatesImportablePemKeys()
    {
        var pair = PemKeyGenerator.GenerateEcdsaP256();

        pair.PrivateKeyPem.ShouldNotBeNullOrWhiteSpace("Private key PEM should be generated");
        pair.PublicKeyPem.ShouldNotBeNullOrWhiteSpace("Public key PEM should be generated");

        using var ecdsaPrivate = ECDsa.Create();
        ecdsaPrivate.ImportFromPem(pair.PrivateKeyPem);

        using var ecdsaPublic = ECDsa.Create();
        ecdsaPublic.ImportFromPem(pair.PublicKeyPem);

        var data = RandomNumberGenerator.GetBytes(32);
        var signature = ecdsaPrivate.SignData(data, HashAlgorithmName.SHA256);
        ecdsaPublic.VerifyData(data, signature, HashAlgorithmName.SHA256)
            .ShouldBeTrue("Public key should verify a signature created with the private key");
    }
}
