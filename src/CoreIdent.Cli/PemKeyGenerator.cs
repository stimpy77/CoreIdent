using System.Security.Cryptography;

namespace CoreIdent.Cli;

public sealed record PemKeyPair(string PrivateKeyPem, string PublicKeyPem);

public static class PemKeyGenerator
{
    public static PemKeyPair GenerateRsa(int keySize)
    {
        using var rsa = RSA.Create(keySize);

        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        var privatePem = PemEncoding.WriteString("PRIVATE KEY", privateKey);
        var publicPem = PemEncoding.WriteString("PUBLIC KEY", publicKey);

        return new PemKeyPair(privatePem, publicPem);
    }

    public static PemKeyPair GenerateEcdsaP256()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var privatePem = PemEncoding.WriteString("PRIVATE KEY", privateKey);
        var publicPem = PemEncoding.WriteString("PUBLIC KEY", publicKey);

        return new PemKeyPair(privatePem, publicPem);
    }
}
