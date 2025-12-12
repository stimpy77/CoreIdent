namespace CoreIdent.Core.Configuration;

public class CoreIdentKeyOptions
{
    public KeyType Type { get; set; } = KeyType.RSA;
    public int RsaKeySize { get; set; } = 2048;
    public string? PrivateKeyPem { get; set; }
    public string? PrivateKeyPath { get; set; }
    public string? CertificatePath { get; set; }
    public string? CertificatePassword { get; set; }
    public string? SymmetricKey { get; set; }
}

public enum KeyType
{
    RSA,
    ECDSA,
    Symmetric
}
