namespace CoreIdent.Core.Configuration;

/// <summary>
/// Options that control signing key selection and loading.
/// </summary>
public class CoreIdentKeyOptions
{
    /// <summary>
    /// Selected key type.
    /// </summary>
    public KeyType Type { get; set; } = KeyType.RSA;

    /// <summary>
    /// RSA key size in bits.
    /// </summary>
    public int RsaKeySize { get; set; } = 2048;

    /// <summary>
    /// PEM-encoded private key.
    /// </summary>
    public string? PrivateKeyPem { get; set; }

    /// <summary>
    /// Path to a PEM-encoded private key file.
    /// </summary>
    public string? PrivateKeyPath { get; set; }

    /// <summary>
    /// Optional path to an X.509 certificate file.
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>
    /// Optional certificate password.
    /// </summary>
    public string? CertificatePassword { get; set; }

    /// <summary>
    /// Symmetric key material used for HMAC signing.
    /// </summary>
    public string? SymmetricKey { get; set; }
}

/// <summary>
/// Supported signing key types.
/// </summary>
public enum KeyType
{
    /// <summary>
    /// RSA signing.
    /// </summary>
    RSA,

    /// <summary>
    /// ECDSA signing.
    /// </summary>
    ECDSA,

    /// <summary>
    /// Symmetric (HMAC) signing.
    /// </summary>
    Symmetric
}
