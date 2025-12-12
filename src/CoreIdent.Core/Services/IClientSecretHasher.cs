namespace CoreIdent.Core.Services;

/// <summary>
/// Service for hashing and verifying client secrets.
/// </summary>
public interface IClientSecretHasher
{
    /// <summary>
    /// Hashes a client secret for storage.
    /// </summary>
    string HashSecret(string secret);

    /// <summary>
    /// Verifies a client secret against a stored hash.
    /// </summary>
    bool VerifySecret(string secret, string hash);
}
