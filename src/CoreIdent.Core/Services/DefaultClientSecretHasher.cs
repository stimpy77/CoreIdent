using System.Security.Cryptography;

namespace CoreIdent.Core.Services;

/// <summary>
/// Default implementation of <see cref="IClientSecretHasher"/> using PBKDF2.
/// </summary>
public sealed class DefaultClientSecretHasher : IClientSecretHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 100_000;
    private static readonly HashAlgorithmName Algorithm = HashAlgorithmName.SHA256;

    /// <inheritdoc />
    public string HashSecret(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, Algorithm, HashSize);

        var result = new byte[SaltSize + HashSize];
        salt.CopyTo(result, 0);
        hash.CopyTo(result, SaltSize);

        return Convert.ToBase64String(result);
    }

    /// <inheritdoc />
    public bool VerifySecret(string secret, string hash)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(hash))
        {
            return false;
        }

        try
        {
            var hashBytes = Convert.FromBase64String(hash);
            if (hashBytes.Length != SaltSize + HashSize)
            {
                return false;
            }

            var salt = hashBytes[..SaltSize];
            var storedHash = hashBytes[SaltSize..];

            var computedHash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, Algorithm, HashSize);

            return CryptographicOperations.FixedTimeEquals(storedHash, computedHash);
        }
        catch
        {
            return false;
        }
    }
}
