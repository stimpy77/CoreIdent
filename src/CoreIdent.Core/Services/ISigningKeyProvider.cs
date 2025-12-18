using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Services;

/// <summary>
/// Provides signing credentials and validation keys for JWT issuance and validation.
/// </summary>
public interface ISigningKeyProvider
{
    /// <summary>
    /// Gets the signing credentials used to issue JWTs.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The signing credentials.</returns>
    Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default);

    /// <summary>
    /// Gets the set of public keys that should be used to validate issued tokens.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The validation keys.</returns>
    Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default);

    /// <summary>
    /// Gets the JWT signing algorithm identifier.
    /// </summary>
    string Algorithm { get; }
}

/// <summary>
/// Describes a security key used for token validation.
/// </summary>
public record SecurityKeyInfo
{
    /// <summary>
    /// The key identifier (kid).
    /// </summary>
    public string KeyId { get; init; }

    /// <summary>
    /// The security key.
    /// </summary>
    public SecurityKey Key { get; init; }

    /// <summary>
    /// The optional expiry time for the key.
    /// </summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>
    /// Creates a new <see cref="SecurityKeyInfo"/>.
    /// </summary>
    /// <param name="keyId">The key identifier (kid).</param>
    /// <param name="key">The security key.</param>
    /// <param name="expiresAt">The optional expiry time for the key.</param>
    public SecurityKeyInfo(string keyId, SecurityKey key, DateTime? expiresAt)
    {
        KeyId = keyId;
        Key = key;
        ExpiresAt = expiresAt;
    }
}
