namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware token revocation store for managing revoked tokens.
/// </summary>
public interface IRealmTokenRevocationStore
{
    /// <summary>
    /// Revokes a token within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="jti">The JWT ID of the token to revoke.</param>
    /// <param name="tokenType">The type of token being revoked.</param>
    /// <param name="expiry">The expiry time of the token.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RevokeTokenAsync(string realmId, string jti, string tokenType, DateTime expiry, CancellationToken ct = default);
    
    /// <summary>
    /// Checks if a token is revoked within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="jti">The JWT ID of the token to check.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>True if the token is revoked, otherwise false.</returns>
    Task<bool> IsRevokedAsync(string realmId, string jti, CancellationToken ct = default);
    
    /// <summary>
    /// Cleans up expired revoked tokens within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
