using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware refresh token store for managing OAuth refresh tokens.
/// </summary>
public interface IRealmRefreshTokenStore
{
    /// <summary>
    /// Stores a refresh token within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="token">The refresh token to store.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The handle of the stored token.</returns>
    Task<string> StoreAsync(string realmId, CoreIdentRefreshToken token, CancellationToken ct = default);
    
    /// <summary>
    /// Retrieves a refresh token by handle within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="handle">The token handle to retrieve.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The refresh token if found, otherwise null.</returns>
    Task<CoreIdentRefreshToken?> GetAsync(string realmId, string handle, CancellationToken ct = default);
    
    /// <summary>
    /// Revokes a refresh token by handle within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="handle">The token handle to revoke.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>True if token was revoked, otherwise false.</returns>
    Task<bool> RevokeAsync(string realmId, string handle, CancellationToken ct = default);
    
    /// <summary>
    /// Revokes all tokens in the same family within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="familyId">The family ID to revoke.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RevokeFamilyAsync(string realmId, string familyId, CancellationToken ct = default);
    
    /// <summary>
    /// Consumes a refresh token by handle within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="handle">The token handle to consume.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>True if token was consumed, otherwise false.</returns>
    Task<bool> ConsumeAsync(string realmId, string handle, CancellationToken ct = default);
    
    /// <summary>
    /// Cleans up expired refresh tokens within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
