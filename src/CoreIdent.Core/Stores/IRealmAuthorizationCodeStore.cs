using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware authorization code store for managing OAuth authorization codes.
/// </summary>
public interface IRealmAuthorizationCodeStore
{
    /// <summary>
    /// Creates an authorization code within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="code">The authorization code to create.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CreateAsync(string realmId, CoreIdentAuthorizationCode code, CancellationToken ct = default);

    /// <summary>
    /// Retrieves an authorization code by handle within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="handle">The authorization code handle to retrieve.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The authorization code if found, otherwise null.</returns>
    Task<CoreIdentAuthorizationCode?> GetAsync(string realmId, string handle, CancellationToken ct = default);

    /// <summary>
    /// Consumes an authorization code by handle within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="handle">The authorization code handle to consume.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>True if the code was consumed, otherwise false.</returns>
    Task<bool> ConsumeAsync(string realmId, string handle, CancellationToken ct = default);

    /// <summary>
    /// Cleans up expired authorization codes within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
