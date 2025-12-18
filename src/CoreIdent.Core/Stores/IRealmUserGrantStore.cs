using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware user grant store for managing user consent grants.
/// </summary>
public interface IRealmUserGrantStore
{
    /// <summary>
    /// Finds a user grant within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="subjectId">The subject (user) identifier.</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The user grant if found, otherwise null.</returns>
    Task<CoreIdentUserGrant?> FindAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Saves a user grant within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="grant">The user grant to save.</param>
    /// <param name="ct">The cancellation token.</param>
    Task SaveAsync(string realmId, CoreIdentUserGrant grant, CancellationToken ct = default);

    /// <summary>
    /// Revokes a user grant within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="subjectId">The subject (user) identifier.</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RevokeAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Checks if a user has granted consent for specific scopes within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="subjectId">The subject (user) identifier.</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="scopes">The scopes to check consent for.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>True if user has granted consent for all scopes, otherwise false.</returns>
    Task<bool> HasUserGrantedConsentAsync(string realmId, string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default);
}
