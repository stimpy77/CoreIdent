using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware user store for managing user accounts and claims.
/// </summary>
public interface IRealmUserStore
{
    /// <summary>
    /// Finds a user by ID within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="id">The user ID to find.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The user if found, otherwise null.</returns>
    Task<CoreIdentUser?> FindByIdAsync(string realmId, string id, CancellationToken ct = default);

    /// <summary>
    /// Finds a user by username within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="username">The username to find.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The user if found, otherwise null.</returns>
    Task<CoreIdentUser?> FindByUsernameAsync(string realmId, string username, CancellationToken ct = default);

    /// <summary>
    /// Creates a new user within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="user">The user to create.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CreateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default);

    /// <summary>
    /// Updates an existing user within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="user">The user to update.</param>
    /// <param name="ct">The cancellation token.</param>
    Task UpdateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default);

    /// <summary>
    /// Deletes a user by ID within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="id">The user ID to delete.</param>
    /// <param name="ct">The cancellation token.</param>
    Task DeleteAsync(string realmId, string id, CancellationToken ct = default);

    /// <summary>
    /// Gets all claims for a user within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="subjectId">The subject (user) identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The user's claims.</returns>
    Task<IReadOnlyList<Claim>> GetClaimsAsync(string realmId, string subjectId, CancellationToken ct = default);

    /// <summary>
    /// Sets claims for a user within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="subjectId">The subject (user) identifier.</param>
    /// <param name="claims">The claims to set.</param>
    /// <param name="ct">The cancellation token.</param>
    Task SetClaimsAsync(string realmId, string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default);
}
