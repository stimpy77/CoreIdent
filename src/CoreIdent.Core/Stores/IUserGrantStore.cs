using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Persists user consent/grants for clients and scopes.
/// </summary>
public interface IUserGrantStore
{
    /// <summary>
    /// Finds an existing grant for the given subject and client.
    /// </summary>
    /// <param name="subjectId">The subject identifier (user ID).</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The grant, or <see langword="null"/> if none exists.</returns>
    Task<CoreIdentUserGrant?> FindAsync(string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Saves a grant.
    /// </summary>
    /// <param name="grant">The grant to save.</param>
    /// <param name="ct">The cancellation token.</param>
    Task SaveAsync(CoreIdentUserGrant grant, CancellationToken ct = default);

    /// <summary>
    /// Revokes an existing grant for the given subject and client.
    /// </summary>
    /// <param name="subjectId">The subject identifier (user ID).</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RevokeAsync(string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Checks whether a user has granted consent for the requested scopes.
    /// </summary>
    /// <param name="subjectId">The subject identifier (user ID).</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="scopes">The requested scopes.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns><see langword="true"/> if consent exists; otherwise <see langword="false"/>.</returns>
    Task<bool> HasUserGrantedConsentAsync(string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default);
}
