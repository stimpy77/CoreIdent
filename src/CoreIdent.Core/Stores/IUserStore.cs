using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Provides access to users and their claims.
/// </summary>
public interface IUserStore
{
    /// <summary>
    /// Finds a user by its identifier.
    /// </summary>
    /// <param name="id">The user identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The user, or <see langword="null"/> if not found.</returns>
    Task<CoreIdentUser?> FindByIdAsync(string id, CancellationToken ct = default);

    /// <summary>
    /// Finds a user by its username.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The user, or <see langword="null"/> if not found.</returns>
    Task<CoreIdentUser?> FindByUsernameAsync(string username, CancellationToken ct = default);

    /// <summary>
    /// Creates a new user.
    /// </summary>
    /// <param name="user">The user to create.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CreateAsync(CoreIdentUser user, CancellationToken ct = default);

    /// <summary>
    /// Updates an existing user.
    /// </summary>
    /// <param name="user">The updated user.</param>
    /// <param name="ct">The cancellation token.</param>
    Task UpdateAsync(CoreIdentUser user, CancellationToken ct = default);

    /// <summary>
    /// Deletes a user by its identifier.
    /// </summary>
    /// <param name="id">The user identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task DeleteAsync(string id, CancellationToken ct = default);

    /// <summary>
    /// Gets claims for the specified subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier (user ID).</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The subject claims.</returns>
    Task<IReadOnlyList<Claim>> GetClaimsAsync(string subjectId, CancellationToken ct = default);

    /// <summary>
    /// Sets claims for the specified subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier (user ID).</param>
    /// <param name="claims">The claims to set.</param>
    /// <param name="ct">The cancellation token.</param>
    Task SetClaimsAsync(string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default);
}
