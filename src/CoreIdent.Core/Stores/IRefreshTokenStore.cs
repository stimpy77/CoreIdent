using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Persists and manages refresh tokens.
/// </summary>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Stores a refresh token and returns a handle that can be used to retrieve it.
    /// </summary>
    /// <param name="token">The refresh token to store.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The token handle.</returns>
    Task<string> StoreAsync(CoreIdentRefreshToken token, CancellationToken ct = default);

    /// <summary>
    /// Retrieves a refresh token by its handle.
    /// </summary>
    /// <param name="handle">The refresh token handle.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The refresh token, or <see langword="null"/> if not found.</returns>
    Task<CoreIdentRefreshToken?> GetAsync(string handle, CancellationToken ct = default);

    /// <summary>
    /// Revokes a refresh token by its handle.
    /// </summary>
    /// <param name="handle">The refresh token handle.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns><see langword="true"/> if a token was revoked; otherwise <see langword="false"/>.</returns>
    Task<bool> RevokeAsync(string handle, CancellationToken ct = default);

    /// <summary>
    /// Revokes all refresh tokens that belong to the same token family.
    /// </summary>
    /// <param name="familyId">The token family identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RevokeFamilyAsync(string familyId, CancellationToken ct = default);

    /// <summary>
    /// Marks a refresh token as consumed (used) by its handle.
    /// </summary>
    /// <param name="handle">The refresh token handle.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns><see langword="true"/> if the token was consumed; otherwise <see langword="false"/>.</returns>
    Task<bool> ConsumeAsync(string handle, CancellationToken ct = default);

    /// <summary>
    /// Removes expired refresh tokens.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(CancellationToken ct = default);
}
