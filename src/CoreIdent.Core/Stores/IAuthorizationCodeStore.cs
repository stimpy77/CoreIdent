using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Persists authorization codes issued for the OAuth 2.0 authorization code flow.
/// </summary>
public interface IAuthorizationCodeStore
{
    /// <summary>
    /// Creates and stores an authorization code.
    /// </summary>
    /// <param name="code">The authorization code to store.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CreateAsync(CoreIdentAuthorizationCode code, CancellationToken ct = default);

    /// <summary>
    /// Retrieves an authorization code by its handle.
    /// </summary>
    /// <param name="handle">The authorization code handle.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The authorization code, or <see langword="null"/> if not found.</returns>
    Task<CoreIdentAuthorizationCode?> GetAsync(string handle, CancellationToken ct = default);

    /// <summary>
    /// Marks an authorization code as consumed.
    /// </summary>
    /// <param name="handle">The authorization code handle.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns><see langword="true"/> if the code was consumed; otherwise <see langword="false"/>.</returns>
    Task<bool> ConsumeAsync(string handle, CancellationToken ct = default);

    /// <summary>
    /// Removes expired authorization codes.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(CancellationToken ct = default);
}
