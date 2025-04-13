using CoreIdent.Core.Models;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Provides an abstraction for storing, retrieving, and managing refresh tokens.
/// </summary>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Stores a new refresh token.
    /// </summary>
    /// <param name="token">The refresh token to store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task StoreRefreshTokenAsync(CoreIdentRefreshToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a refresh token by its handle.
    /// </summary>
    /// <param name="tokenHandle">The handle of the refresh token to retrieve.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the <see cref="CoreIdentRefreshToken"/> if found, otherwise null.</returns>
    Task<CoreIdentRefreshToken?> GetRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken);

    /// <summary>
    /// Removes (or marks as consumed) a refresh token by its handle.
    /// The implementation decides whether to physically remove or mark as consumed (e.g., for replay detection).
    /// </summary>
    /// <param name="tokenHandle">The handle of the refresh token to remove or consume.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task RemoveRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken);

    // Optional: Add methods to find tokens by SubjectId or ClientId if needed for revocation scenarios.
    // Task<IEnumerable<CoreIdentRefreshToken>> FindTokensBySubjectIdAsync(string subjectId, CancellationToken cancellationToken);
    // Task RemoveTokensBySubjectIdAsync(string subjectId, CancellationToken cancellationToken);
} 