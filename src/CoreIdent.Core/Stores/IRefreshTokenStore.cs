using CoreIdent.Core.Models;
using System.Collections.Generic;
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

    /// <summary>
    /// Revokes all tokens belonging to a specific family, used for token theft detection.
    /// This marks all tokens in the family as consumed.
    /// </summary>
    /// <param name="familyId">The family identifier to revoke.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task RevokeTokenFamilyAsync(string familyId, CancellationToken cancellationToken);
    
    /// <summary>
    /// Find tokens associated with a specific user.
    /// </summary>
    /// <param name="subjectId">The subject ID (user ID) to find tokens for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the collection of refresh tokens.</returns>
    Task<IEnumerable<CoreIdentRefreshToken>> FindTokensBySubjectIdAsync(string subjectId, CancellationToken cancellationToken);
    
    // Optional: Add method to remove tokens for a user if needed
    // Task RemoveTokensBySubjectIdAsync(string subjectId, CancellationToken cancellationToken);
} 