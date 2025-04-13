using CoreIdent.Core.Models;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Provides an abstraction for storing and retrieving user information.
/// Phase 1 focuses on basic creation and retrieval.
/// </summary>
public interface IUserStore
{
    /// <summary>
    /// Creates a new user in the store.
    /// </summary>
    /// <param name="user">The user object to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing an operation result (e.g., success, failure, conflict).</returns>
    Task<StoreResult> CreateUserAsync(CoreIdentUser user, CancellationToken cancellationToken); // Consider returning a result object

    /// <summary>
    /// Finds a user by their unique ID.
    /// </summary>
    /// <param name="userId">The ID of the user to find.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the user if found, otherwise null.</returns>
    Task<CoreIdentUser?> FindUserByIdAsync(string userId, CancellationToken cancellationToken);

    /// <summary>
    /// Finds a user by their username (which is often the email).
    /// </summary>
    /// <param name="normalizedUserName">The normalized username to search for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the user if found, otherwise null.</returns>
    Task<CoreIdentUser?> FindUserByUsernameAsync(string normalizedUserName, CancellationToken cancellationToken);

    /// <summary>
    /// Updates the specified user in the store.
    /// </summary>
    /// <param name="user">The user to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the <see cref="StoreResult"/> for the update.</returns>
    Task<StoreResult> UpdateUserAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes the specified user from the store.
    /// </summary>
    /// <param name="user">The user to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the <see cref="StoreResult"/> for the deletion.</returns>
    Task<StoreResult> DeleteUserAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the normalized user name for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose normalized name should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the normalized user name for the specified <paramref name="user"/>.</returns>
    Task<string?> GetNormalizedUserNameAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the normalized user name for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose normalized name should be set.</param>
    /// <param name="normalizedName">The normalized name to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task SetNormalizedUserNameAsync(CoreIdentUser user, string? normalizedName, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the password hash for a user.
    /// </summary>
    /// <param name="user">The user to set the password hash for.</param>
    /// <param name="passwordHash">The password hash to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task SetPasswordHashAsync(CoreIdentUser user, string? passwordHash, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the password hash for a user.
    /// </summary>
    /// <param name="user">The user to retrieve the password hash for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, returning the password hash.</returns>
    Task<string?> GetPasswordHashAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Returns a flag indicating if the specified user has a password set.
    /// </summary>
    /// <param name="user">The user to check.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, returning true if the user has a password set, otherwise false.</returns>
    Task<bool> HasPasswordAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Get the claims associated with the specified <paramref name="user"/> as an asynchronous operation.
    /// </summary>
    /// <param name="user">The user whose claims should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, returning the list of <see cref="Claim"/>s.</returns>
    Task<IList<Claim>> GetClaimsAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Adds the <paramref name="claims"/> given to the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to add the claim to.</param>
    /// <param name="claims">The claims to add.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task AddClaimsAsync(CoreIdentUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the <paramref name="claim"/> on the specified <paramref name="user"/>, with the <paramref name="newClaim"/>.
    /// </summary>
    /// <param name="user">The user to replace the claim on.</param>
    /// <param name="claim">The claim to replace.</param>
    /// <param name="newClaim">The new claim replacing the <paramref name="claim"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task ReplaceClaimAsync(CoreIdentUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the <paramref name="claims"/> given from the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to remove the claims from.</param>
    /// <param name="claims">The claims to remove.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task RemoveClaimsAsync(CoreIdentUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all users with the specified claim.
    /// </summary>
    /// <param name="claim">The claim whose users should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, returning a list of users who possess the claim.</returns>
    Task<IList<CoreIdentUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the current failed access count for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose failed access count should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, returning the failed access count.</returns>
    Task<int> GetAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a flag indicating whether user lockout is enabled for the specified user.
    /// </summary>
    /// <param name="user">The user whose ability to be locked out should be returned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, true if a user can be locked out, otherwise false.</returns>
    Task<bool> GetLockoutEnabledAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the last <see cref="DateTimeOffset"/> a user's lockout expired, if any.
    /// Any time in the past should be indicates a user is not locked out.
    /// </summary>
    /// <param name="user">The user whose lockout date should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the lockout date.</returns>
    Task<DateTimeOffset?> GetLockoutEndDateAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Records that a failed access has occurred, incrementing the failed access count.
    /// </summary>
    /// <param name="user">The user whose cancellation count should be incremented.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, returning the incremented failed access count.</returns>
    Task<int> IncrementAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Resets a user's failed access count.
    /// </summary>
    /// <param name="user">The user whose failed access count should be reset.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task ResetAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken);

    /// <summary>
    /// Locks out a user until the specified end date has passed.
    /// Setting a lockout end date in the past immediately unlocks a user.
    /// </summary>
    /// <param name="user">The user whose lockout date should be set.</param>
    /// <param name="lockoutEnd">The <see cref="DateTimeOffset"/> after which the <paramref name="user"/>'s lockout should end.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task SetLockoutEndDateAsync(CoreIdentUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken);

    /// <summary>
    /// Sets a flag indicating whether the specified <paramref name="user"/> can be locked out.
    /// </summary>
    /// <param name="user">The user whose ability to be locked out should be set.</param>
    /// <param name="enabled">A flag indicating if the user can be locked out, true if the user can be locked out, otherwise false.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task SetLockoutEnabledAsync(CoreIdentUser user, bool enabled, CancellationToken cancellationToken);
}

// Simple result enum for store operations initially. Can be expanded later.
public enum StoreResult
{
    Success,
    Conflict, // e.g., Username already exists
    Failure
}
