using CoreIdent.Core.Models;
using System.Threading;
using System.Threading.Tasks;

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
}

// Simple result enum for store operations initially. Can be expanded later.
public enum StoreResult
{
    Success,
    Conflict, // e.g., Username already exists
    Failure
}
