using CoreIdent.Core.Models;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

/// <summary>
/// An in-memory implementation of IUserStore for testing or simple scenarios.
/// Note: This implementation is thread-safe.
/// </summary>
public class InMemoryUserStore : IUserStore
{
    // Use ConcurrentDictionary for thread safety
    private readonly ConcurrentDictionary<string, CoreIdentUser> _usersById = new();
    private readonly ConcurrentDictionary<string, string> _usersByNormalizedUsername = new(StringComparer.OrdinalIgnoreCase); // Case-insensitive username lookup

    /// <inheritdoc />
    public Task<StoreResult> CreateUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        var normalizedUsername = user.UserName?.ToUpperInvariant(); // Use normalized for lookup
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            // Or handle normalization elsewhere if needed
            return Task.FromResult(StoreResult.Failure); // Username is required
        }

        // Attempt to add username first (atomic check and add)
        if (!_usersByNormalizedUsername.TryAdd(normalizedUsername, user.Id))
        {
            return Task.FromResult(StoreResult.Conflict); // Username already exists
        }

        // If username added successfully, try adding the user by ID
        if (!_usersById.TryAdd(user.Id, user))
        {
            // This should ideally not happen if IDs are unique and username was added,
            // but handle potential race condition or logic error by removing the username entry.
            _usersByNormalizedUsername.TryRemove(normalizedUsername, out _);
            return Task.FromResult(StoreResult.Conflict); // ID already exists (unexpected)
        }

        return Task.FromResult(StoreResult.Success);
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindUserByIdAsync(string userId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userId);
        cancellationToken.ThrowIfCancellationRequested();

        _usersById.TryGetValue(userId, out var user);
        // Return a copy to prevent external modification of the stored object (optional, depends on desired behavior)
        // For simplicity here, we return the direct reference. Consider cloning if mutation is a concern.
        return Task.FromResult(user);
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindUserByUsernameAsync(string normalizedUsername, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(normalizedUsername);
        cancellationToken.ThrowIfCancellationRequested();

        if (_usersByNormalizedUsername.TryGetValue(normalizedUsername, out var userId))
        {
            _usersById.TryGetValue(userId, out var user);
            return Task.FromResult(user); // Return direct reference or clone
        }

        return Task.FromResult<CoreIdentUser?>(null);
    }

    /// <inheritdoc />
    public Task<StoreResult> UpdateUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        // Check if user exists by ID
        if (!_usersById.ContainsKey(user.Id))
        {
            return Task.FromResult(StoreResult.Failure); // User not found
        }

        // Update the user object in the dictionary.
        // ConcurrentDictionary's indexer handles the update atomically.
        _usersById[user.Id] = user;

        // Note: This simple implementation doesn't handle username changes.
        // If username could change, we'd need to update _usersByNormalizedUsername too,
        // which adds complexity (e.g., removing old, adding new, handling conflicts).
        // For now, assume username is immutable or handled at a higher layer.

        return Task.FromResult(StoreResult.Success);
    }

    /// <inheritdoc />
    public Task<StoreResult> DeleteUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        // Try removing by ID first
        if (!_usersById.TryRemove(user.Id, out var removedUser))
        {
            return Task.FromResult(StoreResult.Failure); // User not found by ID
        }

        // If removed by ID, also remove the username lookup entry
        var normalizedUsername = removedUser.UserName?.ToUpperInvariant();
        if (!string.IsNullOrWhiteSpace(normalizedUsername))
        {
            _usersByNormalizedUsername.TryRemove(normalizedUsername, out _);
            // We don't necessarily care if the username removal succeeds, the primary removal was by ID.
        }

        return Task.FromResult(StoreResult.Success);
    }
}
