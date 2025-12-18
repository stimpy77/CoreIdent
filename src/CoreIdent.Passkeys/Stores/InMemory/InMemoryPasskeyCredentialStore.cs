using System.Collections.Concurrent;
using CoreIdent.Passkeys.Models;

namespace CoreIdent.Passkeys.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IPasskeyCredentialStore"/> intended for development and testing.
/// </summary>
public sealed class InMemoryPasskeyCredentialStore : IPasskeyCredentialStore
{
    private readonly ConcurrentDictionary<string, PasskeyCredential> _byKey = new(StringComparer.Ordinal);

    /// <summary>
    /// Retrieves a list of passkey credentials associated with the specified user ID.
    /// </summary>
    /// <param name="userId">The user ID to retrieve credentials for.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation, containing a list of passkey credentials.</returns>
    public Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var results = _byKey.Values.Where(x => string.Equals(x.UserId, userId, StringComparison.Ordinal)).ToList();
        return Task.FromResult<IReadOnlyList<PasskeyCredential>>(results);
    }

    /// <summary>
    /// Retrieves a passkey credential by its credential ID.
    /// </summary>
    /// <param name="credentialId">The credential ID to retrieve.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation, containing the passkey credential or null if not found.</returns>
    public Task<PasskeyCredential?> GetByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var key = Convert.ToBase64String(credentialId);
        _byKey.TryGetValue(key, out var value);
        return Task.FromResult(value);
    }

    /// <summary>
    /// Upserts a passkey credential in the store.
    /// </summary>
    /// <param name="credential">The passkey credential to upsert.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public Task UpsertAsync(PasskeyCredential credential, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var key = Convert.ToBase64String(credential.CredentialId);
        _byKey[key] = credential;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Deletes a passkey credential from the store.
    /// </summary>
    /// <param name="userId">The user ID associated with the credential.</param>
    /// <param name="credentialId">The credential ID to delete.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public Task DeleteAsync(string userId, byte[] credentialId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(credentialId);

        var key = Convert.ToBase64String(credentialId);
        _byKey.TryRemove(key, out _);

        return Task.CompletedTask;
    }
}
