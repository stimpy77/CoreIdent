using CoreIdent.Passkeys.Models;

namespace CoreIdent.Passkeys.Stores;

/// <summary>
/// Persistence abstraction for storing and retrieving passkey credentials.
/// </summary>
public interface IPasskeyCredentialStore
{
    /// <summary>
    /// Gets all passkey credentials associated with a user.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The user's passkey credentials.</returns>
    Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default);

    /// <summary>
    /// Gets a passkey credential by its credential identifier.
    /// </summary>
    /// <param name="credentialId">The raw credential identifier.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The credential, or <see langword="null"/> if not found.</returns>
    Task<PasskeyCredential?> GetByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default);

    /// <summary>
    /// Inserts or updates a passkey credential.
    /// </summary>
    /// <param name="credential">The credential to store.</param>
    /// <param name="ct">A cancellation token.</param>
    Task UpsertAsync(PasskeyCredential credential, CancellationToken ct = default);

    /// <summary>
    /// Deletes a passkey credential.
    /// </summary>
    /// <param name="userId">The user identifier that owns the credential.</param>
    /// <param name="credentialId">The raw credential identifier.</param>
    /// <param name="ct">A cancellation token.</param>
    Task DeleteAsync(string userId, byte[] credentialId, CancellationToken ct = default);
}
