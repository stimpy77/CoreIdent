using CoreIdent.Passkeys.Models;

namespace CoreIdent.Passkeys.Stores;

public interface IPasskeyCredentialStore
{
    Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default);

    Task<PasskeyCredential?> GetByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default);

    Task UpsertAsync(PasskeyCredential credential, CancellationToken ct = default);

    Task DeleteAsync(string userId, byte[] credentialId, CancellationToken ct = default);
}
