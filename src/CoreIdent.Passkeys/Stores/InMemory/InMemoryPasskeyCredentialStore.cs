using System.Collections.Concurrent;
using CoreIdent.Passkeys.Models;

namespace CoreIdent.Passkeys.Stores.InMemory;

public sealed class InMemoryPasskeyCredentialStore : IPasskeyCredentialStore
{
    private readonly ConcurrentDictionary<string, PasskeyCredential> _byKey = new(StringComparer.Ordinal);

    public Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var results = _byKey.Values.Where(x => string.Equals(x.UserId, userId, StringComparison.Ordinal)).ToList();
        return Task.FromResult<IReadOnlyList<PasskeyCredential>>(results);
    }

    public Task<PasskeyCredential?> GetByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var key = Convert.ToBase64String(credentialId);
        _byKey.TryGetValue(key, out var value);
        return Task.FromResult(value);
    }

    public Task UpsertAsync(PasskeyCredential credential, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var key = Convert.ToBase64String(credential.CredentialId);
        _byKey[key] = credential;

        return Task.CompletedTask;
    }

    public Task DeleteAsync(string userId, byte[] credentialId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(credentialId);

        var key = Convert.ToBase64String(credentialId);
        _byKey.TryRemove(key, out _);

        return Task.CompletedTask;
    }
}
