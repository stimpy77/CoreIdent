using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmClientStoreAdapter : IRealmClientStore
{
    private readonly IClientStore _inner;

    public DefaultRealmClientStoreAdapter(IClientStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task<CoreIdentClient?> FindByClientIdAsync(string realmId, string clientId, CancellationToken ct = default)
    {
        return _inner.FindByClientIdAsync(clientId, ct);
    }

    public Task<bool> ValidateClientSecretAsync(string realmId, string clientId, string clientSecret, CancellationToken ct = default)
    {
        return _inner.ValidateClientSecretAsync(clientId, clientSecret, ct);
    }

    public Task CreateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default)
    {
        return _inner.CreateAsync(client, ct);
    }

    public Task UpdateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default)
    {
        return _inner.UpdateAsync(client, ct);
    }

    public Task DeleteAsync(string realmId, string clientId, CancellationToken ct = default)
    {
        return _inner.DeleteAsync(clientId, ct);
    }
}
