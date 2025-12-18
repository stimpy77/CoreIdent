using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="IClientStore"/> to provide realm-aware client storage.
/// </summary>
public sealed class DefaultRealmClientStoreAdapter : IRealmClientStore
{
    private readonly IClientStore _inner;

    /// <summary>
    /// Initializes a new instance of <see cref="DefaultRealmClientStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner client store to wrap.</param>
    public DefaultRealmClientStoreAdapter(IClientStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task<CoreIdentClient?> FindByClientIdAsync(string realmId, string clientId, CancellationToken ct = default)
    {
        return _inner.FindByClientIdAsync(clientId, ct);
    }

    /// <inheritdoc />
    public Task<bool> ValidateClientSecretAsync(string realmId, string clientId, string clientSecret, CancellationToken ct = default)
    {
        return _inner.ValidateClientSecretAsync(clientId, clientSecret, ct);
    }

    /// <inheritdoc />
    public Task CreateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default)
    {
        return _inner.CreateAsync(client, ct);
    }

    /// <inheritdoc />
    public Task UpdateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default)
    {
        return _inner.UpdateAsync(client, ct);
    }

    /// <inheritdoc />
    public Task DeleteAsync(string realmId, string clientId, CancellationToken ct = default)
    {
        return _inner.DeleteAsync(clientId, ct);
    }
}
