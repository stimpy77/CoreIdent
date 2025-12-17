using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmScopeStoreAdapter : IRealmScopeStore
{
    private readonly IScopeStore _inner;

    public DefaultRealmScopeStoreAdapter(IScopeStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task<CoreIdentScope?> FindByNameAsync(string realmId, string name, CancellationToken ct = default)
    {
        return _inner.FindByNameAsync(name, ct);
    }

    public Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(string realmId, IEnumerable<string> scopeNames, CancellationToken ct = default)
    {
        return _inner.FindByScopesAsync(scopeNames, ct);
    }

    public Task<IEnumerable<CoreIdentScope>> GetAllAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.GetAllAsync(ct);
    }
}
