using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmUserGrantStoreAdapter : IRealmUserGrantStore
{
    private readonly IUserGrantStore _inner;

    public DefaultRealmUserGrantStoreAdapter(IUserGrantStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task<CoreIdentUserGrant?> FindAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default)
    {
        return _inner.FindAsync(subjectId, clientId, ct);
    }

    public Task SaveAsync(string realmId, CoreIdentUserGrant grant, CancellationToken ct = default)
    {
        return _inner.SaveAsync(grant, ct);
    }

    public Task RevokeAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default)
    {
        return _inner.RevokeAsync(subjectId, clientId, ct);
    }

    public Task<bool> HasUserGrantedConsentAsync(string realmId, string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default)
    {
        return _inner.HasUserGrantedConsentAsync(subjectId, clientId, scopes, ct);
    }
}
