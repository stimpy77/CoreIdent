using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmAuthorizationCodeStoreAdapter : IRealmAuthorizationCodeStore
{
    private readonly IAuthorizationCodeStore _inner;

    public DefaultRealmAuthorizationCodeStoreAdapter(IAuthorizationCodeStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task CreateAsync(string realmId, CoreIdentAuthorizationCode code, CancellationToken ct = default)
    {
        return _inner.CreateAsync(code, ct);
    }

    public Task<CoreIdentAuthorizationCode?> GetAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.GetAsync(handle, ct);
    }

    public Task<bool> ConsumeAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.ConsumeAsync(handle, ct);
    }

    public Task CleanupExpiredAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.CleanupExpiredAsync(ct);
    }
}
