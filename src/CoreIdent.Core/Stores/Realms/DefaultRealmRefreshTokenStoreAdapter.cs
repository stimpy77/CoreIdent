using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmRefreshTokenStoreAdapter : IRealmRefreshTokenStore
{
    private readonly IRefreshTokenStore _inner;

    public DefaultRealmRefreshTokenStoreAdapter(IRefreshTokenStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task<string> StoreAsync(string realmId, CoreIdentRefreshToken token, CancellationToken ct = default)
    {
        return _inner.StoreAsync(token, ct);
    }

    public Task<CoreIdentRefreshToken?> GetAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.GetAsync(handle, ct);
    }

    public Task<bool> RevokeAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.RevokeAsync(handle, ct);
    }

    public Task RevokeFamilyAsync(string realmId, string familyId, CancellationToken ct = default)
    {
        return _inner.RevokeFamilyAsync(familyId, ct);
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
