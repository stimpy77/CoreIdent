namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmTokenRevocationStoreAdapter : IRealmTokenRevocationStore
{
    private readonly ITokenRevocationStore _inner;

    public DefaultRealmTokenRevocationStoreAdapter(ITokenRevocationStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task RevokeTokenAsync(string realmId, string jti, string tokenType, DateTime expiry, CancellationToken ct = default)
    {
        return _inner.RevokeTokenAsync(jti, tokenType, expiry, ct);
    }

    public Task<bool> IsRevokedAsync(string realmId, string jti, CancellationToken ct = default)
    {
        return _inner.IsRevokedAsync(jti, ct);
    }

    public Task CleanupExpiredAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.CleanupExpiredAsync(ct);
    }
}
