namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="ITokenRevocationStore"/> to provide realm-aware token revocation storage.
/// </summary>
public sealed class DefaultRealmTokenRevocationStoreAdapter : IRealmTokenRevocationStore
{
    private readonly ITokenRevocationStore _inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultRealmTokenRevocationStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner token revocation store to wrap.</param>
    public DefaultRealmTokenRevocationStoreAdapter(ITokenRevocationStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task RevokeTokenAsync(string realmId, string jti, string tokenType, DateTime expiry, CancellationToken ct = default)
    {
        return _inner.RevokeTokenAsync(jti, tokenType, expiry, ct);
    }

    /// <inheritdoc />
    public Task<bool> IsRevokedAsync(string realmId, string jti, CancellationToken ct = default)
    {
        return _inner.IsRevokedAsync(jti, ct);
    }

    /// <inheritdoc />
    public Task CleanupExpiredAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.CleanupExpiredAsync(ct);
    }
}
