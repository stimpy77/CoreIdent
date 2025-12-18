using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="IRefreshTokenStore"/> to provide realm-aware refresh token storage.
/// </summary>
public sealed class DefaultRealmRefreshTokenStoreAdapter : IRealmRefreshTokenStore
{
    private readonly IRefreshTokenStore _inner;

    /// <summary>
    /// Initializes a new instance of <see cref="DefaultRealmRefreshTokenStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner refresh token store to wrap.</param>
    public DefaultRealmRefreshTokenStoreAdapter(IRefreshTokenStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task<string> StoreAsync(string realmId, CoreIdentRefreshToken token, CancellationToken ct = default)
    {
        return _inner.StoreAsync(token, ct);
    }

    /// <inheritdoc />
    public Task<CoreIdentRefreshToken?> GetAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.GetAsync(handle, ct);
    }

    /// <inheritdoc />
    public Task<bool> RevokeAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.RevokeAsync(handle, ct);
    }

    /// <inheritdoc />
    public Task RevokeFamilyAsync(string realmId, string familyId, CancellationToken ct = default)
    {
        return _inner.RevokeFamilyAsync(familyId, ct);
    }

    /// <inheritdoc />
    public Task<bool> ConsumeAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.ConsumeAsync(handle, ct);
    }

    /// <inheritdoc />
    public Task CleanupExpiredAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.CleanupExpiredAsync(ct);
    }
}
