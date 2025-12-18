using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="IAuthorizationCodeStore"/> to provide realm-aware authorization code storage.
/// </summary>
public sealed class DefaultRealmAuthorizationCodeStoreAdapter : IRealmAuthorizationCodeStore
{
    private readonly IAuthorizationCodeStore _inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultRealmAuthorizationCodeStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner authorization code store to wrap.</param>
    public DefaultRealmAuthorizationCodeStoreAdapter(IAuthorizationCodeStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task CreateAsync(string realmId, CoreIdentAuthorizationCode code, CancellationToken ct = default)
    {
        return _inner.CreateAsync(code, ct);
    }

    /// <inheritdoc />
    public Task<CoreIdentAuthorizationCode?> GetAsync(string realmId, string handle, CancellationToken ct = default)
    {
        return _inner.GetAsync(handle, ct);
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
