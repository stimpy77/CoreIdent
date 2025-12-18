using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="IUserGrantStore"/> to provide realm-aware user grant storage.
/// </summary>
public sealed class DefaultRealmUserGrantStoreAdapter : IRealmUserGrantStore
{
    private readonly IUserGrantStore _inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultRealmUserGrantStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner user grant store to wrap.</param>
    public DefaultRealmUserGrantStoreAdapter(IUserGrantStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task<CoreIdentUserGrant?> FindAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default)
    {
        return _inner.FindAsync(subjectId, clientId, ct);
    }

    /// <inheritdoc />
    public Task SaveAsync(string realmId, CoreIdentUserGrant grant, CancellationToken ct = default)
    {
        return _inner.SaveAsync(grant, ct);
    }

    /// <inheritdoc />
    public Task RevokeAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default)
    {
        return _inner.RevokeAsync(subjectId, clientId, ct);
    }

    /// <inheritdoc />
    public Task<bool> HasUserGrantedConsentAsync(string realmId, string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default)
    {
        return _inner.HasUserGrantedConsentAsync(subjectId, clientId, scopes, ct);
    }
}
