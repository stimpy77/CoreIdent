using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="IScopeStore"/> to provide realm-aware scope storage.
/// </summary>
public sealed class DefaultRealmScopeStoreAdapter : IRealmScopeStore
{
    private readonly IScopeStore _inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultRealmScopeStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner scope store to wrap.</param>
    public DefaultRealmScopeStoreAdapter(IScopeStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task<CoreIdentScope?> FindByNameAsync(string realmId, string name, CancellationToken ct = default)
    {
        return _inner.FindByNameAsync(name, ct);
    }

    /// <inheritdoc />
    public Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(string realmId, IEnumerable<string> scopeNames, CancellationToken ct = default)
    {
        return _inner.FindByScopesAsync(scopeNames, ct);
    }

    /// <inheritdoc />
    public Task<IEnumerable<CoreIdentScope>> GetAllAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.GetAllAsync(ct);
    }
}
