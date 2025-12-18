using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="IUserStore"/> to provide realm-aware user storage.
/// </summary>
public sealed class DefaultRealmUserStoreAdapter : IRealmUserStore
{
    private readonly IUserStore _inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultRealmUserStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner user store to wrap.</param>
    public DefaultRealmUserStoreAdapter(IUserStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindByIdAsync(string realmId, string id, CancellationToken ct = default)
    {
        return _inner.FindByIdAsync(id, ct);
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindByUsernameAsync(string realmId, string username, CancellationToken ct = default)
    {
        return _inner.FindByUsernameAsync(username, ct);
    }

    /// <inheritdoc />
    public Task CreateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default)
    {
        return _inner.CreateAsync(user, ct);
    }

    /// <inheritdoc />
    public Task UpdateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default)
    {
        return _inner.UpdateAsync(user, ct);
    }

    /// <inheritdoc />
    public Task DeleteAsync(string realmId, string id, CancellationToken ct = default)
    {
        return _inner.DeleteAsync(id, ct);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<Claim>> GetClaimsAsync(string realmId, string subjectId, CancellationToken ct = default)
    {
        return _inner.GetClaimsAsync(subjectId, ct);
    }

    /// <inheritdoc />
    public Task SetClaimsAsync(string realmId, string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default)
    {
        return _inner.SetClaimsAsync(subjectId, claims, ct);
    }
}
