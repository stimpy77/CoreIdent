using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmUserStoreAdapter : IRealmUserStore
{
    private readonly IUserStore _inner;

    public DefaultRealmUserStoreAdapter(IUserStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task<CoreIdentUser?> FindByIdAsync(string realmId, string id, CancellationToken ct = default)
    {
        return _inner.FindByIdAsync(id, ct);
    }

    public Task<CoreIdentUser?> FindByUsernameAsync(string realmId, string username, CancellationToken ct = default)
    {
        return _inner.FindByUsernameAsync(username, ct);
    }

    public Task CreateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default)
    {
        return _inner.CreateAsync(user, ct);
    }

    public Task UpdateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default)
    {
        return _inner.UpdateAsync(user, ct);
    }

    public Task DeleteAsync(string realmId, string id, CancellationToken ct = default)
    {
        return _inner.DeleteAsync(id, ct);
    }

    public Task<IReadOnlyList<Claim>> GetClaimsAsync(string realmId, string subjectId, CancellationToken ct = default)
    {
        return _inner.GetClaimsAsync(subjectId, ct);
    }

    public Task SetClaimsAsync(string realmId, string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default)
    {
        return _inner.SetClaimsAsync(subjectId, claims, ct);
    }
}
