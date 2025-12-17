using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRealmUserStore
{
    Task<CoreIdentUser?> FindByIdAsync(string realmId, string id, CancellationToken ct = default);

    Task<CoreIdentUser?> FindByUsernameAsync(string realmId, string username, CancellationToken ct = default);

    Task CreateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default);

    Task UpdateAsync(string realmId, CoreIdentUser user, CancellationToken ct = default);

    Task DeleteAsync(string realmId, string id, CancellationToken ct = default);

    Task<IReadOnlyList<Claim>> GetClaimsAsync(string realmId, string subjectId, CancellationToken ct = default);

    Task SetClaimsAsync(string realmId, string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default);
}
