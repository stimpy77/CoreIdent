using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IUserStore
{
    Task<CoreIdentUser?> FindByIdAsync(string id, CancellationToken ct = default);

    Task<CoreIdentUser?> FindByUsernameAsync(string username, CancellationToken ct = default);

    Task CreateAsync(CoreIdentUser user, CancellationToken ct = default);

    Task UpdateAsync(CoreIdentUser user, CancellationToken ct = default);

    Task DeleteAsync(string id, CancellationToken ct = default);

    Task<IReadOnlyList<Claim>> GetClaimsAsync(string subjectId, CancellationToken ct = default);

    Task SetClaimsAsync(string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default);
}
