using System.Threading;
using System.Threading.Tasks;
 using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRefreshTokenStore
{
    Task<string> StoreAsync(CoreIdentRefreshToken token, CancellationToken ct = default);
    Task<CoreIdentRefreshToken?> GetAsync(string handle, CancellationToken ct = default);
    Task<bool> RevokeAsync(string handle, CancellationToken ct = default);
    Task RevokeFamilyAsync(string familyId, CancellationToken ct = default);
    Task<bool> ConsumeAsync(string handle, CancellationToken ct = default);
    Task CleanupExpiredAsync(CancellationToken ct = default);
}
