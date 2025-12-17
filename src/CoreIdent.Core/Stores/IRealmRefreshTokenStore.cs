using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRealmRefreshTokenStore
{
    Task<string> StoreAsync(string realmId, CoreIdentRefreshToken token, CancellationToken ct = default);
    Task<CoreIdentRefreshToken?> GetAsync(string realmId, string handle, CancellationToken ct = default);
    Task<bool> RevokeAsync(string realmId, string handle, CancellationToken ct = default);
    Task RevokeFamilyAsync(string realmId, string familyId, CancellationToken ct = default);
    Task<bool> ConsumeAsync(string realmId, string handle, CancellationToken ct = default);
    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
