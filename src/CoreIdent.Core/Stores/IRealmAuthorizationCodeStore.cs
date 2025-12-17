using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRealmAuthorizationCodeStore
{
    Task CreateAsync(string realmId, CoreIdentAuthorizationCode code, CancellationToken ct = default);

    Task<CoreIdentAuthorizationCode?> GetAsync(string realmId, string handle, CancellationToken ct = default);

    Task<bool> ConsumeAsync(string realmId, string handle, CancellationToken ct = default);

    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
