using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IAuthorizationCodeStore
{
    Task CreateAsync(CoreIdentAuthorizationCode code, CancellationToken ct = default);

    Task<CoreIdentAuthorizationCode?> GetAsync(string handle, CancellationToken ct = default);

    Task<bool> ConsumeAsync(string handle, CancellationToken ct = default);

    Task CleanupExpiredAsync(CancellationToken ct = default);
}
