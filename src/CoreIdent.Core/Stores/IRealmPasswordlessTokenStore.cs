using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRealmPasswordlessTokenStore
{
    Task<string> CreateTokenAsync(string realmId, PasswordlessToken token, CancellationToken ct = default);

    Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, CancellationToken ct = default);

    Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, string? tokenType, string? recipient, CancellationToken ct = default);

    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
