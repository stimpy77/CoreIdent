using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IPasswordlessTokenStore
{
    Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default);

    Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default);

    Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, string? tokenType, string? recipient, CancellationToken ct = default);

    Task CleanupExpiredAsync(CancellationToken ct = default);
}
