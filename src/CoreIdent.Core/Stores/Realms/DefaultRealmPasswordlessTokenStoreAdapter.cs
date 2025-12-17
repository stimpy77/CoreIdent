using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

public sealed class DefaultRealmPasswordlessTokenStoreAdapter : IRealmPasswordlessTokenStore
{
    private readonly IPasswordlessTokenStore _inner;

    public DefaultRealmPasswordlessTokenStoreAdapter(IPasswordlessTokenStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task<string> CreateTokenAsync(string realmId, PasswordlessToken token, CancellationToken ct = default)
    {
        return _inner.CreateTokenAsync(token, ct);
    }

    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, CancellationToken ct = default)
    {
        return _inner.ValidateAndConsumeAsync(token, ct);
    }

    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, string? tokenType, string? recipient, CancellationToken ct = default)
    {
        return _inner.ValidateAndConsumeAsync(token, tokenType, recipient, ct);
    }

    public Task CleanupExpiredAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.CleanupExpiredAsync(ct);
    }
}
