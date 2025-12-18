using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.Realms;

/// <summary>
/// Default adapter that wraps an <see cref="IPasswordlessTokenStore"/> to provide realm-aware passwordless token storage.
/// </summary>
public sealed class DefaultRealmPasswordlessTokenStoreAdapter : IRealmPasswordlessTokenStore
{
    private readonly IPasswordlessTokenStore _inner;

    /// <summary>
    /// Initializes a new instance of <see cref="DefaultRealmPasswordlessTokenStoreAdapter"/> class.
    /// </summary>
    /// <param name="inner">The inner passwordless token store to wrap.</param>
    public DefaultRealmPasswordlessTokenStoreAdapter(IPasswordlessTokenStore inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc />
    public Task<string> CreateTokenAsync(string realmId, PasswordlessToken token, CancellationToken ct = default)
    {
        return _inner.CreateTokenAsync(token, ct);
    }

    /// <inheritdoc />
    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, CancellationToken ct = default)
    {
        return _inner.ValidateAndConsumeAsync(token, ct);
    }

    /// <inheritdoc />
    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, string? tokenType, string? recipient, CancellationToken ct = default)
    {
        return _inner.ValidateAndConsumeAsync(token, tokenType, recipient, ct);
    }

    /// <inheritdoc />
    public Task CleanupExpiredAsync(string realmId, CancellationToken ct = default)
    {
        return _inner.CleanupExpiredAsync(ct);
    }
}
