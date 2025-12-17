namespace CoreIdent.Core.Stores;

public interface IRealmTokenRevocationStore
{
    Task RevokeTokenAsync(string realmId, string jti, string tokenType, DateTime expiry, CancellationToken ct = default);
    Task<bool> IsRevokedAsync(string realmId, string jti, CancellationToken ct = default);
    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
