using System;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

public interface ITokenRevocationStore
{
    Task RevokeTokenAsync(string jti, string tokenType, DateTime expiry, CancellationToken ct = default);
    Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default);
    Task CleanupExpiredAsync(CancellationToken ct = default);
}
