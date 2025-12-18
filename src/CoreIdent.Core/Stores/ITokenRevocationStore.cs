using System;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Stores revoked token identifiers (JTI) so tokens can be rejected prior to expiry.
/// </summary>
public interface ITokenRevocationStore
{
    /// <summary>
    /// Records a token as revoked.
    /// </summary>
    /// <param name="jti">The token identifier (JTI).</param>
    /// <param name="tokenType">The token type (e.g. <c>access_token</c> or <c>refresh_token</c>).</param>
    /// <param name="expiry">The token expiry time.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RevokeTokenAsync(string jti, string tokenType, DateTime expiry, CancellationToken ct = default);

    /// <summary>
    /// Determines whether a token identifier has been revoked.
    /// </summary>
    /// <param name="jti">The token identifier (JTI).</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns><see langword="true"/> if the token is revoked; otherwise <see langword="false"/>.</returns>
    Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default);

    /// <summary>
    /// Removes expired revocation entries.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(CancellationToken ct = default);
}
