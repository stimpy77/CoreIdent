using System.Security.Claims;

namespace CoreIdent.Core.Services;

/// <summary>
/// Service for creating JWT tokens.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Creates a JWT with the specified parameters.
    /// </summary>
    /// <param name="issuer">Token issuer.</param>
    /// <param name="audience">Token audience.</param>
    /// <param name="claims">Claims to include in the token.</param>
    /// <param name="expiresAt">Token expiration time.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The signed JWT string.</returns>
    Task<string> CreateJwtAsync(
        string issuer,
        string audience,
        IEnumerable<Claim> claims,
        DateTimeOffset expiresAt,
        CancellationToken ct = default);
}
