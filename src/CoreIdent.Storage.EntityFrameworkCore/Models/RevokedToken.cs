using System;

namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity representing a revoked token (by JTI) and its expiration.
/// </summary>
public sealed class RevokedToken
{
    /// <summary>
    /// Gets or sets the JWT ID (JTI) that uniquely identifies the token.
    /// </summary>
    public string Jti { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the token type (e.g. access token, refresh token).
    /// </summary>
    public string TokenType { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the UTC time when this revocation record expires.
    /// </summary>
    public DateTime ExpiresAtUtc { get; set; }
    /// <summary>
    /// Gets or sets the UTC time when the token was revoked.
    /// </summary>
    public DateTime RevokedAtUtc { get; set; }
}
