using System;

namespace CoreIdent.Core.Configuration;

/// <summary>
/// Configuration options for CoreIdent core services.
/// </summary>
public class CoreIdentOptions
{
    /// <summary>
    /// Gets or sets the issuer name to be used in JWT tokens. Required.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the audience name to be used in JWT tokens. Required.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Gets or sets the secret key used for signing JWT tokens (symmetric key). Required.
    /// Min length recommended: 32 bytes (256 bits) for HS256.
    /// Note: Asymmetric keys (RSA/ECDSA) will be supported later.
    /// </summary>
    public string? SigningKeySecret { get; set; }

    /// <summary>
    /// Gets or sets the lifetime duration for access tokens. Required and must be positive.
    /// </summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15); // Default

    /// <summary>
    /// Gets or sets the lifetime duration for refresh tokens. Required and must be positive.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7); // Default
}
