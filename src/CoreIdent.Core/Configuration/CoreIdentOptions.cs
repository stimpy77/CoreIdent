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

    /// <summary>
    /// Gets or sets the retention period for consumed refresh tokens before they are permanently removed.
    /// This helps with detecting token replay attempts while managing database growth.
    /// Set to null to keep consumed tokens indefinitely (not recommended for production).
    /// </summary>
    public TimeSpan? ConsumedTokenRetentionPeriod { get; set; } = TimeSpan.FromDays(30); // Default 30 days

    /// <summary>
    /// Options for token security behavior.
    /// </summary>
    public TokenSecurityOptions TokenSecurity { get; set; } = new TokenSecurityOptions();
}

/// <summary>
/// Defines options for token security behavior, especially for token theft detection.
/// </summary>
public class TokenSecurityOptions
{
    /// <summary>
    /// Specifies how to respond when a consumed token is presented again, which could indicate token theft.
    /// Default: RevokeFamily - Revoke all tokens in the family.
    /// </summary>
    public TokenTheftDetectionMode TokenTheftDetectionMode { get; set; } = TokenTheftDetectionMode.RevokeFamily;

    /// <summary>
    /// Whether to automatically revoke all refresh tokens for a user when they change their password.
    /// Default: true
    /// </summary>
    public bool RevokeTokensOnPasswordChange { get; set; } = true;

    /// <summary>
    /// Whether to enable token family tracking for theft detection and automatic family revocation.
    /// When disabled, refresh tokens are still rotated, but consumed tokens do not trigger family revocation.
    /// Default: true (Recommended for enhanced security)
    /// </summary>
    public bool EnableTokenFamilyTracking { get; set; } = true;
}

/// <summary>
/// Defines how to respond to a potential token theft scenario.
/// </summary>
public enum TokenTheftDetectionMode
{
    /// <summary>
    /// Do nothing special, just reject the token.
    /// </summary>
    Silent = 0,

    /// <summary>
    /// Revoke all tokens in the same family (chain of rotated tokens).
    /// </summary>
    RevokeFamily = 1,

    /// <summary>
    /// Revoke all tokens for the user across all clients.
    /// </summary>
    RevokeAllUserTokens = 2
}
