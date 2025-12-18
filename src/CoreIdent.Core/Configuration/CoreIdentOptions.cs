using System;

namespace CoreIdent.Core.Configuration;

/// <summary>
/// Core configuration options for CoreIdent.
/// </summary>
public sealed class CoreIdentOptions
{
    /// <summary>
    /// Issuer URI.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Audience URI.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Default access token lifetime.
    /// </summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Default refresh token lifetime.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);
}
