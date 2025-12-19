using System.Collections.Generic;

namespace CoreIdent.Core.Configuration;

/// <summary>
/// Configuration options for UserInfo endpoint behavior, including custom claims exposure.
/// </summary>
public sealed class CoreIdentUserInfoOptions
{
    /// <summary>
    /// Optional scope name that gates inclusion of custom claims in the UserInfo response.
    /// When set, custom claims are only included if this scope is granted.
    /// </summary>
    public string? CustomClaimsScope { get; set; }

    /// <summary>
    /// Optional allowlist of custom claim names to include when <see cref="CustomClaimsScope"/> is granted.
    /// If empty or null, all non-reserved custom claims are included.
    /// </summary>
    public ICollection<string> CustomClaimNames { get; set; } = [];
}
