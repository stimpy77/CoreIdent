using System;

namespace CoreIdent.Core.Configuration;

public sealed class CoreIdentOptions
{
    public string? Issuer { get; set; }
    public string? Audience { get; set; }

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);
}
