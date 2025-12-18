namespace CoreIdent.Core.Configuration;

/// <summary>
/// Options for authorization code issuance and cleanup.
/// </summary>
public sealed class CoreIdentAuthorizationCodeOptions
{
    /// <summary>
    /// Lifetime of issued authorization codes.
    /// </summary>
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether to enable the background cleanup service for expired authorization codes.
    /// </summary>
    public bool EnableCleanupHostedService { get; set; } = true;

    /// <summary>
    /// Interval for the authorization code cleanup job.
    /// </summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(5);
}
