namespace CoreIdent.Core.Configuration;

public sealed class CoreIdentAuthorizationCodeOptions
{
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public bool EnableCleanupHostedService { get; set; } = true;

    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(5);
}
