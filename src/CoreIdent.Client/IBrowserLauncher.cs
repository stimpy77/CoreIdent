namespace CoreIdent.Client;

/// <summary>
/// Abstraction for launching a browser-based authentication flow.
/// </summary>
public interface IBrowserLauncher
{
    /// <summary>
    /// Launches the system browser (or embedded browser) and waits for a redirect.
    /// </summary>
    /// <param name="url">Authorization URL.</param>
    /// <param name="redirectUri">Expected redirect URI.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<BrowserResult> LaunchAsync(string url, string redirectUri, CancellationToken ct = default);
}
