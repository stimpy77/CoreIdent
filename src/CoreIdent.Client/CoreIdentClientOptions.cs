namespace CoreIdent.Client;

/// <summary>
/// Options for configuring a <see cref="CoreIdentClient"/>.
/// </summary>
public sealed class CoreIdentClientOptions
{
    /// <summary>
    /// Authorization server authority (e.g., "https://auth.example.com").
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// OAuth client identifier.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Optional client secret (confidential clients).
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Redirect URI for the authorization response.
    /// </summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>
    /// Post-logout redirect URI.
    /// </summary>
    public string PostLogoutRedirectUri { get; set; } = string.Empty;

    /// <summary>
    /// Scopes to request.
    /// </summary>
    public IEnumerable<string> Scopes { get; set; } = ["openid", "profile"];

    /// <summary>
    /// Whether to use PKCE.
    /// </summary>
    public bool UsePkce { get; set; } = true;

    /// <summary>
    /// Whether to use DPoP.
    /// </summary>
    public bool UseDPoP { get; set; } = false;

    /// <summary>
    /// How soon before access token expiration to refresh.
    /// </summary>
    public TimeSpan TokenRefreshThreshold { get; set; } = TimeSpan.FromMinutes(5);
}
