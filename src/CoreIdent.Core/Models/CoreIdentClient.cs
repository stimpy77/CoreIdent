namespace CoreIdent.Core.Models;

/// <summary>
/// Represents an OAuth 2.0 / OIDC client application.
/// </summary>
public class CoreIdentClient
{
    /// <summary>
    /// Unique identifier for the client.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Hashed client secret for confidential clients. Null for public clients.
    /// </summary>
    public string? ClientSecretHash { get; set; }

    /// <summary>
    /// Human-readable name for the client.
    /// </summary>
    public string ClientName { get; set; } = string.Empty;

    /// <summary>
    /// Type of client (public or confidential).
    /// </summary>
    public ClientType ClientType { get; set; } = ClientType.Confidential;

    /// <summary>
    /// Allowed redirect URIs for authorization code flow.
    /// </summary>
    public ICollection<string> RedirectUris { get; set; } = [];

    /// <summary>
    /// Allowed post-logout redirect URIs.
    /// </summary>
    public ICollection<string> PostLogoutRedirectUris { get; set; } = [];

    /// <summary>
    /// Scopes the client is allowed to request.
    /// </summary>
    public ICollection<string> AllowedScopes { get; set; } = [];

    /// <summary>
    /// Grant types the client is allowed to use.
    /// </summary>
    public ICollection<string> AllowedGrantTypes { get; set; } = [];

    /// <summary>
    /// Access token lifetime in seconds.
    /// </summary>
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;

    /// <summary>
    /// Refresh token lifetime in seconds.
    /// </summary>
    public int RefreshTokenLifetimeSeconds { get; set; } = 86400;

    /// <summary>
    /// Whether PKCE is required for authorization code flow.
    /// </summary>
    public bool RequirePkce { get; set; } = true;

    /// <summary>
    /// Whether the client can request offline_access (refresh tokens).
    /// </summary>
    public bool AllowOfflineAccess { get; set; } = false;

    /// <summary>
    /// Whether the client is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// When the client was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// When the client was last updated.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}

/// <summary>
/// OAuth 2.0 client types per RFC 6749.
/// </summary>
public enum ClientType
{
    /// <summary>
    /// Public client (e.g., SPA, mobile app) - cannot securely store secrets.
    /// </summary>
    Public,

    /// <summary>
    /// Confidential client (e.g., server-side app) - can securely store secrets.
    /// </summary>
    Confidential
}
