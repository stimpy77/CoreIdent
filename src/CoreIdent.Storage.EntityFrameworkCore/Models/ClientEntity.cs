namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity for OAuth 2.0 / OIDC client applications.
/// </summary>
public class ClientEntity
{
    /// <summary>
    /// Gets or sets the client identifier.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the hashed client secret, if applicable.
    /// </summary>
    public string? ClientSecretHash { get; set; }
    /// <summary>
    /// Gets or sets the client display name.
    /// </summary>
    public string ClientName { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the client type string.
    /// </summary>
    public string ClientType { get; set; } = "Confidential";
    /// <summary>
    /// Gets or sets the JSON-serialized list of redirect URIs.
    /// </summary>
    public string RedirectUrisJson { get; set; } = "[]";
    /// <summary>
    /// Gets or sets the JSON-serialized list of post-logout redirect URIs.
    /// </summary>
    public string PostLogoutRedirectUrisJson { get; set; } = "[]";
    /// <summary>
    /// Gets or sets the JSON-serialized list of allowed scopes.
    /// </summary>
    public string AllowedScopesJson { get; set; } = "[]";
    /// <summary>
    /// Gets or sets the JSON-serialized list of allowed grant types.
    /// </summary>
    public string AllowedGrantTypesJson { get; set; } = "[]";
    /// <summary>
    /// Gets or sets the access token lifetime in seconds.
    /// </summary>
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    /// <summary>
    /// Gets or sets the refresh token lifetime in seconds.
    /// </summary>
    public int RefreshTokenLifetimeSeconds { get; set; } = 86400;
    /// <summary>
    /// Gets or sets a value indicating whether PKCE is required.
    /// </summary>
    public bool RequirePkce { get; set; } = true;
    /// <summary>
    /// Gets or sets a value indicating whether user consent is required.
    /// </summary>
    public bool RequireConsent { get; set; } = false;
    /// <summary>
    /// Gets or sets a value indicating whether offline access is allowed.
    /// </summary>
    public bool AllowOfflineAccess { get; set; } = false;
    /// <summary>
    /// Gets or sets a value indicating whether the client is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// Gets or sets the UTC time when the client was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }
    /// <summary>
    /// Gets or sets the UTC time when the client was last updated.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}
