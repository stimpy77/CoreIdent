using System;
using System.Collections.Generic;

namespace CoreIdent.Core.Models;

/// <summary>
/// Represents an OAuth 2.0 / OIDC client application.
/// </summary>
public class CoreIdentClient
{
    /// <summary>
    /// Unique identifier for the client.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Client display name (used for consent screens, etc.).
    /// </summary>
    public string? ClientName { get; set; }

    /// <summary>
    /// URI to further information about client (used on consent screen).
    /// </summary>
    public string? ClientUri { get; set; }

    /// <summary>
    /// URI to client logo (used on consent screen).
    /// </summary>
    public string? LogoUri { get; set; }

    /// <summary>
    /// Specifies if the client is enabled (defaults to true).
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// List of client secrets - credentials defining the client.
    /// </summary>
    public virtual ICollection<CoreIdentClientSecret> ClientSecrets { get; set; } = new List<CoreIdentClientSecret>();

    /// <summary>
    /// Specifies the grant types the client is allowed to use.
    /// Use constants (e.g., GrantType.AuthorizationCode, GrantType.ClientCredentials).
    /// </summary>
    public virtual List<string> AllowedGrantTypes { get; set; } = new List<string>();

    /// <summary>
    /// Specifies the allowed URIs to return tokens or authorization codes to.
    /// </summary>
    public virtual List<string> RedirectUris { get; set; } = new List<string>();

    /// <summary>
    /// Specifies the allowed URIs to redirect to after logout.
    /// </summary>
    public virtual List<string> PostLogoutRedirectUris { get; set; } = new List<string>();

    /// <summary>
    /// Specifies the scopes that the client is allowed to request. If empty, the client can request all scopes defined in the system.
    /// </summary>
    public virtual List<string> AllowedScopes { get; set; } = new List<string>();

    /// <summary>
    /// Specifies whether this client must use PKCE for the authorization code flow (defaults to true for public clients).
    /// </summary>
    public bool RequirePkce { get; set; } = true; // Consider basing default on client type (confidential vs public)

    /// <summary>
    /// Specifies whether the client is allowed to request refresh tokens (via the offline_access scope).
    /// </summary>
    public bool AllowOfflineAccess { get; set; } = false;

    /// <summary>
    /// Lifetime of identity token in seconds (defaults to 300 seconds / 5 minutes).
    /// </summary>
    public int IdentityTokenLifetime { get; set; } = 300;

    /// <summary>
    /// Lifetime of access token in seconds (defaults to 3600 seconds / 1 hour).
    /// </summary>
    public int AccessTokenLifetime { get; set; } = 3600;

    /// <summary>
    /// Lifetime of authorization code in seconds (defaults to 300 seconds / 5 minutes).
    /// </summary>
    public int AuthorizationCodeLifetime { get; set; } = 300;

    /// <summary>
    /// Absolute lifetime of refresh token in seconds (defaults to 2592000 seconds / 30 days).
    /// </summary>
    public int AbsoluteRefreshTokenLifetime { get; set; } = 2592000;

    /// <summary>
    /// Sliding lifetime of refresh token in seconds (defaults to 1296000 seconds / 15 days).
    /// </summary>
    public int SlidingRefreshTokenLifetime { get; set; } = 1296000;

    /// <summary>
    /// Refresh token usage type (ReUse, OneTimeOnly - defaults to OneTimeOnly for security).
    /// </summary>
    public TokenUsage RefreshTokenUsage { get; set; } = TokenUsage.OneTimeOnly;

    /// <summary>
    /// Refresh token expiration type (Absolute, Sliding - defaults to Absolute).
    /// </summary>
    public TokenExpiration RefreshTokenExpiration { get; set; } = TokenExpiration.Absolute;

    /// <summary>
    /// Specifies whether consent is required for this client (defaults to false).
    /// </summary>
    public bool RequireConsent { get; set; } = false;

    // Add other properties as needed: AllowedCorsOrigins, IdentityProviderRestrictions, etc.
}

/// <summary>
/// Represents a secret associated with a client.
/// </summary>
public class CoreIdentClientSecret
{
    /// <summary>
    /// Primary key.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Foreign key to the Client.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Client this secret belongs to.
    /// </summary>
    public virtual CoreIdentClient Client { get; set; } = default!;

    /// <summary>
    /// Description of the secret.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// The secret value (should be hashed).
    /// </summary>
    public string Value { get; set; } = default!;

    /// <summary>
    /// Expiration date for the secret.
    /// </summary>
    public DateTime? Expiration { get; set; }

    /// <summary>
    /// Type of the secret (e.g., SharedSecret, X509Thumbprint).
    /// </summary>
    public string Type { get; set; } = "SharedSecret";

    /// <summary>
    /// Date the secret was created.
    /// </summary>
    public DateTime Created { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Enum for refresh token usage behavior.
/// </summary>
public enum TokenUsage
{
    ReUse = 0,
    OneTimeOnly = 1
}

/// <summary>
/// Enum for refresh token expiration behavior.
/// </summary>
public enum TokenExpiration
{
    Absolute = 0,
    Sliding = 1
} 