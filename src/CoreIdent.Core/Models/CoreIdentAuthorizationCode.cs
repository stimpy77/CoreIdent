namespace CoreIdent.Core.Models;

/// <summary>
/// Represents an OAuth 2.0 authorization code.
/// </summary>
public sealed class CoreIdentAuthorizationCode
{
    /// <summary>
    /// Opaque handle used to reference the authorization code.
    /// </summary>
    public string Handle { get; set; } = string.Empty;

    /// <summary>
    /// Client identifier the code was issued to.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Subject identifier (user ID).
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Redirect URI associated with the code.
    /// </summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>
    /// Scopes granted to the authorization code.
    /// </summary>
    public ICollection<string> Scopes { get; set; } = [];

    /// <summary>
    /// Creation time (UTC).
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Expiration time (UTC).
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Time the code was consumed (UTC), if applicable.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }

    /// <summary>
    /// Optional nonce for ID token issuance.
    /// </summary>
    public string? Nonce { get; set; }

    /// <summary>
    /// PKCE code challenge.
    /// </summary>
    public string CodeChallenge { get; set; } = string.Empty;

    /// <summary>
    /// PKCE code challenge method.
    /// </summary>
    public string CodeChallengeMethod { get; set; } = string.Empty;
}
