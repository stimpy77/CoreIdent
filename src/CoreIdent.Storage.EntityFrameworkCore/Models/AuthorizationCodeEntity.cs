namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity representing an OAuth 2.0 authorization code.
/// </summary>
public sealed class AuthorizationCodeEntity
{
    /// <summary>
    /// Gets or sets the authorization code handle.
    /// </summary>
    public string Handle { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client identifier.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the subject (user) identifier.
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the redirect URI.
    /// </summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the JSON-serialized list of requested scopes.
    /// </summary>
    public string ScopesJson { get; set; } = "[]";

    /// <summary>
    /// Gets or sets the UTC time when the authorization code was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC time when the authorization code expires.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC time when the authorization code was consumed.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }

    /// <summary>
    /// Gets or sets the nonce, if provided.
    /// </summary>
    public string? Nonce { get; set; }

    /// <summary>
    /// Gets or sets the PKCE code challenge.
    /// </summary>
    public string CodeChallenge { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the PKCE code challenge method.
    /// </summary>
    public string CodeChallengeMethod { get; set; } = string.Empty;
}
