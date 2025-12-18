namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity for storing refresh tokens.
/// </summary>
public class RefreshTokenEntity
{
    /// <summary>
    /// Gets or sets the refresh token handle.
    /// </summary>
    public string Handle { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the subject (user) identifier.
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the client identifier.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the refresh token family identifier, if used.
    /// </summary>
    public string? FamilyId { get; set; }
    /// <summary>
    /// Gets or sets the JSON-serialized list of scopes.
    /// </summary>
    public string ScopesJson { get; set; } = "[]";
    /// <summary>
    /// Gets or sets the UTC time when the refresh token was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }
    /// <summary>
    /// Gets or sets the UTC time when the refresh token expires.
    /// </summary>
    public DateTime ExpiresAt { get; set; }
    /// <summary>
    /// Gets or sets the UTC time when the refresh token was consumed.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }
    /// <summary>
    /// Gets or sets a value indicating whether the refresh token has been revoked.
    /// </summary>
    public bool IsRevoked { get; set; }
}
