namespace CoreIdent.Core.Models;

/// <summary>
/// Represents a refresh token issued to a client.
/// </summary>
public class CoreIdentRefreshToken
{
    /// <summary>
    /// Opaque handle used to reference the refresh token.
    /// </summary>
    public string Handle { get; set; } = string.Empty;

    /// <summary>
    /// Subject identifier (user ID). Empty for non-user tokens.
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Client identifier the token was issued to.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Token family identifier for refresh token rotation.
    /// </summary>
    public string? FamilyId { get; set; }

    /// <summary>
    /// Scopes granted to the refresh token.
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
    /// Time the token was consumed (UTC), if applicable.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }

    /// <summary>
    /// Whether the token has been revoked.
    /// </summary>
    public bool IsRevoked { get; set; } = false;
}
