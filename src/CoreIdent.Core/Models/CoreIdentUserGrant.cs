namespace CoreIdent.Core.Models;

/// <summary>
/// Represents a persisted user grant/consent for a client.
/// </summary>
public sealed class CoreIdentUserGrant
{
    /// <summary>
    /// Subject identifier (user ID).
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Client identifier.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Scopes that were granted.
    /// </summary>
    public ICollection<string> Scopes { get; set; } = [];

    /// <summary>
    /// Creation time (UTC).
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Optional expiration time (UTC).
    /// </summary>
    public DateTime? ExpiresAt { get; set; }
}
