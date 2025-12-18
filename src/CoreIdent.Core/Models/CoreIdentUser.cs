namespace CoreIdent.Core.Models;

/// <summary>
/// Represents a user in CoreIdent.
/// </summary>
public class CoreIdentUser
{
    /// <summary>
    /// The user identifier.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// The username (often an email address).
    /// </summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>
    /// Normalized username for lookups.
    /// </summary>
    public string NormalizedUserName { get; set; } = string.Empty;

    /// <summary>
    /// Password hash, if passwords are enabled.
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// Creation time (UTC).
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last update time (UTC).
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}
