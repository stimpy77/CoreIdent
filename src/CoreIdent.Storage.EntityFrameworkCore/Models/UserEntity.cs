namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity for storing CoreIdent users.
/// </summary>
public class UserEntity
{
    /// <summary>
    /// Gets or sets the user identifier.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the normalized username used for lookups.
    /// </summary>
    public string NormalizedUserName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the hashed password, if applicable.
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// Gets or sets the JSON-serialized list of user claims.
    /// </summary>
    public string ClaimsJson { get; set; } = "[]";

    /// <summary>
    /// Gets or sets the UTC time when the user was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC time when the user was last updated.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}
