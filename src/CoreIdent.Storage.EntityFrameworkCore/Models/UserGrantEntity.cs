namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity representing persisted user consent/grants for a client.
/// </summary>
public sealed class UserGrantEntity
{
    /// <summary>
    /// Gets or sets the subject (user) identifier.
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client identifier.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the JSON-serialized list of granted scopes.
    /// </summary>
    public string ScopesJson { get; set; } = "[]";

    /// <summary>
    /// Gets or sets the UTC time when the grant was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the optional UTC expiration time for the grant.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }
}
