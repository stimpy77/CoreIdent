namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity representing a passwordless token (magic link or OTP).
/// </summary>
public sealed class PasswordlessTokenEntity
{
    /// <summary>
    /// Gets or sets the token identifier.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the recipient email/phone value.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the token type.
    /// </summary>
    public string TokenType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the hashed token value.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the UTC time when the token was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC time when the token expires.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets the UTC time when the token was consumed.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }

    /// <summary>
    /// Gets or sets the associated user identifier, if available.
    /// </summary>
    public string? UserId { get; set; }
}
