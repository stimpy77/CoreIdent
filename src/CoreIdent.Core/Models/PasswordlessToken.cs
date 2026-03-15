namespace CoreIdent.Core.Models;

/// <summary>
/// Represents a passwordless authentication token.
/// </summary>
public class PasswordlessToken
{
    /// <summary>
    /// Token identifier.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// The recipient of the passwordless token — an email address (for magic links)
    /// or phone number (for SMS OTP). Distinguished by <see cref="TokenType"/>.
    /// </summary>
    public string Recipient { get; set; } = string.Empty;

    /// <summary>
    /// Token type identifier.
    /// </summary>
    public string TokenType { get; set; } = string.Empty;

    /// <summary>
    /// Hash of the token value.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// Creation time (UTC).
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Expiration time (UTC).
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Whether the token has been consumed.
    /// </summary>
    public bool Consumed { get; set; }

    /// <summary>
    /// Optional user identifier associated with the token.
    /// </summary>
    public string? UserId { get; set; }
}
