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
    /// Recipient email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Recipient identifier.
    /// </summary>
    public string Recipient
    {
        get => Email;
        set => Email = value;
    }

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
