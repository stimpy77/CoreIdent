namespace CoreIdent.Core.Models;

public class PasswordlessToken
{
    public string Id { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    public bool Consumed { get; set; }

    public string? UserId { get; set; }
}
