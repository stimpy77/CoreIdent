namespace CoreIdent.Core.Models;

public class CoreIdentRefreshToken
{
    public string Handle { get; set; } = string.Empty;
    public string SubjectId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string? FamilyId { get; set; }
    public ICollection<string> Scopes { get; set; } = [];
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
    public bool IsRevoked { get; set; } = false;
}
