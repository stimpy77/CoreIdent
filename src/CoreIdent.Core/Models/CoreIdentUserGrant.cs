namespace CoreIdent.Core.Models;

public sealed class CoreIdentUserGrant
{
    public string SubjectId { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public ICollection<string> Scopes { get; set; } = [];

    public DateTime CreatedAt { get; set; }

    public DateTime? ExpiresAt { get; set; }
}
