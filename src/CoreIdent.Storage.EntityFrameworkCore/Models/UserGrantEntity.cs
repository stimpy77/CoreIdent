namespace CoreIdent.Storage.EntityFrameworkCore.Models;

public sealed class UserGrantEntity
{
    public string SubjectId { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string ScopesJson { get; set; } = "[]";

    public DateTime CreatedAt { get; set; }

    public DateTime? ExpiresAt { get; set; }
}
