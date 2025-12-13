namespace CoreIdent.Storage.EntityFrameworkCore.Models;

public sealed class AuthorizationCodeEntity
{
    public string Handle { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string SubjectId { get; set; } = string.Empty;

    public string RedirectUri { get; set; } = string.Empty;

    public string ScopesJson { get; set; } = "[]";

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    public DateTime? ConsumedAt { get; set; }

    public string? Nonce { get; set; }

    public string CodeChallenge { get; set; } = string.Empty;

    public string CodeChallengeMethod { get; set; } = string.Empty;
}
