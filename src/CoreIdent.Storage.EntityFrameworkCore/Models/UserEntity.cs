namespace CoreIdent.Storage.EntityFrameworkCore.Models;

public class UserEntity
{
    public string Id { get; set; } = string.Empty;

    public string UserName { get; set; } = string.Empty;

    public string NormalizedUserName { get; set; } = string.Empty;

    public string? PasswordHash { get; set; }

    public string ClaimsJson { get; set; } = "[]";

    public DateTime CreatedAt { get; set; }

    public DateTime? UpdatedAt { get; set; }
}
