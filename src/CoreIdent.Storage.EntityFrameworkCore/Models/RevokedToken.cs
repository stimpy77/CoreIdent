using System;

namespace CoreIdent.Storage.EntityFrameworkCore.Models;

public sealed class RevokedToken
{
    public string Jti { get; set; } = string.Empty;
    public string TokenType { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime RevokedAtUtc { get; set; }
}
