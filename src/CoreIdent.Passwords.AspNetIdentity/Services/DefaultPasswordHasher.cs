using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passwords.AspNetIdentity.Services;

public sealed class DefaultPasswordHasher : IPasswordHasher
{
    private readonly PasswordHasher<CoreIdentUser> _hasher = new();

    public string HashPassword(CoreIdentUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        return _hasher.HashPassword(user, password);
    }

    public bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashedPassword);
        ArgumentException.ThrowIfNullOrWhiteSpace(providedPassword);

        var result = _hasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
        return result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded;
    }
}
