using CoreIdent.Core.Models;

namespace CoreIdent.Core.Services;

public sealed class ThrowingPasswordHasher : IPasswordHasher
{
    public string HashPassword(CoreIdentUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        throw new InvalidOperationException("No IPasswordHasher has been configured.");
    }

    public bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashedPassword);
        ArgumentException.ThrowIfNullOrWhiteSpace(providedPassword);

        throw new InvalidOperationException("No IPasswordHasher has been configured.");
    }
}
