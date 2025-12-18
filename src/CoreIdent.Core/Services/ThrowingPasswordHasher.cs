using CoreIdent.Core.Models;

namespace CoreIdent.Core.Services;

/// <summary>
/// Fallback <see cref="IPasswordHasher"/> that throws when no implementation is configured.
/// </summary>
public sealed class ThrowingPasswordHasher : IPasswordHasher
{
    /// <inheritdoc />
    public string HashPassword(CoreIdentUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        throw new InvalidOperationException("No IPasswordHasher has been configured.");
    }

    /// <inheritdoc />
    public bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashedPassword);
        ArgumentException.ThrowIfNullOrWhiteSpace(providedPassword);

        throw new InvalidOperationException("No IPasswordHasher has been configured.");
    }
}
