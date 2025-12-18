using CoreIdent.Core.Models;

namespace CoreIdent.Core.Services;

/// <summary>
/// Hashes and verifies user passwords.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes a password for storage.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="password">The plaintext password.</param>
    /// <returns>The hashed password.</returns>
    string HashPassword(CoreIdentUser user, string password);

    /// <summary>
    /// Verifies a password against a stored hash.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="hashedPassword">The stored hash.</param>
    /// <param name="providedPassword">The provided plaintext password.</param>
    /// <returns><see langword="true"/> if the password matches; otherwise <see langword="false"/>.</returns>
    bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword);
}
