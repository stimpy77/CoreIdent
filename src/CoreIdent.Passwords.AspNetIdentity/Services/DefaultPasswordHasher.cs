using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passwords.AspNetIdentity.Services;

/// <summary>
/// Default CoreIdent password hasher implementation backed by ASP.NET Core Identity's <see cref="PasswordHasher{TUser}"/>.
/// </summary>
public sealed class DefaultPasswordHasher : IPasswordHasher
{
    private readonly PasswordHasher<CoreIdentUser> _hasher = new();

    /// <summary>
    /// Hashes a plaintext password for the specified user.
    /// </summary>
    /// <param name="user">The user the password is being hashed for.</param>
    /// <param name="password">The plaintext password.</param>
    /// <returns>The hashed password string.</returns>
    public string HashPassword(CoreIdentUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        return _hasher.HashPassword(user, password);
    }

    /// <summary>
    /// Verifies a provided password against a previously hashed password.
    /// </summary>
    /// <param name="user">The user the password belongs to.</param>
    /// <param name="hashedPassword">The stored hashed password.</param>
    /// <param name="providedPassword">The plaintext password to verify.</param>
    /// <returns><see langword="true"/> if the password matches; otherwise <see langword="false"/>.</returns>
    public bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashedPassword);
        ArgumentException.ThrowIfNullOrWhiteSpace(providedPassword);

        var result = _hasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
        return result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded;
    }
}
