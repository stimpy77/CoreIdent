using CoreIdent.Core.Models;

namespace CoreIdent.Core.Services;

/// <summary>
/// Provides an abstraction for hashing and verifying passwords.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes the provided password for the given user.
    /// </summary>
    /// <param name="user">The user associated with the password (may be used for context like user ID). Can be null.</param>
    /// <param name="password">The plaintext password to hash.</param>
    /// <returns>The hashed password.</returns>
    string HashPassword(CoreIdentUser? user, string password);

    /// <summary>
    /// Verifies that a provided plaintext password matches the hashed password.
    /// </summary>
    /// <param name="user">The user associated with the password (may be used for context). Can be null.</param>
    /// <param name="hashedPassword">The stored hashed password.</param>
    /// <param name="providedPassword">The plaintext password provided by the user.</param>
    /// <returns>A PasswordVerificationResult indicating success, failure, or if rehash is needed.</returns>
    PasswordVerificationResult VerifyHashedPassword(CoreIdentUser? user, string hashedPassword, string providedPassword);
}

/// <summary>
/// Specifies the results for password verification.
/// Matches Microsoft.AspNetCore.Identity.PasswordVerificationResult
/// </summary>
public enum PasswordVerificationResult
{
    Failed = 0,
    Success = 1,
    SuccessRehashNeeded = 2
}
