using CoreIdent.Core.Models;
using Microsoft.AspNetCore.Identity; // Required for PasswordHasher
using Microsoft.Extensions.Options;  // Required for IOptions

namespace CoreIdent.Core.Services;

/// <summary>
/// Default implementation of IPasswordHasher using ASP.NET Core Identity's PasswordHasher.
/// </summary>
public class DefaultPasswordHasher : IPasswordHasher
{
    // Use PasswordHasher<CoreIdentUser> to leverage Identity's implementation
    private readonly PasswordHasher<CoreIdentUser> _passwordHasher = new PasswordHasher<CoreIdentUser>(
        new PasswordHasherOptionsAccessor() // Provide default options
        );

    public string HashPassword(CoreIdentUser? user, string password)
    {
        // Identity's hasher expects a non-null user instance. Pass a dummy if null.
        return _passwordHasher.HashPassword(user ?? new CoreIdentUser(), password);
    }

    public PasswordVerificationResult VerifyHashedPassword(CoreIdentUser? user, string hashedPassword, string providedPassword)
    {
        var identityResult = _passwordHasher.VerifyHashedPassword(user ?? new CoreIdentUser(), hashedPassword, providedPassword);

        // Map Identity's enum to CoreIdent's enum
        return identityResult switch
        {
            Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success => PasswordVerificationResult.Success,
            Microsoft.AspNetCore.Identity.PasswordVerificationResult.SuccessRehashNeeded => PasswordVerificationResult.SuccessRehashNeeded,
            _ => PasswordVerificationResult.Failed,
        };
    }

    // Helper class to provide PasswordHasherOptions using defaults.
    // ASP.NET Core Identity defaults are generally secure (V3, PBKDF2-HMAC-SHA256, 100k iterations as of .NET 6+)
    private sealed class PasswordHasherOptionsAccessor : IOptions<PasswordHasherOptions>
    {
        public PasswordHasherOptions Value { get; } = new PasswordHasherOptions
        {
            // Explicitly setting V3 for clarity, though it's often the default.
             CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3
            // IterationCount = 100000; // Default for V3, can override if needed
        };
    }
}
