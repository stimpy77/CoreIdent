namespace CoreIdent.Core.Models;

/// <summary>
/// Basic user model for CoreIdent.
/// </summary>
public class CoreIdentUser
{
    /// <summary>
    /// Unique identifier for the user (e.g., GUID).
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString(); // Default to new Guid

    /// <summary>
    /// Primary username or email used for login. Should be unique.
    /// </summary>
    public string? UserName { get; set; } // Changed from Username to UserName for convention

    /// <summary>
    /// Securely hashed password.
    /// </summary>
    public string? PasswordHash { get; set; } // Changed from HashedPassword for convention

    // Additional properties (Claims, Lockout, etc.) will be added in later phases
}
