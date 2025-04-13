namespace CoreIdent.Core.Models;
using System.Collections.Generic;
using System.Security.Claims;
using System; // Added for DateTimeOffset

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
    /// A normalized representation of the UserName.
    /// </summary>
    public string? NormalizedUserName { get; set; }

    /// <summary>
    /// Securely hashed password.
    /// </summary>
    public string? PasswordHash { get; set; } // Changed from HashedPassword for convention

    /// <summary>
    /// Navigation property for user claims.
    /// </summary>
    public virtual ICollection<CoreIdentUserClaim> Claims { get; private set; } = new List<CoreIdentUserClaim>();

    /// <summary>
    /// Gets or sets the date and time, in UTC, when any user lockout ends.
    /// </summary>
    /// <remarks>
    /// A value in the past means the user is not locked out.
    /// </remarks>
    public DateTimeOffset? LockoutEnd { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating if the user is locked out.
    /// </summary>
    /// <value>True if the user is locked out, otherwise false.</value>
    /// <remarks>This is a computed property based on LockoutEnd.</remarks>
    public bool IsLockedOut => LockoutEnd.HasValue && LockoutEnd.Value > DateTimeOffset.UtcNow;

    /// <summary>
    /// Gets or sets the number of failed login attempts for the current user.
    /// </summary>
    public int AccessFailedCount { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating if lockout is enabled for this user.
    /// </summary>
    /// <value>True if lockout is enabled, otherwise false.</value>
    public bool LockoutEnabled { get; set; }
}

/// <summary>
/// Represents a claim that a user possesses.
/// </summary>
public class CoreIdentUserClaim
{
    /// <summary>
    /// Gets or sets the identifier for this user claim.
    /// </summary>
    public virtual int Id { get; set; }

    /// <summary>
    /// Gets or sets the primary key of the user associated with this claim.
    /// </summary>
    public virtual string UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the claim type for this claim.
    /// </summary>
    public virtual string? ClaimType { get; set; }

    /// <summary>
    /// Gets or sets the claim value for this claim.
    /// </summary>
    public virtual string? ClaimValue { get; set; }

    /// <summary>
    /// Initializes a new instance of <see cref="CoreIdentUserClaim"/>.
    /// </summary>
    public CoreIdentUserClaim() { }

    /// <summary>
    /// Constructs a new claim with the type and value.
    /// </summary>
    /// <returns></returns>
    public virtual Claim ToClaim()
    {
        return new Claim(ClaimType ?? string.Empty, ClaimValue ?? string.Empty);
    }

    /// <summary>
    /// Initializes by copying ClaimType and ClaimValue from the other claim.
    /// </summary>
    /// <param name="other">The claim to initialize from.</param>
    public virtual void InitializeFromClaim(Claim other)
    {
        ArgumentNullException.ThrowIfNull(other);
        ClaimType = other.Type;
        ClaimValue = other.Value;
    }
}
