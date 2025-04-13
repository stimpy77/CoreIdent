using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Adapters.DelegatedUserStore;

/// <summary>
/// Options for configuring the DelegatedUserStore.
/// Provide delegates to integrate with an external user management system.
/// </summary>
public sealed class DelegatedUserStoreOptions
{
    /// <summary>
    /// Delegate to find a user by their unique ID. Required for most operations.
    /// </summary>
    public Func<string, CancellationToken, Task<CoreIdentUser?>>? FindUserByIdAsync { get; set; }

    /// <summary>
    /// Delegate to find a user by their username. Required for login.
    /// </summary>
    public Func<string, CancellationToken, Task<CoreIdentUser?>>? FindUserByUsernameAsync { get; set; }

    /// <summary>
    /// Delegate to validate a user's credentials (e.g., username and password). Required for login.
    /// </summary>
    public Func<string, string, CancellationToken, Task<bool>>? ValidateCredentialsAsync { get; set; }

    /// <summary>
    /// Optional delegate to retrieve claims for a user. If not provided, only basic claims might be generated.
    /// </summary>
    public Func<CoreIdentUser, CancellationToken, Task<IList<Claim>>>? GetClaimsAsync { get; set; }

    // Note: Other IUserStore methods like CreateAsync, UpdateAsync, DeleteAsync, etc.,
    // are intentionally omitted as this adapter primarily focuses on read operations
    // suitable for integrating with an existing, separately managed user store.
    // Implementations for those methods in DelegatedUserStore will likely throw NotImplementedException.
} 