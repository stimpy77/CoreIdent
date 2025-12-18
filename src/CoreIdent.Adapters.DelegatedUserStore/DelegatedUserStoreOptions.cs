using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Adapters.DelegatedUserStore;

/// <summary>
/// Options for configuring the delegated user store adapter.
/// </summary>
public sealed class DelegatedUserStoreOptions
{
    /// <summary>
    /// Gets or sets the delegate used to find a user by identifier.
    /// </summary>
    public Func<string, CancellationToken, Task<CoreIdentUser?>>? FindUserByIdAsync { get; set; }

    /// <summary>
    /// Gets or sets the delegate used to find a user by username.
    /// </summary>
    public Func<string, CancellationToken, Task<CoreIdentUser?>>? FindUserByUsernameAsync { get; set; }

    /// <summary>
    /// Gets or sets the delegate used to validate user credentials.
    /// </summary>
    public Func<CoreIdentUser, string, CancellationToken, Task<bool>>? ValidateCredentialsAsync { get; set; }

    /// <summary>
    /// Gets or sets the delegate used to retrieve claims for a subject.
    /// </summary>
    public Func<string, CancellationToken, Task<IReadOnlyList<Claim>>>? GetClaimsAsync { get; set; }
}
