using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Adapters.DelegatedUserStore;

public sealed class DelegatedUserStoreOptions
{
    public Func<string, CancellationToken, Task<CoreIdentUser?>>? FindUserByIdAsync { get; set; }

    public Func<string, CancellationToken, Task<CoreIdentUser?>>? FindUserByUsernameAsync { get; set; }

    public Func<CoreIdentUser, string, CancellationToken, Task<bool>>? ValidateCredentialsAsync { get; set; }

    public Func<string, CancellationToken, Task<IReadOnlyList<Claim>>>? GetClaimsAsync { get; set; }
}
