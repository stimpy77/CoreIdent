using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passkeys.AspNetIdentity.Services;

/// <summary>
/// Minimal <see cref="IUserClaimsPrincipalFactory{TUser}"/> implementation for CoreIdent users.
/// </summary>
public sealed class NullUserClaimsPrincipalFactory : IUserClaimsPrincipalFactory<CoreIdent.Core.Models.CoreIdentUser>
{
    /// <summary>
    /// Creates a <see cref="ClaimsPrincipal"/> from the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to create a <see cref="ClaimsPrincipal"/> for.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the created <see cref="ClaimsPrincipal"/>.</returns>
    public Task<ClaimsPrincipal> CreateAsync(CoreIdent.Core.Models.CoreIdentUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

        return Task.FromResult(new ClaimsPrincipal(identity));
    }
}
