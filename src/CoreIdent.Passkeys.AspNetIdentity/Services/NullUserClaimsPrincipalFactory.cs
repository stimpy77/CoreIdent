using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passkeys.AspNetIdentity.Services;

public sealed class NullUserClaimsPrincipalFactory : IUserClaimsPrincipalFactory<CoreIdent.Core.Models.CoreIdentUser>
{
    public Task<ClaimsPrincipal> CreateAsync(CoreIdent.Core.Models.CoreIdentUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

        return Task.FromResult(new ClaimsPrincipal(identity));
    }
}
