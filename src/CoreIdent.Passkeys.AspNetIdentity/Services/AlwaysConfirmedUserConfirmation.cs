using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passkeys.AspNetIdentity.Services;

public sealed class AlwaysConfirmedUserConfirmation<TUser> : IUserConfirmation<TUser>
    where TUser : class
{
    public Task<bool> IsConfirmedAsync(UserManager<TUser> manager, TUser user)
    {
        return Task.FromResult(true);
    }
}
