using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passkeys.AspNetIdentity.Services;

/// <summary>
/// User confirmation implementation that always treats users as confirmed.
/// </summary>
/// <typeparam name="TUser">The user type.</typeparam>
public sealed class AlwaysConfirmedUserConfirmation<TUser> : IUserConfirmation<TUser>
    where TUser : class
{
    /// <inheritdoc />
    public Task<bool> IsConfirmedAsync(UserManager<TUser> manager, TUser user)
    {
        return Task.FromResult(true);
    }
}
