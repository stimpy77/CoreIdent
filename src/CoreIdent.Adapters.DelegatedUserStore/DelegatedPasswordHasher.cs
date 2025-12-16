using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore;

public sealed class DelegatedPasswordHasher : IPasswordHasher
{
    private readonly IOptions<DelegatedUserStoreOptions> _options;

    public DelegatedPasswordHasher(IOptions<DelegatedUserStoreOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public string HashPassword(CoreIdentUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        throw new NotSupportedException("Delegated user store does not support password hashing. Passwords are managed by your existing user system.");
    }

    public bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(providedPassword);

        var validate = _options.Value.ValidateCredentialsAsync
            ?? throw new InvalidOperationException($"{nameof(DelegatedUserStoreOptions.ValidateCredentialsAsync)} has not been configured.");

        return validate(user, providedPassword, CancellationToken.None)
            .ConfigureAwait(false)
            .GetAwaiter()
            .GetResult();
    }
}
