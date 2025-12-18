using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore;

/// <summary>
/// Password hasher implementation that delegates credential validation to the host via <see cref="DelegatedUserStoreOptions"/>.
/// </summary>
public sealed class DelegatedPasswordHasher : IPasswordHasher
{
    private readonly IOptions<DelegatedUserStoreOptions> _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegatedPasswordHasher"/> class.
    /// </summary>
    /// <param name="options">The delegated user store options.</param>
    public DelegatedPasswordHasher(IOptions<DelegatedUserStoreOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public string HashPassword(CoreIdentUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        throw new NotSupportedException("Delegated user store does not support password hashing. Passwords are managed by your existing user system.");
    }

    /// <inheritdoc />
    public bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(providedPassword);

        var validate = _options.Value.ValidateCredentials
            ?? throw new InvalidOperationException($"{nameof(DelegatedUserStoreOptions.ValidateCredentials)} has not been configured.");

        return validate(user, providedPassword);
    }
}
