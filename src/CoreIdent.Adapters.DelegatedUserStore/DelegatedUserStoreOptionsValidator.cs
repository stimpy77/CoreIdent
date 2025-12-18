using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore;

/// <summary>
/// Validates <see cref="DelegatedUserStoreOptions"/>.
/// </summary>
public sealed class DelegatedUserStoreOptionsValidator : IValidateOptions<DelegatedUserStoreOptions>
{
    /// <summary>
    /// Validates a <see cref="DelegatedUserStoreOptions"/> instance.
    /// </summary>
    /// <param name="name">The name of the options instance being validated.</param>
    /// <param name="options">The options instance being validated.</param>
    /// <returns>A <see cref="ValidateOptionsResult"/> indicating whether the options instance is valid.</returns>
    public ValidateOptionsResult Validate(string? name, DelegatedUserStoreOptions options)
    {
        var errors = new List<string>();

        if (options.FindUserByIdAsync is null)
        {
            errors.Add($"{nameof(DelegatedUserStoreOptions.FindUserByIdAsync)} is required.");
        }

        if (options.FindUserByUsernameAsync is null)
        {
            errors.Add($"{nameof(DelegatedUserStoreOptions.FindUserByUsernameAsync)} is required.");
        }

        if (options.ValidateCredentialsAsync is null)
        {
            errors.Add($"{nameof(DelegatedUserStoreOptions.ValidateCredentialsAsync)} is required.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
