using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore;

public sealed class DelegatedUserStoreOptionsValidator : IValidateOptions<DelegatedUserStoreOptions>
{
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
