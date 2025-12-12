using System;
using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Configuration;

public sealed class CoreIdentOptionsValidator : IValidateOptions<CoreIdentOptions>
{
    public ValidateOptionsResult Validate(string? name, CoreIdentOptions options)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            errors.Add($"{nameof(CoreIdentOptions.Issuer)} is required.");
        }
        else if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out _))
        {
            errors.Add($"{nameof(CoreIdentOptions.Issuer)} must be a valid absolute URI.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            errors.Add($"{nameof(CoreIdentOptions.Audience)} is required.");
        }
        else if (!Uri.TryCreate(options.Audience, UriKind.Absolute, out _))
        {
            errors.Add($"{nameof(CoreIdentOptions.Audience)} must be a valid absolute URI.");
        }

        if (options.AccessTokenLifetime <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(CoreIdentOptions.AccessTokenLifetime)} must be a positive duration.");
        }

        if (options.RefreshTokenLifetime <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(CoreIdentOptions.RefreshTokenLifetime)} must be a positive duration.");
        }

        if (options.RefreshTokenLifetime <= options.AccessTokenLifetime)
        {
            errors.Add($"{nameof(CoreIdentOptions.RefreshTokenLifetime)} must be greater than {nameof(CoreIdentOptions.AccessTokenLifetime)}.");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }
}
