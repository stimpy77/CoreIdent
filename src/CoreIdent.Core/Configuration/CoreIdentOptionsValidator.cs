using System;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Configuration;

/// <summary>
/// Validates CoreIdentOptions upon startup.
/// </summary>
public class CoreIdentOptionsValidator : IValidateOptions<CoreIdentOptions>
{
    // Consider making this configurable or basing it on the intended algorithm (HS256 requires >= 256 bits)
    private const int MinSigningKeyLengthBytes = 32;

    public ValidateOptionsResult Validate(string? name, CoreIdentOptions options)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            errors.Add($"{nameof(options.Issuer)} is required.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            errors.Add($"{nameof(options.Audience)} is required.");
        }

        if (string.IsNullOrWhiteSpace(options.SigningKeySecret))
        {
            errors.Add($"{nameof(options.SigningKeySecret)} is required.");
        }
        // Assuming UTF8 encoding for simplicity, check byte length. A more robust check might be needed
        // depending on how the key is generated/encoded.
        else if (System.Text.Encoding.UTF8.GetByteCount(options.SigningKeySecret) < MinSigningKeyLengthBytes)
        {
             errors.Add($"{nameof(options.SigningKeySecret)} is too short. Minimum length is {MinSigningKeyLengthBytes} bytes (e.g., 32 ASCII characters for HS256).");
        }


        if (options.AccessTokenLifetime <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(options.AccessTokenLifetime)} must be a positive duration.");
        }

        if (options.RefreshTokenLifetime <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(options.RefreshTokenLifetime)} must be a positive duration.");
        }

        if (errors.Any())
        {
            return ValidateOptionsResult.Fail(errors);
        }

        return ValidateOptionsResult.Success;
    }
}