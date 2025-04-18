using System;
using System.Collections.Generic;
using System.Linq;
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
        // Skip strict validations in development
        var envName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var isDevelopment = string.Equals(envName, "Development", StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            errors.Add($"{nameof(options.Issuer)} is required.");
        }
        else if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuerUri))
        {
            errors.Add($"{nameof(options.Issuer)} must be a valid absolute URI.");
        }
        else if (!isDevelopment && issuerUri.Scheme == Uri.UriSchemeHttp && !issuerUri.IsLoopback)
        {
            errors.Add($"{nameof(options.Issuer)} must use HTTPS scheme unless it's a loopback address.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            errors.Add($"{nameof(options.Audience)} is required.");
        }
        else if (!Uri.TryCreate(options.Audience, UriKind.Absolute, out var audienceUri))
        {
            errors.Add($"{nameof(options.Audience)} must be a valid absolute URI.");
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
        else if (!isDevelopment && options.RefreshTokenLifetime <= options.AccessTokenLifetime)
        {
            errors.Add($"{nameof(options.RefreshTokenLifetime)} must be strictly greater than {nameof(options.AccessTokenLifetime)}.");
        }
        if (!isDevelopment && options.AccessTokenLifetime > TimeSpan.FromDays(1))
        {
            errors.Add($"{nameof(options.AccessTokenLifetime)} must be no more than 1 day.");
        }
        if (!isDevelopment && options.RefreshTokenLifetime > TimeSpan.FromDays(90))
        {
            errors.Add($"{nameof(options.RefreshTokenLifetime)} must be no more than 90 days.");
        }

        // Validate that ConsumedTokenRetentionPeriod, if specified, is non-negative
        if (options.ConsumedTokenRetentionPeriod.HasValue && options.ConsumedTokenRetentionPeriod.Value < TimeSpan.Zero)
        {
            errors.Add($"{nameof(options.ConsumedTokenRetentionPeriod)} must be non-negative.");
        }

        // Validate token security options
        if (options.TokenSecurity == null)
        {
            errors.Add($"{nameof(options.TokenSecurity)} cannot be null.");
        }
        else
        {
            // Validate token theft detection mode is a valid enum value
            if (!Enum.IsDefined(typeof(TokenTheftDetectionMode), options.TokenSecurity.TokenTheftDetectionMode))
            {
                errors.Add($"{nameof(options.TokenSecurity.TokenTheftDetectionMode)} must be a valid {nameof(TokenTheftDetectionMode)} value.");
            }
            
            // Ensure token family tracking is enabled when RevokeFamily mode is set
            if (options.TokenSecurity.TokenTheftDetectionMode == TokenTheftDetectionMode.RevokeFamily && 
                !options.TokenSecurity.EnableTokenFamilyTracking)
            {
                errors.Add($"{nameof(options.TokenSecurity.EnableTokenFamilyTracking)} must be true when {nameof(options.TokenSecurity.TokenTheftDetectionMode)} is set to {nameof(TokenTheftDetectionMode.RevokeFamily)}.");
            }
        }

        if (errors.Any())
        {
            return ValidateOptionsResult.Fail(errors);
        }

        return ValidateOptionsResult.Success;
    }
}