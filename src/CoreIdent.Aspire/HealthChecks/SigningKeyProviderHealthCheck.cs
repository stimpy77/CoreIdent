using CoreIdent.Core.Services;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CoreIdent.Aspire.HealthChecks;

/// <summary>
/// Health check that validates CoreIdent signing keys can be resolved and at least one validation key is available.
/// </summary>
public sealed class SigningKeyProviderHealthCheck(ISigningKeyProvider signingKeyProvider) : IHealthCheck
{
    /// <summary>
    /// Executes the health check.
    /// </summary>
    /// <param name="context">The health check context.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The health check result.</returns>
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var keys = await signingKeyProvider.GetValidationKeysAsync(cancellationToken);
            if (!keys.Any())
            {
                return HealthCheckResult.Unhealthy("No validation keys available.");
            }

            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Failed to read signing keys.", ex);
        }
    }
}
