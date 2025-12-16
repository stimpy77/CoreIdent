using CoreIdent.Core.Services;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CoreIdent.Aspire.HealthChecks;

public sealed class SigningKeyProviderHealthCheck(ISigningKeyProvider signingKeyProvider) : IHealthCheck
{
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
