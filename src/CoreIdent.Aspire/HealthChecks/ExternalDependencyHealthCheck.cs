using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CoreIdent.Aspire.HealthChecks;

/// <summary>
/// Represents a probe for an external dependency that should be surfaced via health checks.
/// </summary>
public interface ICoreIdentExternalDependencyProbe
{
    /// <summary>
    /// Gets a human-readable name for the dependency.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Checks the external dependency.
    /// </summary>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The health check result.</returns>
    Task<HealthCheckResult> CheckAsync(CancellationToken ct);
}

/// <summary>
/// Health check that aggregates registered <see cref="ICoreIdentExternalDependencyProbe"/> implementations.
/// </summary>
public sealed class ExternalDependencyHealthCheck(IServiceProvider services) : IHealthCheck
{
    /// <summary>
    /// Executes the health check.
    /// </summary>
    /// <param name="context">The health check context.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The health check result.</returns>
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var probes = services.GetServices<ICoreIdentExternalDependencyProbe>().ToList();

        if (probes.Count == 0)
        {
            return HealthCheckResult.Healthy();
        }

        var failures = new List<string>();

        foreach (var probe in probes)
        {
            HealthCheckResult result;
            try
            {
                result = await probe.CheckAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                result = HealthCheckResult.Unhealthy("External dependency probe failed.", ex);
            }

            if (result.Status != HealthStatus.Healthy)
            {
                failures.Add(probe.Name);
            }
        }

        return failures.Count == 0
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy($"External dependency probes failing: {string.Join(", ", failures)}");
    }
}
