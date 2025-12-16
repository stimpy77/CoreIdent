using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CoreIdent.Aspire.HealthChecks;

public interface ICoreIdentExternalDependencyProbe
{
    string Name { get; }

    Task<HealthCheckResult> CheckAsync(CancellationToken ct);
}

public sealed class ExternalDependencyHealthCheck(IServiceProvider services) : IHealthCheck
{
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
