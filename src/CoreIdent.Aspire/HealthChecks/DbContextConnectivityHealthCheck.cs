using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CoreIdent.Aspire.HealthChecks;

public sealed class DbContextConnectivityHealthCheck<TDbContext>(TDbContext dbContext) : IHealthCheck where TDbContext : DbContext
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var canConnect = await dbContext.Database.CanConnectAsync(cancellationToken);
            return canConnect ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy("Database connection check failed.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database connection check failed.", ex);
        }
    }
}
