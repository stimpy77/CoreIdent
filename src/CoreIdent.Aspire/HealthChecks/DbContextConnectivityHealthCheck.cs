using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CoreIdent.Aspire.HealthChecks;

/// <summary>
/// Health check that validates the application can connect to the configured database.
/// </summary>
/// <typeparam name="TDbContext">The EF Core <see cref="DbContext"/> type to check connectivity for.</typeparam>
public sealed class DbContextConnectivityHealthCheck<TDbContext>(TDbContext dbContext) : IHealthCheck where TDbContext : DbContext
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
            var canConnect = await dbContext.Database.CanConnectAsync(cancellationToken);
            return canConnect ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy("Database connection check failed.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database connection check failed.", ex);
        }
    }
}
