using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Service registration helpers for CoreIdent metrics.
/// </summary>
public static class MetricsServiceCollectionExtensions
{
    /// <summary>
    /// Registers the default <see cref="ICoreIdentMetrics"/> implementation.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddCoreIdentMetrics(this IServiceCollection services)
    {
        return services.AddCoreIdentMetrics(configure: null);
    }

    /// <summary>
    /// Registers the default <see cref="ICoreIdentMetrics"/> implementation with optional configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional configuration callback.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddCoreIdentMetrics(this IServiceCollection services, Action<CoreIdentMetricsOptions>? configure)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configure is not null)
        {
            services.Configure(configure);
        }
        else
        {
            services.AddOptions<CoreIdentMetricsOptions>();
        }

        services.Replace(ServiceDescriptor.Singleton<ICoreIdentMetrics, CoreIdentMetrics>());

        return services;
    }
}
