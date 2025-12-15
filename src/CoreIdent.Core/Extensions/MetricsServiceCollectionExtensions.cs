using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CoreIdent.Core.Extensions;

public static class MetricsServiceCollectionExtensions
{
    public static IServiceCollection AddCoreIdentMetrics(this IServiceCollection services)
    {
        return services.AddCoreIdentMetrics(configure: null);
    }

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
