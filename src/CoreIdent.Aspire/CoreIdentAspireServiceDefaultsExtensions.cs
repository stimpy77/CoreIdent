using CoreIdent.Core.Extensions;
using CoreIdent.Core.Observability;
using CoreIdent.Core.Services;
using CoreIdent.Aspire.HealthChecks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace CoreIdent.Aspire;

public static class CoreIdentAspireServiceDefaultsExtensions
{
    private static readonly PathString HealthEndpointPath = new("/health");
    private static readonly PathString AlivenessEndpointPath = new("/alive");

    public static TBuilder AddCoreIdentDefaults<TBuilder>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddCoreIdentMetrics();

        builder.ConfigureCoreIdentOpenTelemetry();

        builder.AddCoreIdentDefaultHealthChecks();

        builder.Services.AddServiceDiscovery();

        builder.Services.ConfigureHttpClientDefaults(http =>
        {
            http.AddStandardResilienceHandler();
            http.AddServiceDiscovery();
        });

        return builder;
    }

    public static TBuilder AddCoreIdentDbContextHealthCheck<TBuilder, TDbContext>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
        where TDbContext : Microsoft.EntityFrameworkCore.DbContext
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddHealthChecks()
            .AddCheck<DbContextConnectivityHealthCheck<TDbContext>>("coreident.db");

        return builder;
    }

    public static WebApplication MapCoreIdentDefaultEndpoints(this WebApplication app, bool includeProduction = false)
    {
        ArgumentNullException.ThrowIfNull(app);

        if (includeProduction || app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing"))
        {
            app.MapHealthChecks(HealthEndpointPath);

            app.MapHealthChecks(AlivenessEndpointPath, new HealthCheckOptions
            {
                Predicate = r => r.Tags.Contains("live")
            });
        }

        return app;
    }

    private static TBuilder ConfigureCoreIdentOpenTelemetry<TBuilder>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
    {
        var useOtlpExporter = !string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]);

        builder.Services.AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics.AddAspNetCoreInstrumentation();
                metrics.AddHttpClientInstrumentation();
                metrics.AddRuntimeInstrumentation();
                metrics.AddMeter(CoreIdentMetrics.MeterName);

                if (useOtlpExporter)
                {
                    metrics.AddOtlpExporter();
                }
            })
            .WithTracing(tracing =>
            {
                tracing.AddSource(builder.Environment.ApplicationName);
                tracing.AddSource(CoreIdentActivitySource.ActivitySourceName);

                tracing.AddAspNetCoreInstrumentation(options =>
                    options.Filter = context =>
                        !context.Request.Path.StartsWithSegments(HealthEndpointPath)
                        && !context.Request.Path.StartsWithSegments(AlivenessEndpointPath));

                tracing.AddHttpClientInstrumentation();

                if (useOtlpExporter)
                {
                    tracing.AddOtlpExporter();
                }
            });

        return builder;
    }

    private static TBuilder AddCoreIdentDefaultHealthChecks<TBuilder>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
    {
        builder.Services.AddHealthChecks()
            .AddCheck("self", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy(), tags: ["live"])
            .AddCheck<SigningKeyProviderHealthCheck>("coreident.signing_keys")
            .AddCheck<ExternalDependencyHealthCheck>("coreident.external_dependencies");

        return builder;
    }
}
