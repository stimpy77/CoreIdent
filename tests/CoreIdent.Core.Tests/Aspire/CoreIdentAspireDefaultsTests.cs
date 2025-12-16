using CoreIdent.Aspire;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Shouldly;

namespace CoreIdent.Core.Tests.Aspire;

public sealed class CoreIdentAspireDefaultsTests
{
    [Fact]
    public async Task AddCoreIdentDefaults_registers_expected_services()
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            EnvironmentName = "Development"
        });

        builder.Services.AddCoreIdent(o =>
        {
            o.Issuer = "https://issuer.example";
            o.Audience = "https://audience.example";
        });

        builder.Services.AddSigningKey(o => o.UseSymmetric("0123456789abcdef0123456789abcdef"));

        builder.AddCoreIdentDefaults();

        using var host = builder.Build();

        var healthChecks = host.Services.GetRequiredService<HealthCheckService>();
        healthChecks.ShouldNotBeNull("HealthCheckService should be registered by AddCoreIdentDefaults.");
        host.Services.GetRequiredService<ICoreIdentMetrics>().ShouldNotBeNull("ICoreIdentMetrics should be registered.");

        host.Services.GetService<MeterProvider>().ShouldNotBeNull("OpenTelemetry MeterProvider should be registered.");
        host.Services.GetService<TracerProvider>().ShouldNotBeNull("OpenTelemetry TracerProvider should be registered.");

        var report = await healthChecks.CheckHealthAsync();
        report.Status.ShouldBe(HealthStatus.Healthy);
        report.Entries.ShouldContainKey("self");
        report.Entries.ShouldContainKey("coreident.signing_keys");
        report.Entries.ShouldContainKey("coreident.external_dependencies");
        report.Entries["self"].Status.ShouldBe(HealthStatus.Healthy);
        report.Entries["coreident.signing_keys"].Status.ShouldBe(HealthStatus.Healthy);
        report.Entries["coreident.external_dependencies"].Status.ShouldBe(HealthStatus.Healthy);
    }
}
