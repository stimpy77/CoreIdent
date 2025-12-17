# Aspire Integration (Feature 1.6)

This guide describes how to integrate CoreIdent with .NET Aspire (v13+) service defaults.

## Server project

In your CoreIdent host (API/server) project:

- Call `builder.AddCoreIdentDefaults()` to enable:
  - OpenTelemetry tracing and metrics
  - CoreIdent metric export wiring (includes the CoreIdent meter name)
  - Health checks + default endpoints (`/health`, `/alive`)
  - Service discovery + resilient `HttpClient` defaults

- Call `app.MapCoreIdentDefaultEndpoints()` to map health endpoints in `Development` (and `Testing`).

### Minimal server example

```csharp
using CoreIdent.Aspire;
using CoreIdent.Core.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCoreIdent(o =>
{
    o.Issuer = "https://issuer.example";
    o.Audience = "https://resource.example";
});

builder.Services.AddSigningKey(o => o.UseSymmetric("0123456789abcdef0123456789abcdef"));

builder.AddCoreIdentDefaults();

var app = builder.Build();

app.MapCoreIdentDefaultEndpoints();
app.MapCoreIdentEndpoints();

app.Run();
```

### Production note

By default, `MapCoreIdentDefaultEndpoints()` maps `/health` and `/alive` only in `Development` and `Testing`.

If you want these endpoints mapped in production, call:

```csharp
app.MapCoreIdentDefaultEndpoints(includeProduction: true);
```

## AppHost project

In your Aspire AppHost:

- Use `AddCoreIdentProject<TProject>(...)` to add your CoreIdent host project resource and attach an HTTP health check.

### Minimal AppHost example

```csharp
using Aspire.Hosting;
using CoreIdent.Aspire;

var builder = DistributedApplication.CreateBuilder(args);

builder.AddCoreIdentProject<Projects.CoreIdent_TestHost>("coreident");

builder.Build().Run();
```

## Health checks

The CoreIdent Aspire defaults include:

- A liveness check (`self`, tagged `live`)
- Signing key availability check (`coreident.signing_keys`)
- External dependency probes (`coreident.external_dependencies`) via `ICoreIdentExternalDependencyProbe`

The external dependency health check reports `Healthy` when no probes are registered.

If you use EF Core, add a DB connectivity check:

- `builder.AddCoreIdentDbContextHealthCheck<TDbContext>()`

## Tracing

CoreIdent emits spans using an `ActivitySource` named `CoreIdent`.

## Metrics

CoreIdent emits metrics using a `Meter` named `CoreIdent`.

To export telemetry to the Aspire dashboard (or another collector), configure OTLP via the standard environment variable:

- `OTEL_EXPORTER_OTLP_ENDPOINT`

## Logging

This package does not automatically configure OpenTelemetry logging export.

If you want OpenTelemetry logging, configure it explicitly in your host using the OpenTelemetry logging packages.
