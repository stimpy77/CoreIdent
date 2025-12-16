using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

namespace CoreIdent.Aspire;

public static class CoreIdentDistributedApplicationBuilderExtensions
{
    public static IResourceBuilder<ProjectResource> AddCoreIdentProject<TProject>(
        this IDistributedApplicationBuilder builder,
        string name,
        string? healthPath = "/health",
        int? statusCode = 200,
        string? endpointName = null)
        where TProject : IProjectMetadata, new()
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var project = builder.AddProject<TProject>(name);

        project.WithHttpHealthCheck(path: healthPath, statusCode: statusCode, endpointName: endpointName);

        return project;
    }
}
