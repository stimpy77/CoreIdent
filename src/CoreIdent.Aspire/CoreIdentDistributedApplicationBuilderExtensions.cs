using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

namespace CoreIdent.Aspire;

/// <summary>
/// Aspire helper extensions for adding CoreIdent projects to a distributed application.
/// </summary>
public static class CoreIdentDistributedApplicationBuilderExtensions
{
    /// <summary>
    /// Adds a CoreIdent project resource to the distributed application and configures an HTTP health check.
    /// </summary>
    /// <typeparam name="TProject">The Aspire project metadata type.</typeparam>
    /// <param name="builder">The distributed application builder.</param>
    /// <param name="name">The resource name.</param>
    /// <param name="healthPath">The HTTP path used for the health check.</param>
    /// <param name="statusCode">The expected HTTP status code for a healthy response.</param>
    /// <param name="endpointName">An optional endpoint name to associate with the health check.</param>
    /// <returns>The project resource builder.</returns>
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
