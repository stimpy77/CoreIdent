namespace CoreIdent.OpenApi.Configuration;

/// <summary>
/// Options for configuring CoreIdent OpenAPI document generation.
/// </summary>
public sealed class CoreIdentOpenApiOptions
{
    /// <summary>
    /// The OpenAPI document title.
    /// </summary>
    public string DocumentTitle { get; set; } = "CoreIdent API";

    /// <summary>
    /// The OpenAPI document version.
    /// </summary>
    public string DocumentVersion { get; set; } = "v1";

    /// <summary>
    /// The HTTP route where the OpenAPI JSON document is served.
    /// </summary>
    public string OpenApiRoute { get; set; } = "/openapi/v1.json";

    /// <summary>
    /// When <see langword="true"/>, include XML documentation (when available) in the generated OpenAPI document.
    /// </summary>
    public bool IncludeXmlComments { get; set; } = true;

    /// <summary>
    /// When <see langword="true"/>, include OpenAPI security scheme definitions in the document.
    /// </summary>
    public bool IncludeSecurityDefinitions { get; set; } = true;
}
