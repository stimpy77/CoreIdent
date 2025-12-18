using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace CoreIdent.OpenApi.Transformers;

internal sealed class CoreIdentOpenApiSchemaTransformer : IOpenApiSchemaTransformer
{
    private static readonly ConcurrentDictionary<string, string?> SummaryCache = new(StringComparer.Ordinal);

    public Task TransformAsync(OpenApiSchema schema, OpenApiSchemaTransformerContext context, CancellationToken cancellationToken)
    {
        if (schema is null)
        {
            return Task.CompletedTask;
        }

        if (!string.IsNullOrWhiteSpace(schema.Description))
        {
            return Task.CompletedTask;
        }

        var type = context.JsonTypeInfo?.Type;
        if (type is null)
        {
            return Task.CompletedTask;
        }

        var typeKey = type.AssemblyQualifiedName;
        if (string.IsNullOrWhiteSpace(typeKey))
        {
            return Task.CompletedTask;
        }

        var summary = SummaryCache.GetOrAdd(typeKey, _ => TryGetTypeSummary(type));
        if (!string.IsNullOrWhiteSpace(summary))
        {
            schema.Description = summary;
        }

        return Task.CompletedTask;
    }

    private static string? TryGetTypeSummary(Type type)
    {
        var doc = TryLoadCoreIdentCoreXml();
        if (doc is null)
        {
            return null;
        }

        var memberName = "T:" + GetXmlDocTypeName(type);

        var summary = doc
            .Root?
            .Element("members")?
            .Elements("member")
            .FirstOrDefault(m => string.Equals((string?)m.Attribute("name"), memberName, StringComparison.Ordinal))?
            .Element("summary")?
            .Value;

        if (string.IsNullOrWhiteSpace(summary))
        {
            return null;
        }

        return NormalizeWhitespace(summary);
    }

    private static XDocument? TryLoadCoreIdentCoreXml()
    {
        // Best-effort: CoreIdent.Core generates an XML doc file when packed; in tests it's copied to output.
        var baseDir = AppContext.BaseDirectory;
        var path = Path.Combine(baseDir, "CoreIdent.Core.xml");

        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            return XDocument.Load(path, LoadOptions.None);
        }
        catch
        {
            return null;
        }
    }

    private static string GetXmlDocTypeName(Type type)
    {
        // Handle nested types
        var fullName = type.FullName ?? type.Name;
        fullName = fullName.Replace('+', '.');

        // Handle generic types: Type`1 becomes Type{T}
        if (!type.IsGenericType)
        {
            return fullName;
        }

        var genericTypeDef = type.GetGenericTypeDefinition();
        var genericFullName = (genericTypeDef.FullName ?? genericTypeDef.Name).Replace('+', '.');

        var tickIndex = genericFullName.IndexOf('`', StringComparison.Ordinal);
        if (tickIndex >= 0)
        {
            genericFullName = genericFullName[..tickIndex];
        }

        var args = type.GetGenericArguments().Select(GetXmlDocTypeName);
        return genericFullName + "{" + string.Join(",", args) + "}";
    }

    private static string NormalizeWhitespace(string value)
    {
        return string.Join(' ', value
            .Split(new[] { '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }
}
