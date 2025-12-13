using System;

namespace CoreIdent.Core.Configuration;

public sealed class CoreIdentRouteOptions
{
    public string BasePath { get; set; } = "/auth";

    public string AuthorizePath { get; set; } = "authorize";

    public string TokenPath { get; set; } = "token";

    public string RevocationPath { get; set; } = "revoke";

    public string IntrospectionPath { get; set; } = "introspect";

    public string? DiscoveryPath { get; set; }

    public string? JwksPath { get; set; }

    public string ConsentPath { get; set; } = "consent";

    public string UserInfoPath { get; set; } = "userinfo";

    public string UserProfilePath { get; set; } = "/me";

    public string CombineWithBase(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be null or whitespace.", nameof(path));
        }

        if (path.StartsWith("/", StringComparison.Ordinal))
        {
            return NormalizeRouteTemplate(path);
        }

        var basePath = NormalizeBasePath(BasePath);
        return NormalizeRouteTemplate($"{basePath}/{path}");
    }

    public string GetDiscoveryPath(CoreIdentOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrWhiteSpace(DiscoveryPath))
        {
            return NormalizeRouteTemplate(DiscoveryPath);
        }

        var issuer = GetValidatedIssuer(options);
        return NormalizeRouteTemplate($"{issuer}/.well-known/openid-configuration");
    }

    public string GetJwksPath(CoreIdentOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrWhiteSpace(JwksPath))
        {
            return NormalizeRouteTemplate(JwksPath);
        }

        var issuer = GetValidatedIssuer(options);
        return NormalizeRouteTemplate($"{issuer}/.well-known/jwks.json");
    }

    private static string GetValidatedIssuer(CoreIdentOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            throw new InvalidOperationException($"{nameof(CoreIdentOptions.Issuer)} must be configured.");
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuerUri))
        {
            throw new InvalidOperationException($"{nameof(CoreIdentOptions.Issuer)} must be a valid absolute URI.");
        }

        var path = issuerUri.AbsolutePath;
        if (string.IsNullOrWhiteSpace(path) || path == "/")
        {
            return string.Empty;
        }

        return path.TrimEnd('/');
    }

    private static string NormalizeBasePath(string basePath)
    {
        if (string.IsNullOrWhiteSpace(basePath) || !basePath.StartsWith("/", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{nameof(BasePath)} must be configured and start with '/'. Current value: '{basePath}'");
        }

        return NormalizeRouteTemplate(basePath);
    }

    private static string NormalizeRouteTemplate(string template)
    {
        var trimmed = template.Trim();

        if (!trimmed.StartsWith("/", StringComparison.Ordinal))
        {
            trimmed = "/" + trimmed;
        }

        while (trimmed.Contains("//", StringComparison.Ordinal))
        {
            trimmed = trimmed.Replace("//", "/", StringComparison.Ordinal);
        }

        if (trimmed.Length > 1 && trimmed.EndsWith("/", StringComparison.Ordinal))
        {
            trimmed = trimmed.TrimEnd('/');
        }

        return trimmed;
    }
}
