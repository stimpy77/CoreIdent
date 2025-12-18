using System;

namespace CoreIdent.Core.Configuration;

/// <summary>
/// Route configuration options for CoreIdent endpoints.
/// </summary>
public sealed class CoreIdentRouteOptions
{
    /// <summary>
    /// Base path prepended to relative endpoint paths.
    /// </summary>
    public string BasePath { get; set; } = "/auth";

    /// <summary>
    /// Authorization endpoint path.
    /// </summary>
    public string AuthorizePath { get; set; } = "authorize";

    /// <summary>
    /// Token endpoint path.
    /// </summary>
    public string TokenPath { get; set; } = "token";

    /// <summary>
    /// Revocation endpoint path.
    /// </summary>
    public string RevocationPath { get; set; } = "revoke";

    /// <summary>
    /// Introspection endpoint path.
    /// </summary>
    public string IntrospectionPath { get; set; } = "introspect";

    /// <summary>
    /// Optional discovery document path override.
    /// </summary>
    public string? DiscoveryPath { get; set; }

    /// <summary>
    /// Optional JWKS path override.
    /// </summary>
    public string? JwksPath { get; set; }

    /// <summary>
    /// Consent endpoint path.
    /// </summary>
    public string ConsentPath { get; set; } = "consent";

    /// <summary>
    /// User info endpoint path.
    /// </summary>
    public string UserInfoPath { get; set; } = "userinfo";

    /// <summary>
    /// User profile endpoint path.
    /// </summary>
    public string UserProfilePath { get; set; } = "/me";

    /// <summary>
    /// Registration endpoint path.
    /// </summary>
    public string RegisterPath { get; set; } = "register";

    /// <summary>
    /// Login endpoint path.
    /// </summary>
    public string LoginPath { get; set; } = "login";

    /// <summary>
    /// Profile endpoint path.
    /// </summary>
    public string ProfilePath { get; set; } = "profile";

    /// <summary>
    /// Passwordless email start endpoint path.
    /// </summary>
    public string PasswordlessEmailStartPath { get; set; } = "passwordless/email/start";

    /// <summary>
    /// Passwordless email verify endpoint path.
    /// </summary>
    public string PasswordlessEmailVerifyPath { get; set; } = "passwordless/email/verify";

    /// <summary>
    /// Passwordless SMS start endpoint path.
    /// </summary>
    public string PasswordlessSmsStartPath { get; set; } = "passwordless/sms/start";

    /// <summary>
    /// Passwordless SMS verify endpoint path.
    /// </summary>
    public string PasswordlessSmsVerifyPath { get; set; } = "passwordless/sms/verify";

    /// <summary>
    /// Passkey registration options endpoint path.
    /// </summary>
    public string PasskeyRegisterOptionsPath { get; set; } = "passkey/register/options";

    /// <summary>
    /// Passkey registration completion endpoint path.
    /// </summary>
    public string PasskeyRegisterCompletePath { get; set; } = "passkey/register/complete";

    /// <summary>
    /// Passkey authentication options endpoint path.
    /// </summary>
    public string PasskeyAuthenticateOptionsPath { get; set; } = "passkey/authenticate/options";

    /// <summary>
    /// Passkey authentication completion endpoint path.
    /// </summary>
    public string PasskeyAuthenticateCompletePath { get; set; } = "passkey/authenticate/complete";

    /// <summary>
    /// Combines a relative path with <see cref="BasePath"/>.
    /// </summary>
    /// <param name="path">Path to combine.</param>
    /// <returns>A normalized absolute route template.</returns>
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

    /// <summary>
    /// Gets the discovery document path.
    /// </summary>
    /// <param name="options">CoreIdent options.</param>
    /// <returns>The discovery document path.</returns>
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

    /// <summary>
    /// Gets the JWKS path.
    /// </summary>
    /// <param name="options">CoreIdent options.</param>
    /// <returns>The JWKS path.</returns>
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
