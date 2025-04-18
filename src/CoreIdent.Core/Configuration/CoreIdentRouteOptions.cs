using System;

namespace CoreIdent.Core.Configuration;

/// <summary>
/// Configures the routes for CoreIdent endpoints.
/// </summary>
public class CoreIdentRouteOptions
{
    /// <summary>
    /// The base path for all CoreIdent endpoints. Defaults to "/auth".
    /// Must start with a '/'.
    /// </summary>
    public string BasePath { get; set; } = "/auth";

    /// <summary>
    /// Path for the user registration endpoint. Defaults to "register". Relative to BasePath.
    /// </summary>
    public string RegisterPath { get; set; } = "register";

    /// <summary>
    /// Path for the user login endpoint. Defaults to "login". Relative to BasePath.
    /// </summary>
    public string LoginPath { get; set; } = "login";

    /// <summary>
    /// Path for the token endpoint (issuance and refresh). Defaults to "token". Relative to BasePath.
    /// </summary>
    public string TokenPath { get; set; } = "token";

    /// <summary>
    /// Path for the token refresh specific endpoint (legacy/alternative). Defaults to "token/refresh". Relative to BasePath.
    /// Note: The main /token endpoint is preferred for refresh grant_type.
    /// </summary>
    public string RefreshTokenPath { get; set; } = "token/refresh";

    /// <summary>
    /// Path for the OAuth/OIDC authorization endpoint. Defaults to "authorize". Relative to BasePath.
    /// </summary>
    public string AuthorizePath { get; set; } = "authorize";

    /// <summary>
    /// Path for the OIDC UserInfo endpoint. Defaults to "userinfo". Relative to BasePath.
    /// </summary>
    public string UserInfoPath { get; set; } = "userinfo"; // Not yet implemented

    /// <summary>
    /// Path for the OIDC Discovery configuration endpoint. Defaults to ".well-known/openid-configuration". Relative to the root, not BasePath.
    /// </summary>
    public string DiscoveryPath { get; set; } = ".well-known/openid-configuration"; // Not yet implemented

    /// <summary>
    /// Path for the OIDC JWKS endpoint. Defaults to ".well-known/jwks.json". Relative to the root, not BasePath.
    /// </summary>
    public string JwksPath { get; set; } = ".well-known/jwks.json"; // Not yet implemented

    /// <summary>
    /// Path for the consent endpoint. Defaults to "consent". Relative to BasePath.
    /// </summary>
    public string ConsentPath { get; set; } = "consent"; // Not yet implemented

    /// <summary>
    /// Path for the end session/logout endpoint. Defaults to "endsession". Relative to BasePath.
    /// </summary>
    public string EndSessionPath { get; set; } = "endsession"; // Not yet implemented

    // Helper method to combine BasePath and relative path
    internal string Combine(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            throw new ArgumentException("Relative path cannot be null or whitespace.", nameof(relativePath));
        }

        // Handle paths that should be relative to root, not base path
        if (relativePath.StartsWith(".well-known/"))
        {
             // Ensure it starts with exactly one '/'
            return "/" + relativePath.TrimStart('/');
        }

        if (string.IsNullOrWhiteSpace(BasePath) || !BasePath.StartsWith("/"))
        {
            throw new InvalidOperationException($"{nameof(BasePath)} must be configured and start with a '/'. Current value: '{BasePath}'");
        }

        // Ensure BasePath ends with a single '/' and relativePath does not start with one
        var basePathNormalized = BasePath.TrimEnd('/') + "/";
        var relativePathNormalized = relativePath.TrimStart('/');

        return basePathNormalized + relativePathNormalized;
    }
} 