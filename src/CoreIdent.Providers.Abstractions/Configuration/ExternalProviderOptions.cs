using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.Providers.Abstractions.Configuration;

/// <summary>
/// Options for configuring an external authentication provider.
/// </summary>
public class ExternalProviderOptions
{
    /// <summary>
    /// The OAuth client ID.
    /// </summary>
    public required string ClientId { get; set; }
    
    /// <summary>
    /// The OAuth client secret.
    /// </summary>
    public required string ClientSecret { get; set; }
    
    /// <summary>
    /// The redirect URI after authentication.
    /// </summary>
    public string? RedirectUri { get; set; }
    
    /// <summary>
    /// The scopes to request from the provider.
    /// </summary>
    public ICollection<string> Scopes { get; set; } = ["openid", "profile", "email"];
    
    /// <summary>
    /// Whether to enable the provider. Defaults to true.
    /// </summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// Marker interface for provider-specific options.
/// </summary>
public interface IProviderOptions { }

/// <summary>
/// Options for configuring the Google provider.
/// </summary>
public class GoogleProviderOptions : ExternalProviderOptions, IProviderOptions
{
    /// <summary>
    /// Google OAuth 2.0 authorization endpoint.
    /// </summary>
    public string AuthorizationEndpoint { get; set; } = "https://accounts.google.com/o/oauth2/v2/auth";
    
    /// <summary>
    /// Google OAuth 2.0 token endpoint.
    /// </summary>
    public string TokenEndpoint { get; set; } = "https://oauth2.googleapis.com/token";
    
    /// <summary>
    /// Google OAuth 2.0 userinfo endpoint.
    /// </summary>
    public string UserInfoEndpoint { get; set; } = "https://www.googleapis.com/oauth2/v3/userinfo";
    
    /// <summary>
    /// Google OAuth 2.0 revoke endpoint.
    /// </summary>
    public string RevokeEndpoint { get; set; } = "https://oauth2.googleapis.com/revoke";
}

/// <summary>
/// Options for configuring the Microsoft provider.
/// </summary>
public class MicrosoftProviderOptions : ExternalProviderOptions, IProviderOptions
{
    /// <summary>
    /// Microsoft OAuth 2.0 authorization endpoint.
    /// </summary>
    public string AuthorizationEndpoint { get; set; } = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    
    /// <summary>
    /// Microsoft OAuth 2.0 token endpoint.
    /// </summary>
    public string TokenEndpoint { get; set; } = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    
    /// <summary>
    /// Microsoft Graph userinfo endpoint.
    /// </summary>
    public string UserInfoEndpoint { get; set; } = "https://graph.microsoft.com/oidc/v1.0/userinfo";
    
    /// <summary>
    /// The tenant ID (use "common" for multi-tenant).
    /// </summary>
    public string? TenantId { get; set; } = "common";
    
    /// <summary>
    /// Whether to request work/school accounts only.
    /// </summary>
    public bool WorkAndSchoolAccountsOnly { get; set; }
}

/// <summary>
/// Options for configuring the GitHub provider.
/// </summary>
public class GitHubProviderOptions : ExternalProviderOptions, IProviderOptions
{
    /// <summary>
    /// GitHub OAuth authorization endpoint.
    /// </summary>
    public string AuthorizationEndpoint { get; set; } = "https://github.com/login/oauth/authorize";
    
    /// <summary>
    /// GitHub OAuth token endpoint.
    /// </summary>
    public string TokenEndpoint { get; set; } = "https://github.com/login/oauth/access_token";
    
    /// <summary>
    /// GitHub API user endpoint.
    /// </summary>
    public string UserApiEndpoint { get; set; } = "https://api.github.com/user";
    
    /// <summary>
    /// GitHub API emails endpoint (for email scope).
    /// </summary>
    public string EmailsApiEndpoint { get; set; } = "https://api.github.com/user/emails";
}

/// <summary>
/// Extension methods for registering external providers.
/// </summary>
public static class ExternalProviderExtensions
{
    /// <summary>
    /// Adds an external authentication provider.
    /// </summary>
    /// <typeparam name="TProvider">The provider type.</typeparam>
    /// <typeparam name="TOptions">The options type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">The configuration action.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddExternalProvider<TProvider, TOptions>(
        this IServiceCollection services,
        Action<TOptions> configure)
        where TProvider : class, IExternalAuthProvider
        where TOptions : class, IProviderOptions, new()
    {
        services.Configure(configure);
        services.AddScoped<IExternalAuthProvider, TProvider>();
        return services;
    }
}
