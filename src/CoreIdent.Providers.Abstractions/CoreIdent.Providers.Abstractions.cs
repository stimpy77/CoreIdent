using System.Security.Claims;

namespace CoreIdent.Providers.Abstractions;

/// <summary>
/// Represents the result of an external authentication attempt.
/// </summary>
public record ExternalAuthResult(
    /// <summary>
    /// Whether the authentication was successful.
    /// </summary>
    bool Success,
    
    /// <summary>
    /// The external user profile if successful.
    /// </summary>
    ExternalUserProfile? Profile,
    
    /// <summary>
    /// Error message if authentication failed.
    /// </summary>
    string? ErrorMessage,
    
    /// <summary>
    /// Error code if authentication failed.
    /// </summary>
    string? ErrorCode)
{
    /// <summary>
    /// Creates a successful authentication result.
    /// </summary>
    public static ExternalAuthResult Succeeded(ExternalUserProfile profile) 
        => new(true, profile, null, null);
    
    /// <summary>
    /// Creates a failed authentication result.
    /// </summary>
    public static ExternalAuthResult Failed(string errorMessage, string? errorCode = null) 
        => new(false, null, errorMessage, errorCode);
}

/// <summary>
/// Represents user profile information from an external identity provider.
/// </summary>
public record ExternalUserProfile(
    /// <summary>
    /// The unique identifier from the external provider.
    /// </summary>
    string ProviderKey,
    
    /// <summary>
    /// The provider name (e.g., "Google", "Microsoft", "GitHub").
    /// </summary>
    string ProviderName,
    
    /// <summary>
    /// The user's email address.
    /// </summary>
    string? Email,
    
    /// <summary>
    /// The user's display name.
    /// </summary>
    string? DisplayName,
    
    /// <summary>
    /// The user's first name.
    /// </summary>
    string? FirstName,
    
    /// <summary>
    /// The user's last name.
    /// </summary>
    string? LastName,
    
    /// <summary>
    /// URL to the user's profile picture.
    /// </summary>
    string? PictureUrl)
{
    /// <summary>
    /// Gets the full name combining first and last names.
    /// </summary>
    public string? FullName => string.IsNullOrEmpty(FirstName) && string.IsNullOrEmpty(LastName)
        ? null
        : $"{FirstName} {LastName}".Trim();
}

/// <summary>
/// Defines the contract for external authentication providers.
/// </summary>
public interface IExternalAuthProvider
{
    /// <summary>
    /// The unique name of this provider.
    /// </summary>
    string ProviderName { get; }
    
    /// <summary>
    /// Builds the authorization URL for initiating the OAuth/OIDC flow.
    /// </summary>
    /// <param name="redirectUri">The URI to redirect to after authentication.</param>
    /// <param name="state">Optional state parameter for CSRF protection.</param>
    /// <param name="scopes">The scopes to request.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The authorization URL.</returns>
    Task<string> BuildAuthorizationUrlAsync(
        string redirectUri,
        string? state,
        IEnumerable<string> scopes,
        CancellationToken ct = default);
    
    /// <summary>
    /// Exchanges the authorization code for user information.
    /// </summary>
    /// <param name="code">The authorization code from the callback.</param>
    /// <param name="redirectUri">The redirect URI used in the authorization request.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The authentication result.</returns>
    Task<ExternalAuthResult> ExchangeCodeAsync(
        string code,
        string redirectUri,
        CancellationToken ct = default);
    
    /// <summary>
    /// Gets user information using an existing access token.
    /// </summary>
    /// <param name="accessToken">The access token.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The user profile.</returns>
    Task<ExternalUserProfile> GetUserInfoAsync(
        string accessToken,
        CancellationToken ct = default);
    
    /// <summary>
    /// Revokes the external account access.
    /// </summary>
    /// <param name="accessToken">The access token to revoke.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RevokeAccessAsync(string accessToken, CancellationToken ct = default);
}

/// <summary>
/// Defines a store for managing external login associations.
/// </summary>
public interface IExternalLoginStore
{
    /// <summary>
    /// Finds an external login by provider and provider key.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="providerKey">The external provider key.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The external login, or null if not found.</returns>
    Task<ExternalLogin?> FindByProviderKeyAsync(
        string provider,
        string providerKey,
        CancellationToken ct = default);
    
    /// <summary>
    /// Gets all external logins for a user.
    /// </summary>
    /// <param name="userId">The user ID.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The external logins.</returns>
    Task<IReadOnlyList<ExternalLogin>> GetLoginsForUserAsync(
        string userId,
        CancellationToken ct = default);
    
    /// <summary>
    /// Adds an external login to a user.
    /// </summary>
    /// <param name="login">The external login to add.</param>
    /// <param name="ct">The cancellation token.</param>
    Task AddLoginAsync(ExternalLogin login, CancellationToken ct = default);
    
    /// <summary>
    /// Removes an external login from a user.
    /// </summary>
    /// <param name="userId">The user ID.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="providerKey">The external provider key.</param>
    /// <param name="ct">The cancellation token.</param>
    Task RemoveLoginAsync(
        string userId,
        string provider,
        string providerKey,
        CancellationToken ct = default);
}

/// <summary>
/// Represents an external login association.
/// </summary>
public class ExternalLogin
{
    /// <summary>
    /// The unique identifier.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    /// <summary>
    /// The user ID this login is associated with.
    /// </summary>
    public string UserId { get; set; } = string.Empty;
    
    /// <summary>
    /// The provider name (e.g., "Google").
    /// </summary>
    public string Provider { get; set; } = string.Empty;
    
    /// <summary>
    /// The unique identifier from the external provider.
    /// </summary>
    public string ProviderKey { get; set; } = string.Empty;
    
    /// <summary>
    /// The display name of the provider for the user.
    /// </summary>
    public string? ProviderDisplayName { get; set; }
    
    /// <summary>
    /// When this login was linked.
    /// </summary>
    public DateTimeOffset LinkedAt { get; set; } = DateTimeOffset.UtcNow;
}
