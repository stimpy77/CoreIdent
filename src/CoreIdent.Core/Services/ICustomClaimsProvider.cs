using System.Security.Claims;

namespace CoreIdent.Core.Services;

/// <summary>
/// Provides custom claims to be added to tokens during issuance.
/// </summary>
public interface ICustomClaimsProvider
{
    /// <summary>
    /// Gets additional claims to include in the access token.
    /// </summary>
    /// <param name="context">The context for claims generation.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Additional claims to include in the token.</returns>
    Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsContext context, CancellationToken ct = default);

    /// <summary>
    /// Gets additional claims to include in the ID token.
    /// </summary>
    /// <param name="context">The context for claims generation.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Additional claims to include in the ID token.</returns>
    Task<IEnumerable<Claim>> GetIdTokenClaimsAsync(ClaimsContext context, CancellationToken ct = default);
}

/// <summary>
/// Context for custom claims generation.
/// </summary>
public record ClaimsContext
{
    /// <summary>
    /// The subject (user) ID. Null for client_credentials grant.
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// The client ID.
    /// </summary>
    public string ClientId { get; init; } = string.Empty;

    /// <summary>
    /// The granted scopes.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>
    /// The grant type being used.
    /// </summary>
    public string GrantType { get; init; } = string.Empty;
}

/// <summary>
/// Default implementation that returns no additional claims.
/// </summary>
public class NullCustomClaimsProvider : ICustomClaimsProvider
{
    public Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsContext context, CancellationToken ct = default)
        => Task.FromResult(Enumerable.Empty<Claim>());

    public Task<IEnumerable<Claim>> GetIdTokenClaimsAsync(ClaimsContext context, CancellationToken ct = default)
        => Task.FromResult(Enumerable.Empty<Claim>());
}
