using CoreIdent.Core.Models;

namespace CoreIdent.Passkeys.Services;

/// <summary>
/// Service abstraction for generating and completing passkey (WebAuthn) registration and authentication ceremonies.
/// </summary>
public interface IPasskeyService
{
    /// <summary>
    /// Generates registration options (as JSON) for creating a new passkey credential for the specified user.
    /// </summary>
    /// <param name="user">The user registering a new passkey.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>A JSON payload that can be passed to WebAuthn APIs in the browser/client.</returns>
    Task<string> GetRegistrationOptionsJsonAsync(CoreIdentUser user, CancellationToken ct = default);

    /// <summary>
    /// Completes passkey registration using the credential response JSON returned by the client.
    /// </summary>
    /// <param name="user">The user registering a new passkey.</param>
    /// <param name="credentialJson">The credential response JSON returned by the client.</param>
    /// <param name="ct">A cancellation token.</param>
    Task CompleteRegistrationAsync(CoreIdentUser user, string credentialJson, CancellationToken ct = default);

    /// <summary>
    /// Generates authentication options (as JSON) for passkey authentication.
    /// </summary>
    /// <param name="username">The username to scope authentication options to, if provided.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>A JSON payload that can be passed to WebAuthn APIs in the browser/client.</returns>
    Task<string> GetAuthenticationOptionsJsonAsync(string? username, CancellationToken ct = default);

    /// <summary>
    /// Validates an authentication assertion and returns the authenticated user (if successful).
    /// </summary>
    /// <param name="credentialJson">The credential assertion JSON returned by the client.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The authenticated user, or <see langword="null"/> if authentication fails.</returns>
    Task<CoreIdentUser?> AuthenticateAsync(string credentialJson, CancellationToken ct = default);
}
