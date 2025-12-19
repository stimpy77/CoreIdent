using System.Security.Claims;

namespace CoreIdent.Client;

/// <summary>
/// Primary interface for interacting with a CoreIdent (or any OAuth/OIDC) authorization server.
/// </summary>
public interface ICoreIdentClient
{
    /// <summary>
    /// Starts an interactive login flow.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The result of the authentication attempt.</returns>
    Task<AuthResult> LoginAsync(CancellationToken ct = default);

    /// <summary>
    /// Attempts to authenticate without user interaction (e.g., via refresh token).
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The result of the authentication attempt.</returns>
    Task<AuthResult> LoginSilentAsync(CancellationToken ct = default);

    /// <summary>
    /// Logs out the current user.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    Task LogoutAsync(CancellationToken ct = default);

    /// <summary>
    /// Gets a valid access token, refreshing if necessary.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The access token, or null if not authenticated.</returns>
    Task<string?> GetAccessTokenAsync(CancellationToken ct = default);

    /// <summary>
    /// Gets the current authenticated user.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The user claims principal, or null if not authenticated.</returns>
    Task<ClaimsPrincipal?> GetUserAsync(CancellationToken ct = default);

    /// <summary>
    /// Gets whether the client currently has an authenticated session.
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// Raised when the authentication state changes.
    /// </summary>
    event EventHandler<AuthStateChangedEventArgs>? AuthStateChanged;
}
