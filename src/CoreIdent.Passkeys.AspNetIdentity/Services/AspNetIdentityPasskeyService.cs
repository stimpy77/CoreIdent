using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Passkeys.Services;
using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passkeys.AspNetIdentity.Services;

/// <summary>
/// Passkey service implementation backed by ASP.NET Core Identity passkey APIs.
/// </summary>
public sealed class AspNetIdentityPasskeyService : IPasskeyService
{
    private readonly IUserStore _userStore;
    private readonly UserManager<CoreIdentUser> _userManager;
    private readonly SignInManager<CoreIdentUser> _signInManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="AspNetIdentityPasskeyService"/> class.
    /// </summary>
    /// <param name="userStore">The CoreIdent user store.</param>
    /// <param name="userManager">The ASP.NET Core Identity user manager.</param>
    /// <param name="signInManager">The ASP.NET Core Identity sign-in manager.</param>
    public AspNetIdentityPasskeyService(
        CoreIdent.Core.Stores.IUserStore userStore,
        UserManager<CoreIdentUser> userManager,
        SignInManager<CoreIdentUser> signInManager)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
    }

    /// <inheritdoc />
    /// <summary>
    /// Gets the registration options JSON for the specified user.
    /// </summary>
    /// <param name="user">The user to get registration options for.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The registration options JSON.</returns>
    public async Task<string> GetRegistrationOptionsJsonAsync(CoreIdentUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        var userId = await _userManager.GetUserIdAsync(user);
        var userName = await _userManager.GetUserNameAsync(user) ?? "User";

        return await _signInManager.MakePasskeyCreationOptionsAsync(new PasskeyUserEntity
        {
            Id = userId,
            Name = userName,
            DisplayName = userName,
        });
    }

    /// <inheritdoc />
    /// <summary>
    /// Completes the registration for the specified user.
    /// </summary>
    /// <param name="user">The user to complete registration for.</param>
    /// <param name="credentialJson">The credential JSON.</param>
    /// <param name="ct">The cancellation token.</param>
    public async Task CompleteRegistrationAsync(CoreIdentUser user, string credentialJson, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialJson);

        var attestationResult = await _signInManager.PerformPasskeyAttestationAsync(credentialJson);
        if (!attestationResult.Succeeded)
        {
            throw new InvalidOperationException(attestationResult.Failure.Message);
        }

        var addResult = await _userManager.AddOrUpdatePasskeyAsync(user, attestationResult.Passkey);
        if (!addResult.Succeeded)
        {
            throw new InvalidOperationException("Failed to store passkey.");
        }
    }

    /// <inheritdoc />
    /// <summary>
    /// Gets the authentication options JSON for the specified username.
    /// </summary>
    /// <param name="username">The username to get authentication options for.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The authentication options JSON.</returns>
    public async Task<string> GetAuthenticationOptionsJsonAsync(string? username, CancellationToken ct = default)
    {
        CoreIdentUser? user = null;

        if (!string.IsNullOrWhiteSpace(username))
        {
            user = await _userStore.FindByUsernameAsync(username, ct);
        }

        return await _signInManager.MakePasskeyRequestOptionsAsync(user);
    }

    /// <inheritdoc />
    /// <summary>
    /// Authenticates the user using the specified credential JSON.
    /// </summary>
    /// <param name="credentialJson">The credential JSON.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The authenticated user, or null if authentication fails.</returns>
    public async Task<CoreIdentUser?> AuthenticateAsync(string credentialJson, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialJson);

        var assertionResult = await _signInManager.PerformPasskeyAssertionAsync(credentialJson);
        if (!assertionResult.Succeeded)
        {
            return null;
        }

        var setPasskeyResult = await _userManager.AddOrUpdatePasskeyAsync(assertionResult.User, assertionResult.Passkey);
        if (!setPasskeyResult.Succeeded)
        {
            return null;
        }

        return assertionResult.User;
    }
}
