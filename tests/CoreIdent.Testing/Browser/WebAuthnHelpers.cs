using System.Text.Json;
using Microsoft.Playwright;

namespace CoreIdent.Testing.Browser;

/// <summary>
/// Helpers for WebAuthn/Passkey testing with Playwright virtual authenticator.
/// Uses Chrome DevTools Protocol (CDP) to simulate hardware authenticators.
/// </summary>
/// <remarks>
/// Virtual authenticators are only supported in Chromium-based browsers.
/// </remarks>
public static class WebAuthnHelpers
{
    /// <summary>
    /// Creates and enables a virtual authenticator for the given page.
    /// </summary>
    /// <param name="page">The Playwright page to attach the authenticator to.</param>
    /// <param name="options">Configuration for the virtual authenticator.</param>
    /// <returns>A handle to the virtual authenticator that can be used to manage credentials.</returns>
    public static async Task<VirtualAuthenticator> CreateVirtualAuthenticatorAsync(
        IPage page,
        VirtualAuthenticatorOptions? options = null)
    {
        options ??= VirtualAuthenticatorOptions.Default;

        var cdpSession = await page.Context.NewCDPSessionAsync(page);

        // Enable WebAuthn environment
        await cdpSession.SendAsync("WebAuthn.enable", new Dictionary<string, object>
        {
            ["enableUI"] = false // Disable UI prompts for automation
        });

        // Add virtual authenticator
        var addResult = await cdpSession.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object>
        {
            ["options"] = new Dictionary<string, object>
            {
                ["protocol"] = options.Protocol,
                ["transport"] = options.Transport,
                ["hasResidentKey"] = options.HasResidentKey,
                ["hasUserVerification"] = options.HasUserVerification,
                ["isUserVerified"] = options.IsUserVerified,
                ["automaticPresenceSimulation"] = options.AutomaticPresenceSimulation
            }
        });

        var authenticatorId = addResult.Value.GetProperty("authenticatorId").GetString()
            ?? throw new InvalidOperationException("Failed to get authenticator ID");

        return new VirtualAuthenticator(cdpSession, authenticatorId);
    }

    /// <summary>
    /// Adds a credential to the virtual authenticator.
    /// </summary>
    public static async Task AddCredentialAsync(
        VirtualAuthenticator authenticator,
        VirtualCredential credential)
    {
        await authenticator.CdpSession.SendAsync("WebAuthn.addCredential", new Dictionary<string, object>
        {
            ["authenticatorId"] = authenticator.AuthenticatorId,
            ["credential"] = new Dictionary<string, object>
            {
                ["credentialId"] = Convert.ToBase64String(credential.CredentialId),
                ["isResidentCredential"] = credential.IsResidentCredential,
                ["rpId"] = credential.RpId,
                ["privateKey"] = Convert.ToBase64String(credential.PrivateKey),
                ["signCount"] = credential.SignCount,
                ["userHandle"] = credential.UserHandle != null ? Convert.ToBase64String(credential.UserHandle) : null!
            }
        });
    }

    /// <summary>
    /// Gets all credentials from the virtual authenticator.
    /// </summary>
    public static async Task<IReadOnlyList<VirtualCredential>> GetCredentialsAsync(VirtualAuthenticator authenticator)
    {
        var result = await authenticator.CdpSession.SendAsync("WebAuthn.getCredentials", new Dictionary<string, object>
        {
            ["authenticatorId"] = authenticator.AuthenticatorId
        });

        var credentials = new List<VirtualCredential>();
        foreach (var cred in result.Value.GetProperty("credentials").EnumerateArray())
        {
            credentials.Add(new VirtualCredential
            {
                CredentialId = Convert.FromBase64String(cred.GetProperty("credentialId").GetString() ?? ""),
                IsResidentCredential = cred.GetProperty("isResidentCredential").GetBoolean(),
                RpId = cred.GetProperty("rpId").GetString() ?? "",
                PrivateKey = Convert.FromBase64String(cred.GetProperty("privateKey").GetString() ?? ""),
                SignCount = cred.GetProperty("signCount").GetInt32(),
                UserHandle = cred.TryGetProperty("userHandle", out var uh) && uh.ValueKind != JsonValueKind.Null
                    ? Convert.FromBase64String(uh.GetString() ?? "")
                    : null
            });
        }

        return credentials;
    }

    /// <summary>
    /// Clears all credentials from the virtual authenticator.
    /// </summary>
    public static async Task ClearCredentialsAsync(VirtualAuthenticator authenticator)
    {
        await authenticator.CdpSession.SendAsync("WebAuthn.clearCredentials", new Dictionary<string, object>
        {
            ["authenticatorId"] = authenticator.AuthenticatorId
        });
    }

    /// <summary>
    /// Removes the virtual authenticator.
    /// </summary>
    public static async Task RemoveAuthenticatorAsync(VirtualAuthenticator authenticator)
    {
        await authenticator.CdpSession.SendAsync("WebAuthn.removeVirtualAuthenticator", new Dictionary<string, object>
        {
            ["authenticatorId"] = authenticator.AuthenticatorId
        });
    }

    /// <summary>
    /// Sets user verification state on the authenticator.
    /// </summary>
    public static async Task SetUserVerifiedAsync(VirtualAuthenticator authenticator, bool isUserVerified)
    {
        await authenticator.CdpSession.SendAsync("WebAuthn.setUserVerified", new Dictionary<string, object>
        {
            ["authenticatorId"] = authenticator.AuthenticatorId,
            ["isUserVerified"] = isUserVerified
        });
    }
}

/// <summary>
/// Handle to a virtual authenticator created via CDP.
/// </summary>
public sealed class VirtualAuthenticator : IAsyncDisposable
{
    internal ICDPSession CdpSession { get; }

    /// <summary>
    /// Gets the CDP authenticator identifier.
    /// </summary>
    public string AuthenticatorId { get; }

    internal VirtualAuthenticator(ICDPSession cdpSession, string authenticatorId)
    {
        CdpSession = cdpSession;
        AuthenticatorId = authenticatorId;
    }

    /// <summary>
    /// Adds a credential to this authenticator.
    /// </summary>
    public Task AddCredentialAsync(VirtualCredential credential)
        => WebAuthnHelpers.AddCredentialAsync(this, credential);

    /// <summary>
    /// Gets all credentials from this authenticator.
    /// </summary>
    public Task<IReadOnlyList<VirtualCredential>> GetCredentialsAsync()
        => WebAuthnHelpers.GetCredentialsAsync(this);

    /// <summary>
    /// Clears all credentials from this authenticator.
    /// </summary>
    public Task ClearCredentialsAsync()
        => WebAuthnHelpers.ClearCredentialsAsync(this);

    /// <summary>
    /// Sets user verification state.
    /// </summary>
    public Task SetUserVerifiedAsync(bool isUserVerified)
        => WebAuthnHelpers.SetUserVerifiedAsync(this, isUserVerified);

    /// <summary>
    /// Disposes the virtual authenticator by removing it from CDP.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        try
        {
            await WebAuthnHelpers.RemoveAuthenticatorAsync(this);
        }
        catch
        {
            // Ignore errors during cleanup
        }
    }
}

/// <summary>
/// Configuration options for a virtual authenticator.
/// </summary>
public sealed class VirtualAuthenticatorOptions
{
    /// <summary>
    /// Default options for a platform authenticator with resident keys and user verification.
    /// </summary>
    public static VirtualAuthenticatorOptions Default => new()
    {
        Protocol = "ctap2",
        Transport = "internal",
        HasResidentKey = true,
        HasUserVerification = true,
        IsUserVerified = true,
        AutomaticPresenceSimulation = true
    };

    /// <summary>
    /// Options for a USB security key (roaming authenticator).
    /// </summary>
    public static VirtualAuthenticatorOptions UsbSecurityKey => new()
    {
        Protocol = "ctap2",
        Transport = "usb",
        HasResidentKey = false,
        HasUserVerification = false,
        IsUserVerified = false,
        AutomaticPresenceSimulation = true
    };

    /// <summary>
    /// The WebAuthn protocol version: "ctap2" or "u2f".
    /// </summary>
    public string Protocol { get; set; } = "ctap2";

    /// <summary>
    /// The authenticator transport: "usb", "nfc", "ble", "cable", or "internal".
    /// </summary>
    public string Transport { get; set; } = "internal";

    /// <summary>
    /// Whether the authenticator supports resident (discoverable) credentials.
    /// </summary>
    public bool HasResidentKey { get; set; } = true;

    /// <summary>
    /// Whether the authenticator supports user verification.
    /// </summary>
    public bool HasUserVerification { get; set; } = true;

    /// <summary>
    /// Whether the user is already verified (simulates biometric/PIN).
    /// </summary>
    public bool IsUserVerified { get; set; } = true;

    /// <summary>
    /// Whether to automatically simulate user presence when needed.
    /// </summary>
    public bool AutomaticPresenceSimulation { get; set; } = true;
}

/// <summary>
/// Represents a credential stored in a virtual authenticator.
/// </summary>
public sealed class VirtualCredential
{
    /// <summary>
    /// The credential ID.
    /// </summary>
    public byte[] CredentialId { get; set; } = [];

    /// <summary>
    /// Whether this is a resident (discoverable) credential.
    /// </summary>
    public bool IsResidentCredential { get; set; }

    /// <summary>
    /// The relying party ID this credential is bound to.
    /// </summary>
    public string RpId { get; set; } = string.Empty;

    /// <summary>
    /// The private key in PKCS#8 format.
    /// </summary>
    public byte[] PrivateKey { get; set; } = [];

    /// <summary>
    /// The signature counter.
    /// </summary>
    public int SignCount { get; set; }

    /// <summary>
    /// The user handle (user ID) associated with this credential.
    /// </summary>
    public byte[]? UserHandle { get; set; }
}
