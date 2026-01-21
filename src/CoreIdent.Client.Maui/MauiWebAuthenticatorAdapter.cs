#if ANDROID || IOS || MACCATALYST
using Microsoft.Maui.Authentication;
#endif

namespace CoreIdent.Client.Maui;

/// <summary>
/// Response from web authenticator.
/// </summary>
internal sealed record AuthenticatorResponse(IReadOnlyDictionary<string, string> Properties, string? AccessToken);

/// <summary>
/// Abstraction over MAUI WebAuthenticator for testability.
/// </summary>
internal interface IMauiWebAuthenticatorAdapter
{
    Task<AuthenticatorResponse> AuthenticateAsync(Uri url, Uri callbackUri, CancellationToken ct = default);
}

#if ANDROID || IOS || MACCATALYST
internal sealed class MauiWebAuthenticatorAdapter : IMauiWebAuthenticatorAdapter
{
    public static MauiWebAuthenticatorAdapter Default { get; } = new();

    public async Task<AuthenticatorResponse> AuthenticateAsync(Uri url, Uri callbackUri, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        var result = await WebAuthenticator.Default.AuthenticateAsync(url, callbackUri);

        ct.ThrowIfCancellationRequested();
        return new AuthenticatorResponse(result.Properties, result.AccessToken);
    }
}
#else
// Stub for net10.0 (unit test) builds - real implementation only on MAUI platforms
internal sealed class MauiWebAuthenticatorAdapter : IMauiWebAuthenticatorAdapter
{
    public static MauiWebAuthenticatorAdapter Default { get; } = new();

    public Task<AuthenticatorResponse> AuthenticateAsync(Uri url, Uri callbackUri, CancellationToken ct = default)
    {
        throw new PlatformNotSupportedException("WebAuthenticator is only available on MAUI platforms.");
    }
}
#endif
