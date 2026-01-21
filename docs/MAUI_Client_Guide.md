# CoreIdent.Client.Maui — Integration Guide

This guide shows how to use `CoreIdent.Client.Maui` in a .NET MAUI app. The sample below uses the Authorization Code + PKCE flow and secure token storage backed by `SecureStorage`.

## Install package

Reference the project (or NuGet package when published):

- Project reference: `src/CoreIdent.Client.Maui`
- NuGet: `CoreIdent.Client.Maui`

## Sample app setup

### 1) Configure CoreIdent in `MauiProgram.cs`

```csharp
using CoreIdent.Client;
using CoreIdent.Client.Maui;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        builder
            .UseMauiApp<App>()
            .UseCoreIdentClient(options =>
            {
                options.Authority = "https://identity.example";
                options.ClientId = "maui-client";
                options.RedirectUri = "myapp://callback";
                options.Scopes = ["openid", "profile", "offline_access"];
            }, httpClient =>
            {
                httpClient.Timeout = TimeSpan.FromSeconds(60);
            });

        return builder.Build();
    }
}
```

### 2) Call the client from a page

```csharp
using CoreIdent.Client;

public partial class MainPage : ContentPage
{
    private readonly ICoreIdentClient _client;

    public MainPage(ICoreIdentClient client)
    {
        InitializeComponent();
        _client = client;
    }

    private async void OnLoginClicked(object sender, EventArgs e)
    {
        var result = await _client.LoginAsync();
        if (!result.IsSuccess)
        {
            await DisplayAlert("Login failed", result.ErrorDescription ?? result.Error ?? "Unknown error", "OK");
            return;
        }

        var accessToken = await _client.GetAccessTokenAsync();
        await DisplayAlert("Token", accessToken ?? "(none)", "OK");
    }
}
```

## Redirect URI notes

`CoreIdent.Client.Maui` uses `WebAuthenticator`, which expects a custom scheme (`myapp://callback`) or universal link depending on your platform. Follow the MAUI WebAuthenticator setup for your platform:

- **Android**: add a callback activity with an intent filter for your custom scheme.
- **iOS**: add the URL type and associated scheme to your app.
- **Mac Catalyst**: add the URL scheme to `Info.plist`.

Refer to the official MAUI WebAuthenticator documentation for the latest platform guidance.

## Token storage

`MauiSecureTokenStorage` stores tokens in `SecureStorage` and is registered automatically by `UseCoreIdentClient()`.

If you need a custom key, you can register it manually:

```csharp
builder.Services.AddSingleton<ISecureTokenStorage>(
    _ => new MauiSecureTokenStorage(storageKey: "coreident.tokens"));
```

## Troubleshooting

- If login does not return to the app, ensure the redirect URI scheme is registered correctly.
- If tokens do not persist, verify the device supports secure storage and that your app has the correct entitlements.
