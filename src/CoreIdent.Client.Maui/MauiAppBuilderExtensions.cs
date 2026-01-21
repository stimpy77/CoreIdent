#if ANDROID || IOS || MACCATALYST
using CoreIdent.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Hosting;

namespace CoreIdent.Client.Maui;

/// <summary>
/// MAUI integration extensions for CoreIdent.Client.
/// </summary>
public static class MauiAppBuilderExtensions
{
    /// <summary>
    /// Registers CoreIdent.Client services for MAUI apps.
    /// </summary>
    /// <param name="builder">The MAUI app builder.</param>
    /// <param name="configureOptions">Options configuration.</param>
    /// <param name="configureHttpClient">Optional HTTP client configuration.</param>
    /// <returns>The updated builder.</returns>
    public static MauiAppBuilder UseCoreIdentClient(
        this MauiAppBuilder builder,
        Action<CoreIdentClientOptions> configureOptions,
        Action<HttpClient>? configureHttpClient = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureOptions);

        var options = new CoreIdentClientOptions();
        configureOptions(options);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<ISecureTokenStorage, MauiSecureTokenStorage>();
        builder.Services.AddSingleton<IBrowserLauncher, MauiBrowserLauncher>();
        builder.Services.AddHttpClient("CoreIdent.Client", httpClient => configureHttpClient?.Invoke(httpClient));
        builder.Services.AddSingleton<ICoreIdentClient>(sp =>
        {
            var httpClient = sp.GetRequiredService<IHttpClientFactory>().CreateClient("CoreIdent.Client");
            return new CoreIdentClient(
                sp.GetRequiredService<CoreIdentClientOptions>(),
                httpClient,
                sp.GetRequiredService<ISecureTokenStorage>(),
                sp.GetRequiredService<IBrowserLauncher>());
        });

        return builder;
    }
}
#endif
