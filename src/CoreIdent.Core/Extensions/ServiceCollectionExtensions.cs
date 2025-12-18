using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using CoreIdent.Core.Services.Realms;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using CoreIdent.Core.Stores.Realms;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Service registration helpers for CoreIdent.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds CoreIdent services using options resolved from configuration/DI.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    /// <remarks>
    /// <para>
    /// This method registers CoreIdent's default services and in-memory stores using <c>TryAdd*</c> so you can
    /// override any store/service by registering your own implementation before calling <see cref="AddCoreIdent(Microsoft.Extensions.DependencyInjection.IServiceCollection)"/>.
    /// </para>
    /// <para>
    /// <see cref="CoreIdentOptions"/> is validated on startup. You must configure <see cref="CoreIdentOptions.Issuer"/> and
    /// <see cref="CoreIdentOptions.Audience"/> via configuration binding or by using an overload of <see cref="AddCoreIdent(Microsoft.Extensions.DependencyInjection.IServiceCollection,System.Action{CoreIdent.Core.Configuration.CoreIdentOptions})"/>.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddCoreIdent(this IServiceCollection services)
    {
        return services.AddCoreIdent(configureOptions: null, configureRoutes: null);
    }

    /// <summary>
    /// Adds CoreIdent services and configures <see cref="CoreIdentOptions"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Options configuration callback.</param>
    /// <returns>The service collection.</returns>
    /// <remarks>
    /// <para>
    /// For a minimal host, you typically call <see cref="AddCoreIdent(Microsoft.Extensions.DependencyInjection.IServiceCollection,System.Action{CoreIdent.Core.Configuration.CoreIdentOptions})"/> and then
    /// <see cref="AddSigningKey(Microsoft.Extensions.DependencyInjection.IServiceCollection,System.Action{CoreIdent.Core.Extensions.CoreIdentKeyOptionsBuilder})"/>.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddCoreIdent(this IServiceCollection services, Action<CoreIdentOptions> configureOptions)
    {
        return services.AddCoreIdent(configureOptions, configureRoutes: null);
    }

    /// <summary>
    /// Adds CoreIdent services and optionally configures options and routes.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional CoreIdent options configuration.</param>
    /// <param name="configureRoutes">Optional route options configuration.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddCoreIdent(
        this IServiceCollection services,
        Action<CoreIdentOptions>? configureOptions,
        Action<CoreIdentRouteOptions>? configureRoutes)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<CoreIdentOptions>, CoreIdentOptionsValidator>());
        services.AddOptions<CoreIdentOptions>().ValidateOnStart();

        services.AddOptions<CoreIdentRouteOptions>();

        services.AddOptions<CoreIdentResourceOwnerOptions>();

        services.AddOptions<CoreIdentAuthorizationCodeOptions>();

        services.AddOptions<PasswordlessEmailOptions>();

        services.AddOptions<PasswordlessSmsOptions>();

        services.AddOptions<SmtpOptions>();

        if (configureRoutes is not null)
        {
            services.Configure(configureRoutes);
        }

        services.TryAddSingleton<TimeProvider>(TimeProvider.System);

        services.TryAddSingleton<ICoreIdentRealmResolver, DefaultCoreIdentRealmResolver>();
        services.TryAddScoped<ICoreIdentRealmContext, HttpContextCoreIdentRealmContext>();
        services.TryAddSingleton<IRealmIssuerAudienceProvider, DefaultRealmIssuerAudienceProvider>();
        services.TryAddScoped<ICoreIdentIssuerAudienceProvider, DefaultCoreIdentIssuerAudienceProvider>();

        services.TryAddScoped<IRealmClientStore, DefaultRealmClientStoreAdapter>();
        services.TryAddScoped<IRealmScopeStore, DefaultRealmScopeStoreAdapter>();
        services.TryAddScoped<IRealmRefreshTokenStore, DefaultRealmRefreshTokenStoreAdapter>();
        services.TryAddScoped<IRealmAuthorizationCodeStore, DefaultRealmAuthorizationCodeStoreAdapter>();
        services.TryAddScoped<IRealmUserGrantStore, DefaultRealmUserGrantStoreAdapter>();
        services.TryAddScoped<IRealmUserStore, DefaultRealmUserStoreAdapter>();
        services.TryAddScoped<IRealmTokenRevocationStore, DefaultRealmTokenRevocationStoreAdapter>();
        services.TryAddScoped<IRealmPasswordlessTokenStore, DefaultRealmPasswordlessTokenStoreAdapter>();

        services.TryAddScoped<ITokenService, JwtTokenService>();

        services.TryAddSingleton<IClientSecretHasher, DefaultClientSecretHasher>();

        services.TryAdd(ServiceDescriptor.Singleton<InMemoryClientStore>(sp =>
            new InMemoryClientStore(sp.GetRequiredService<IClientSecretHasher>())));
        services.TryAdd(ServiceDescriptor.Singleton<IClientStore>(sp => sp.GetRequiredService<InMemoryClientStore>()));

        services.TryAddSingleton<InMemoryScopeStore>(sp =>
        {
            var store = new InMemoryScopeStore();
            store.SeedStandardScopes();
            return store;
        });
        services.TryAddSingleton<IScopeStore>(sp => sp.GetRequiredService<InMemoryScopeStore>());

        services.TryAddSingleton<InMemoryRefreshTokenStore>(sp =>
            new InMemoryRefreshTokenStore(sp.GetService<TimeProvider>()));
        services.TryAddSingleton<IRefreshTokenStore>(sp => sp.GetRequiredService<InMemoryRefreshTokenStore>());

        services.TryAddSingleton<InMemoryAuthorizationCodeStore>(sp =>
            new InMemoryAuthorizationCodeStore(sp.GetService<TimeProvider>()));
        services.TryAddSingleton<IAuthorizationCodeStore>(sp => sp.GetRequiredService<InMemoryAuthorizationCodeStore>());

        services.TryAddSingleton<InMemoryUserGrantStore>(sp =>
            new InMemoryUserGrantStore(sp.GetService<TimeProvider>()));
        services.TryAddSingleton<IUserGrantStore>(sp => sp.GetRequiredService<InMemoryUserGrantStore>());

        services.TryAddSingleton<ITokenRevocationStore>(sp =>
            new InMemoryTokenRevocationStore(sp.GetService<TimeProvider>()));

        services.TryAddSingleton<IPasswordHasher, ThrowingPasswordHasher>();
        services.TryAddSingleton<InMemoryUserStore>(sp =>
            new InMemoryUserStore(sp.GetService<TimeProvider>()));
        services.TryAddSingleton<IUserStore>(sp => sp.GetRequiredService<InMemoryUserStore>());

        services.TryAddSingleton<ICustomClaimsProvider, NullCustomClaimsProvider>();

        services.TryAddSingleton<PasswordlessEmailTemplateRenderer>();

        services.TryAddSingleton<IEmailSender, SmtpEmailSender>();

        services.TryAddSingleton<ISmsProvider, ConsoleSmsProvider>();

        services.TryAddSingleton<InMemoryPasswordlessTokenStore>(sp =>
            new InMemoryPasswordlessTokenStore(
                sp.GetService<TimeProvider>(),
                sp.GetRequiredService<IOptions<PasswordlessEmailOptions>>(),
                sp.GetRequiredService<IOptions<PasswordlessSmsOptions>>()));
        services.TryAddSingleton<IPasswordlessTokenStore>(sp => sp.GetRequiredService<InMemoryPasswordlessTokenStore>());

        services.TryAddSingleton<ICoreIdentMetrics, NullCoreIdentMetrics>();

        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        services.TryAddSingleton<IRealmSigningKeyProviderResolver, DefaultRealmSigningKeyProviderResolver>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, AuthorizationCodeCleanupHostedService>());

        return services;
    }

    /// <summary>
    /// Configures resource owner endpoints.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration callback.</param>
    /// <returns>The service collection.</returns>
    /// <remarks>
    /// This only configures endpoint behavior (custom result handling). It does not map endpoints.
    /// You must still call <c>app.MapCoreIdentEndpoints()</c> or map resource-owner endpoints explicitly.
    /// </remarks>
    public static IServiceCollection ConfigureResourceOwnerEndpoints(
        this IServiceCollection services,
        Action<CoreIdentResourceOwnerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        return services;
    }

    /// <summary>
    /// Configures JWT signing key selection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Key options configuration callback.</param>
    /// <returns>The service collection.</returns>
    /// <remarks>
    /// <para>
    /// For production, prefer asymmetric keys (RSA/ECDSA). Symmetric keys are intended for development/testing only
    /// and are not published via JWKS.
    /// </para>
    /// <para>
    /// This registers an <see cref="ISigningKeyProvider"/> implementation based on the configured key type.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddSigningKey(this IServiceCollection services, Action<CoreIdentKeyOptionsBuilder> configure)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (configure is null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var builder = new CoreIdentKeyOptionsBuilder();
        configure(builder);

        services.Configure<CoreIdentKeyOptions>(options => builder.Apply(options));

        services.TryAddSingleton<ISigningKeyProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<CoreIdentKeyOptions>>().Value;

            return options.Type switch
            {
                KeyType.RSA => new RsaSigningKeyProvider(sp.GetRequiredService<IOptions<CoreIdentKeyOptions>>(), sp.GetRequiredService<ILogger<RsaSigningKeyProvider>>()),
                KeyType.ECDSA => new EcdsaSigningKeyProvider(sp.GetRequiredService<IOptions<CoreIdentKeyOptions>>(), sp.GetRequiredService<ILogger<EcdsaSigningKeyProvider>>()),
                KeyType.Symmetric => new SymmetricSigningKeyProvider(sp.GetRequiredService<IOptions<CoreIdentKeyOptions>>(), sp.GetRequiredService<ILogger<SymmetricSigningKeyProvider>>()),
                _ => throw new InvalidOperationException($"Unsupported key type: {options.Type}")
            };
        });

        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        services.TryAddSingleton<ICoreIdentRealmResolver, DefaultCoreIdentRealmResolver>();
        services.TryAddScoped<ICoreIdentRealmContext, HttpContextCoreIdentRealmContext>();
        services.TryAddSingleton<IRealmSigningKeyProviderResolver, DefaultRealmSigningKeyProviderResolver>();

        services.TryAddScoped<ITokenService, JwtTokenService>();

        return services;
    }
}

/// <summary>
/// Builder for configuring <see cref="CoreIdentKeyOptions"/> via fluent methods.
/// </summary>
public sealed class CoreIdentKeyOptionsBuilder
{
    private readonly CoreIdentKeyOptions _options = new();

    /// <summary>
    /// Configures RSA signing using a PEM file path.
    /// </summary>
    /// <param name="keyPath">Path to the private key PEM file.</param>
    /// <returns>The builder.</returns>
    /// <remarks>
    /// Use this for typical production deployments where the host can read a private key file from disk.
    /// </remarks>
    public CoreIdentKeyOptionsBuilder UseRsa(string keyPath)
    {
        _options.Type = KeyType.RSA;
        _options.PrivateKeyPath = keyPath;
        return this;
    }

    /// <summary>
    /// Configures RSA signing using a PEM string.
    /// </summary>
    /// <param name="pemString">PEM-encoded private key.</param>
    /// <returns>The builder.</returns>
    /// <remarks>
    /// Use this when keys are loaded from a secrets provider and supplied as an in-memory string.
    /// </remarks>
    public CoreIdentKeyOptionsBuilder UseRsaPem(string pemString)
    {
        _options.Type = KeyType.RSA;
        _options.PrivateKeyPem = pemString;
        return this;
    }

    /// <summary>
    /// Configures ECDSA signing using a PEM file path.
    /// </summary>
    /// <param name="keyPath">Path to the private key PEM file.</param>
    /// <returns>The builder.</returns>
    /// <remarks>
    /// ECDSA signing is typically used with P-256 (ES256).
    /// </remarks>
    public CoreIdentKeyOptionsBuilder UseEcdsa(string keyPath)
    {
        _options.Type = KeyType.ECDSA;
        _options.PrivateKeyPath = keyPath;
        return this;
    }

    /// <summary>
    /// Configures symmetric (HS256) signing. Intended for development/testing only.
    /// </summary>
    /// <param name="secret">Symmetric key material.</param>
    /// <returns>The builder.</returns>
    /// <remarks>
    /// Symmetric keys are not published via JWKS and should not be used for multi-tenant or internet-facing deployments.
    /// </remarks>
    public CoreIdentKeyOptionsBuilder UseSymmetric(string secret)
    {
        _options.Type = KeyType.Symmetric;
        _options.SymmetricKey = secret;
        return this;
    }

    internal void Apply(CoreIdentKeyOptions destination)
    {
        destination.Type = _options.Type;
        destination.RsaKeySize = _options.RsaKeySize;
        destination.PrivateKeyPem = _options.PrivateKeyPem;
        destination.PrivateKeyPath = _options.PrivateKeyPath;
        destination.CertificatePath = _options.CertificatePath;
        destination.CertificatePassword = _options.CertificatePassword;
        destination.SymmetricKey = _options.SymmetricKey;
    }
}
