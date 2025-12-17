using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCoreIdent(this IServiceCollection services)
    {
        return services.AddCoreIdent(configureOptions: null, configureRoutes: null);
    }

    public static IServiceCollection AddCoreIdent(this IServiceCollection services, Action<CoreIdentOptions> configureOptions)
    {
        return services.AddCoreIdent(configureOptions, configureRoutes: null);
    }

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

        services.TryAddSingleton<ITokenService, JwtTokenService>();

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

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, AuthorizationCodeCleanupHostedService>());

        return services;
    }

    public static IServiceCollection ConfigureResourceOwnerEndpoints(
        this IServiceCollection services,
        Action<CoreIdentResourceOwnerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        return services;
    }

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

        services.TryAddSingleton<ITokenService, JwtTokenService>();

        return services;
    }
}

public sealed class CoreIdentKeyOptionsBuilder
{
    private readonly CoreIdentKeyOptions _options = new();

    public CoreIdentKeyOptionsBuilder UseRsa(string keyPath)
    {
        _options.Type = KeyType.RSA;
        _options.PrivateKeyPath = keyPath;
        return this;
    }

    public CoreIdentKeyOptionsBuilder UseRsaPem(string pemString)
    {
        _options.Type = KeyType.RSA;
        _options.PrivateKeyPem = pemString;
        return this;
    }

    public CoreIdentKeyOptionsBuilder UseEcdsa(string keyPath)
    {
        _options.Type = KeyType.ECDSA;
        _options.PrivateKeyPath = keyPath;
        return this;
    }

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
