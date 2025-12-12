using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Extensions;

public static class ServiceCollectionExtensions
{
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
